package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	supplementalCandidateLimit = 80
	supplementalKeepLimit      = 24
	supplementalProbeWorkers   = 8
)

type supplementalSource struct {
	Name string
	URL  string
}

var supplementalSources = []supplementalSource{
	{Name: "proxy-free public SOCKS5", URL: "https://raw.githubusercontent.com/proxy-free/free-proxy-list/main/socks5.txt"},
	{Name: "ProxyScrape public SOCKS5", URL: "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/socks5/data.txt"},
}

type supplementalCandidate struct {
	Host, Source string
	Port         int
}

type SupplementalManager struct {
	mu       sync.Mutex
	c        *Console
	running  bool
	cancel   context.CancelFunc
	done     chan struct{}
	lastAt   time.Time
	lastErr  string
	lastKept int
	probe    func(context.Context, ThirdPartyProxy, string) ThirdPartyRecord
	fetch    func(context.Context) ([]supplementalCandidate, error)
}

func newSupplementalManager(c *Console) *SupplementalManager {
	s := &SupplementalManager{c: c, probe: probeThirdParty}
	s.fetch = s.fetchCandidates
	if c.ctx != nil {
		go s.autoLoop()
	}
	return s
}

func (s *SupplementalManager) autoLoop() {
	// Automatic refresh is opt-in by existence: it begins only after an
	// administrator has successfully created the active manifest. Renaming it
	// through the disable endpoint stops future refreshes as well.
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.c.ctx.Done():
			return
		case <-ticker.C:
			path := filepath.Join(s.c.m.workDir, supplementalPoolFile)
			if _, err := os.Stat(path); err != nil {
				continue
			}
			exits, err := loadSupplementalExits(s.c.m.workDir)
			needsRefresh := err != nil || len(exits) == 0
			for _, exit := range exits {
				if exit.Egress == nil {
					needsRefresh = true
					break
				}
				expiry, parseErr := time.Parse(time.RFC3339Nano, exit.Egress.ExpiresAt)
				if parseErr != nil || time.Until(expiry) < 15*time.Minute {
					needsRefresh = true
					break
				}
			}
			if needsRefresh {
				s.start()
			}
		}
	}
}

func (s *SupplementalManager) shutdown() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	done := s.done
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (s *SupplementalManager) disable() error {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	done := s.done
	s.mu.Unlock()
	if done != nil {
		<-done
	}
	active := filepath.Join(s.c.m.workDir, supplementalPoolFile)
	disabled := active + ".disabled"
	if err := os.Rename(active, disabled); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *SupplementalManager) routes(mux *http.ServeMux) {
	mux.HandleFunc("/api/resources/supplemental", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.mu.Lock()
		status := map[string]any{"running": s.running, "last_at": s.lastAt, "last_error": s.lastErr, "last_kept": s.lastKept}
		s.mu.Unlock()
		if exits, err := loadSupplementalExits(s.c.m.workDir); err == nil {
			for i := range exits {
				exits[i].SocksUser, exits[i].SocksPass = "", ""
			}
			status["active"] = len(exits)
			status["exits"] = exits
		} else {
			status["active"] = 0
		}
		writeJSON(w, http.StatusOK, status)
	})
	mux.HandleFunc("/api/resources/supplemental/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !s.start() {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "supplemental refresh is already running"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
	})
	mux.HandleFunc("/api/resources/supplemental/disable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Cancel and join an in-flight refresh before renaming, otherwise its
		// final atomic write could recreate the pool after the user disabled it.
		// Rename instead of deleting so the evidence remains recoverable.
		if err := s.disable(); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "could not disable supplemental exits"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
}

func (s *SupplementalManager) start() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.c.ctx.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(s.c.ctx, 12*time.Minute)
	s.running, s.cancel, s.done = true, cancel, make(chan struct{})
	go func(done chan struct{}) {
		kept, err := s.refresh(ctx)
		cancel()
		s.mu.Lock()
		s.running, s.cancel = false, nil
		s.lastAt, s.lastKept = time.Now().UTC(), kept
		if err != nil {
			s.lastErr = err.Error()
		} else {
			s.lastErr = ""
		}
		close(done)
		s.mu.Unlock()
	}(s.done)
	return true
}

func (s *SupplementalManager) refresh(ctx context.Context) (int, error) {
	candidates, err := s.fetch(ctx)
	if err != nil {
		return 0, err
	}
	if len(candidates) > supplementalCandidateLimit {
		candidates = candidates[:supplementalCandidateLimit]
	}
	type result struct {
		candidate supplementalCandidate
		record    ThirdPartyRecord
	}
	jobs, results := make(chan supplementalCandidate), make(chan result)
	var workers sync.WaitGroup
	for i := 0; i < supplementalProbeWorkers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for candidate := range jobs {
				proxy := ThirdPartyProxy{Host: candidate.Host, Port: candidate.Port}
				record := s.probe(ctx, proxy, s.c.m.workDir)
				select {
				case results <- result{candidate: candidate, record: record}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, candidate := range candidates {
			select {
			case jobs <- candidate:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()

	manifest := supplementalManifest{SchemaVersion: 1, GeneratedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(45 * time.Minute)}
	for item := range results {
		r := item.record
		if r.Status != "passed" || !r.ExpiresAt.After(time.Now()) {
			continue
		}
		expiry := r.ExpiresAt
		if expiry.After(manifest.ExpiresAt) {
			expiry = manifest.ExpiresAt
		}
		manifest.Entries = append(manifest.Entries, supplementalEntry{
			SourceName: item.candidate.Source, SourceCategory: exitSourceSSTP,
			Host: item.candidate.Host, Port: item.candidate.Port,
			Country: r.Country, City: r.City, ExitIP: r.ActualIP, IPType: "unknown",
			Native: false, LatencyMS: r.LatencyMS, CheckedAt: r.CheckedAt.UTC(), ExpiresAt: expiry.UTC(),
		})
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if len(manifest.Entries) == 0 {
		return 0, errors.New("no public candidate passed VPS verification; previous active pool was preserved")
	}
	sort.Slice(manifest.Entries, func(i, j int) bool {
		if manifest.Entries[i].SourceCategory != manifest.Entries[j].SourceCategory {
			return manifest.Entries[i].SourceCategory < manifest.Entries[j].SourceCategory
		}
		if manifest.Entries[i].Country != manifest.Entries[j].Country {
			return manifest.Entries[i].Country < manifest.Entries[j].Country
		}
		return manifest.Entries[i].LatencyMS < manifest.Entries[j].LatencyMS
	})
	if len(manifest.Entries) > supplementalKeepLimit {
		manifest.Entries = manifest.Entries[:supplementalKeepLimit]
	}
	assignSupplementalSlots(manifest.Entries)
	blob, err := json.Marshal(manifest)
	if err != nil {
		return 0, err
	}
	if err := atomicConfigWrite(filepath.Join(s.c.m.workDir, supplementalPoolFile), blob); err != nil {
		return 0, errors.New("verified supplemental pool could not be saved; previous pool was preserved")
	}
	return len(manifest.Entries), nil
}

// Slots are derived from the upstream endpoint, so refreshing or changing
// list order does not silently move an existing subscription identity to a
// different proxy. Linear probing resolves the extremely unlikely collision.
func assignSupplementalSlots(entries []supplementalEntry) {
	used := make(map[int]bool, len(entries))
	span := supplementalSlotMax - supplementalSlotBase + 1
	for i := range entries {
		h := fnv.New32a()
		_, _ = h.Write([]byte(net.JoinHostPort(entries[i].Host, strconv.Itoa(entries[i].Port))))
		slot := supplementalSlotBase + int(h.Sum32()%uint32(span))
		for used[slot] {
			slot++
			if slot > supplementalSlotMax {
				slot = supplementalSlotBase
			}
		}
		entries[i].Slot, used[slot] = slot, true
	}
}

func (s *SupplementalManager) fetchCandidates(ctx context.Context) ([]supplementalCandidate, error) {
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
			return errors.New("refused supplemental source redirect")
		}
		return nil
	}}
	seen := map[string]bool{}
	all := make([]supplementalCandidate, 0, supplementalCandidateLimit)
	perSourceLimit := supplementalCandidateLimit / len(supplementalSources)
	for _, source := range supplementalSources {
		u, err := url.Parse(source.URL)
		if err != nil || u.Scheme != "https" || u.Host != "raw.githubusercontent.com" {
			continue
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK || resp.ContentLength > 4<<20 {
			resp.Body.Close()
			continue
		}
		scanner := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
		added := 0
		for scanner.Scan() && added < perSourceLimit && len(all) < supplementalCandidateLimit {
			ip, port, ok := parseSupplementalCandidate(scanner.Text())
			key := net.JoinHostPort(ip, strconv.Itoa(port))
			if !ok || seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, supplementalCandidate{Host: ip, Port: port, Source: source.Name})
			added++
		}
		resp.Body.Close()
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no valid SOCKS5 candidates were downloaded")
	}
	return all, nil
}

func parseSupplementalCandidate(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || strings.ToLower(u.Scheme) != "socks5" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return "", 0, false
		}
		value = u.Host
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portText)
	ip, ipErr := publicIPv4(host)
	if err != nil || ipErr != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return ip, port, true
}
