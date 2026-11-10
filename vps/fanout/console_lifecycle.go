package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func (c *Console) shutdown() {
	defer c.third.shutdown()
	c.cancel()
	if c.supplemental != nil {
		c.supplemental.shutdown()
	}
	if c.sstp != nil {
		c.sstp.shutdown()
	}
	// Wait for an in-flight quantity change before stopping user tunnels.
	c.targetMu.Lock()
	c.targetMu.Unlock()
	c.checksMu.Lock()
	job := c.check
	c.checksMu.Unlock()
	if job != nil && job.finished != nil {
		<-job.finished
	}
	c.refreshMu.Lock()
	finished := c.refreshDone
	c.refreshMu.Unlock()
	if finished != nil {
		<-finished
	}
}

func diagnosticConfigOwned(workDir, ns, executable, config string) bool {
	if filepath.Base(executable) != "openvpn" || filepath.Base(config) != ns+".ovpn" {
		return false
	}
	dir := filepath.Dir(config)
	return filepath.Dir(dir) == filepath.Clean(workDir) && strings.HasPrefix(filepath.Base(dir), ".connectivity-")
}

type diagnosticResource struct {
	Config       string `json:"config,omitempty"`
	Slot         int    `json:"slot"`
	NetworkIndex int    `json:"network_index"`
	Node         Node   `json:"node"`
}

// Each resource manifest is written before any kernel resources are created.
// Startup runs under the instance lock and before restoring production work.
func (c *Console) cleanupDiagnostics() error {
	dirs, err := filepath.Glob(filepath.Join(c.m.workDir, ".connectivity-*"))
	if err != nil {
		return err
	}
	seen := map[int]bool{}
	for _, dir := range dirs {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("检测临时目录类型异常")
		}
		blob, err := os.ReadFile(filepath.Join(dir, "diagnostic.json"))
		if err == nil {
			var r diagnosticResource
			if json.Unmarshal(blob, &r) != nil || r.Slot >= 0 || r.Slot < -networkLinkCount || r.NetworkIndex < 0 || r.NetworkIndex >= networkLinkCount || seen[r.Slot] {
				return fmt.Errorf("检测资源记录异常，保留现场")
			}
			seen[r.Slot] = true
			r.Node.Config = r.Config
			if r.Node.Config == "" {
				data, err := os.ReadFile(filepath.Join(dir, (&Tunnel{Slot: r.Slot}).nsName()+".ovpn"))
				if err == nil {
					r.Node.Config = string(data)
				} else if !os.IsNotExist(err) {
					return err
				}
			}
			t := &Tunnel{Slot: r.Slot, networkIndex: &r.NetworkIndex, Node: r.Node}
			if err := c.cleanupDiagnosticTunnel(t); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		} else {
			// Upgrade compatibility: old releases only used 240/241. A private
			// diagnostic config, rather than just the number, identifies ownership.
			for _, slot := range []int{240, 241} {
				t := &Tunnel{Slot: slot}
				config := filepath.Join(dir, t.nsName()+".ovpn")
				if data, err := os.ReadFile(config); err == nil {
					t.Node.Config = string(data)
					if err := c.cleanupDiagnosticTunnel(t); err != nil {
						return err
					}
				} else if !os.IsNotExist(err) {
					return err
				}
			}
		}
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("无法清理检测临时目录")
		}
	}
	return nil
}

func (c *Console) cleanupDiagnosticTunnel(t *Tunnel) error {
	nsPath := filepath.Join("/run/netns", t.nsName())
	nsInfo, err := os.Stat(nsPath)
	if err == nil {
		out, err := cmdOutput(exec.Command("ip", "netns", "pids", t.nsName()))
		if err != nil {
			return fmt.Errorf("无法核对检测进程")
		}
		for _, text := range strings.Fields(string(out)) {
			pid, err := strconv.Atoi(text)
			if err != nil {
				return fmt.Errorf("检测进程编号异常")
			}
			fd, err := unix.PidfdOpen(pid, 0)
			if err == unix.ESRCH {
				continue
			}
			if err != nil {
				return fmt.Errorf("无法固定检测进程身份")
			}
			proc := filepath.Join("/proc", text)
			exe, e1 := os.Readlink(filepath.Join(proc, "exe"))
			blob, e2 := os.ReadFile(filepath.Join(proc, "cmdline"))
			info, e3 := os.Stat(filepath.Join(proc, "ns/net"))
			config := ""
			args := strings.Split(string(blob), "\x00")
			for i, arg := range args {
				if (arg == "--config" || arg == "file") && i+1 < len(args) {
					config = args[i+1]
					break
				}
			}
			if config == "" {
				for _, arg := range args {
					if strings.HasSuffix(arg, t.nsName()+".launch") {
						config = arg
						break
					}
				}
			}
			if os.IsNotExist(e1) || os.IsNotExist(e2) || os.IsNotExist(e3) {
				unix.Close(fd)
				continue
			}
			if e1 != nil || e2 != nil || e3 != nil || !os.SameFile(nsInfo, info) || (!diagnosticProcessOwned(c.m.workDir, t.nsName(), exe, config) && !diagnosticPPPHookOwned(c.m.workDir, t.nsName(), proc, exe)) {
				unix.Close(fd)
				return fmt.Errorf("检测命名空间存在无法确认归属的进程")
			}
			err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			unix.Close(fd)
			if err != nil && err != unix.ESRCH {
				return fmt.Errorf("无法停止残留检测进程")
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("无法核对检测命名空间")
	}
	t.teardownNetns()
	_ = os.RemoveAll(filepath.Join("/etc/netns", t.nsName()))
	return nil
}

func diagnosticProcessOwned(workDir, ns, executable, config string) bool {
	if diagnosticConfigOwned(workDir, ns, executable, config) {
		return true
	}
	dir := filepath.Dir(config)
	if filepath.Dir(dir) != filepath.Clean(workDir) || !strings.HasPrefix(filepath.Base(dir), ".connectivity-sstp-") {
		return false
	}
	if filepath.Base(executable) == "curl" {
		return filepath.Base(config) == ns+".curl"
	}
	if filepath.Base(config) != ns+".ppp" && filepath.Base(config) != ns+".launch" {
		return false
	}
	switch filepath.Base(executable) {
	case "sstpc", "pppd", "sh", "dash", "unshare":
		return true
	}
	return false
}

// PPP hooks run under the private mounted /etc/ppp and may not retain the
// original options argv. Require its inode identity as well as the already
// checked network namespace and executable, never a PID or command name alone.
func diagnosticPPPHookOwned(workDir, ns, proc, executable string) bool {
	switch filepath.Base(executable) {
	case "sh", "dash", "mount":
	default:
		return false
	}
	actual, err := os.Stat(filepath.Join(proc, "root/etc/ppp"))
	if err != nil {
		return false
	}
	dirs, _ := filepath.Glob(filepath.Join(workDir, ".connectivity-sstp-*"))
	for _, dir := range dirs {
		if _, err := os.Stat(filepath.Join(dir, ns+".ppp")); err != nil {
			continue
		}
		expected, err := os.Stat(filepath.Join(dir, "ppp"))
		if err == nil && os.SameFile(actual, expected) {
			return true
		}
	}
	return false
}
