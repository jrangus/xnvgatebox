package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// 订阅：把 fanout 管着的节点链接聚成一条地址，客户端订阅一次就全有了。
//
// 为什么需要它：一次批量开 5 个出口就是 5 个入站、5 条链接，
// 手动一条条复制粘贴到客户端太笨。而且换节点时端口和客户端配置不变，
// 订阅地址一次配好就不用再动，出口增删会自己跟上。
//
// 访问控制：客户端拉订阅时不可能带登录态，所以 /sub 绕过了登录，
// 改用一串独立口令当门槛。它仍然在访问路径（basepath）后面，
// 等于两层：路径猜不到 + 口令猜不到。

// subTokenLen 是订阅口令的字节数，hex 之后是 40 个字符。
const subTokenLen = 20

// subToken 返回当前订阅口令，没有就生成一串并落盘。
func subToken() (string, error) {
	if tok := strings.TrimSpace(getWebSettings().SubToken); tok != "" {
		return tok, nil
	}
	return resetSubToken()
}

// resetSubToken 换一串新的订阅口令。旧地址立即失效，
// 已经订阅过的客户端要重新配。
func resetSubToken() (string, error) {
	managementMu.Lock()
	defer managementMu.Unlock()
	tok, err := randomToken(subTokenLen)
	if err != nil {
		return "", err
	}
	next := getWebSettings()
	next.SubToken = tok
	if err := commitManagementSettings(nil, &webServer{}, next, nil, nil); err != nil {
		return "", err
	}
	return tok, nil
}

// subPath 是订阅地址在当前访问路径下的相对部分，形如 /aB3xY9pQ/sub?token=xxx。
func subPath(tok string) string {
	return currentBasePath() + "/sub?token=" + tok
}

// subFullURL 按当前请求推断一个完整地址。界面上更准的做法是用
// location.origin 拼 subPath，这里只是给不走浏览器的调用方兜底。
func subFullURL(r *http.Request, tok string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		if ip := hostPublicIP(); ip != "" {
			host = ip + ":" + fmt.Sprint(getWebSettings().Port)
		}
	}
	return scheme + "://" + host + subPath(tok)
}

// apiSub 给界面用：返回订阅地址。
func apiSub(w http.ResponseWriter, r *http.Request) {
	tok, err := subToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"token": tok,
		"path":  subPath(tok),
		"url":   subFullURL(r, tok),
	})
}

// apiSubReset 换一串新口令，旧订阅地址立刻作废。
func apiSubReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只接受 POST"})
		return
	}
	tok, err := resetSubToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"token": tok,
		"path":  subPath(tok),
		"url":   subFullURL(r, tok),
	})
}

// subLinks 收集要放进订阅的节点链接。
//
// boundOnly=true 只要绑在出口上的入站。这是默认行为：订阅的意义是
// 显式的本机直出另行选择并明确命名；未绑定入站仍然阻断。
func subLinks(m *Manager, host string, boundOnly bool) ([]string, error) {
	return subLinksSelected(m, host, boundOnly, nil)
}

func subLinksSelected(m *Manager, host string, boundOnly bool, selected map[int]bool) ([]string, error) {
	return subLinksScoped(m, host, boundOnly, selected, selected == nil)
}

func subLinksScoped(m *Manager, host string, boundOnly bool, selected map[int]bool, includeDirect bool) ([]string, error) {
	return subLinksSources(m, host, boundOnly, selected, includeDirect, selected == nil, nil)
}

func subLinksSources(m *Manager, host string, boundOnly bool, selected map[int]bool, includeDirect, includeThird bool, proxies map[int]bool) ([]string, error) {
	p, err := openPanel()
	if err != nil {
		return nil, err
	}

	var ids []int
	if _, native := p.(*Native); native && boundOnly {
		var links []string
		names := map[string]bool{}
		view := m.ExitsOf()
		sort.Slice(view.HostDirect, func(i, j int) bool { return view.HostDirect[i].ID < view.HostDirect[j].ID })
		if includeDirect {
			for _, ib := range view.HostDirect {
				if !ib.Enable {
					continue
				}
				rows, err := p.InboundLinks([]int{ib.ID}, host)
				if err != nil {
					return nil, err
				}
				for _, link := range rows {
					u, err := url.Parse(link)
					if err != nil {
						return nil, err
					}
					u.Fragment = uniqueRemark("VPS 本机直出", names)
					u.RawFragment = ""
					names[u.Fragment] = true
					links = append(links, u.String())
				}
			}
		}
		if includeThird {
			n := p.(*Native)
			records := map[int]ThirdPartyRecord{}
			if m.console != nil && m.console.third != nil {
				records = m.console.third.snapshot()
			}
			rows, err := n.thirdPartyLinks(host, proxies, records, names)
			if err != nil {
				return nil, err
			}
			links = append(links, rows...)
		}
		for _, e := range view.Exits {
			if e.Status != "up" || (selected != nil && !selected[e.Slot]) {
				continue
			}
			sort.Slice(e.Inbounds, func(i, j int) bool { return e.Inbounds[i].ID < e.Inbounds[j].ID })
			for _, ib := range e.Inbounds {
				if !ib.Enable {
					continue
				}
				rows, err := p.InboundLinks([]int{ib.ID}, host)
				if err != nil {
					return nil, err
				}
				label := ib.Remark
				if automaticName(ib) {
					label = subscriptionExitName(e)
					if len(e.Inbounds) > 1 {
						label += fmt.Sprintf(" · %d", ib.Port)
					}
				}
				sourceLabel := subscriptionSourceLabel(e.SourceCategory)
				if !strings.Contains(label, sourceLabel) {
					label += " · " + sourceLabel
				}
				for _, link := range rows {
					name := uniqueRemark(label, names)
					names[name] = true
					u, err := url.Parse(link)
					if err != nil {
						return nil, fmt.Errorf("节点链接无效")
					}
					u.Fragment = name
					u.RawFragment = ""
					links = append(links, u.String())
				}
			}
		}
		return links, nil
	}
	if boundOnly {
		for _, e := range m.ExitsOf().Exits {
			if selected != nil && !selected[e.Slot] {
				continue
			}
			for _, ib := range e.Inbounds {
				if ib.Enable {
					ids = append(ids, ib.ID)
				}
			}
		}
	} else {
		list, lerr := p.Inbounds(nil)
		if lerr != nil {
			return nil, lerr
		}
		for _, ib := range list {
			if ib.Enable {
				ids = append(ids, ib.ID)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return p.InboundLinks(ids, host)
}

// handleSub 是订阅本体。走的是免登录路径，所以第一件事是验口令。
//
// 参数：
//
//	token  必填，订阅口令
//	target 输出格式：base64（默认，通用）或 links（明文，排查用）
//	host   节点链接里的连接地址，默认用母机公网 IP
//	bound  0 表示把没绑出口的入站也放进来
func handleSub(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		want, err := subToken()
		if err != nil {
			http.Error(w, "订阅口令未就绪", http.StatusInternalServerError)
			return
		}
		// 口令不对就当这个地址不存在，不告诉对方这儿有个订阅服务
		a := sha256.Sum256([]byte(want))
		b := sha256.Sum256([]byte(q.Get("token")))
		if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			http.NotFound(w, r)
			return
		}

		target := strings.ToLower(strings.TrimSpace(q.Get("target")))
		switch target {
		case "", "base64", "b64", "v2ray":
			target = "base64"
		case "links", "plain", "text":
			target = "links"
		case "clash", "mihomo":
			target = "clash"
		default:
			http.Error(w, "target 只支持 base64、links 或 clash", http.StatusBadRequest)
			return
		}

		host := q.Get("host")
		if host == "" {
			host = publicHost(r)
		}
		selected, selectErr := subscriptionSlots(q.Get("slots"))
		if selectErr != nil || (selected != nil && q.Get("bound") == "0") {
			http.Error(w, "出口选择无效", 400)
			return
		}
		includeDirect := selected == nil
		if v := q.Get("direct"); v != "" {
			if v != "0" && v != "1" {
				http.Error(w, "直出选择无效", 400)
				return
			}
			includeDirect = v == "1"
		}
		if q.Get("vpn") == "0" {
			selected = map[int]bool{}
		} else if v := q.Get("vpn"); v != "" && v != "1" {
			http.Error(w, "出口选择无效", 400)
			return
		}
		proxies, proxyErr := subscriptionProxyIDs(q.Get("proxies"))
		includeThird := q.Get("slots") == "" && q.Get("vpn") != "0"
		if v := q.Get("third"); v != "" {
			if v != "0" && v != "1" {
				http.Error(w, "第三方选择无效", 400)
				return
			}
			includeThird = v == "1"
		}
		if proxies != nil {
			includeThird = true
		}
		if proxyErr != nil || (proxies != nil && q.Get("third") == "0") {
			http.Error(w, "第三方选择无效", 400)
			return
		}
		links, err := subLinksSources(m, host, q.Get("bound") != "0", selected, includeDirect, includeThird, proxies)
		if err != nil {
			// 节点后端不给链接（xray-cf-lite 模式下链接由它自己的订阅负责）
			http.Error(w, "生成订阅失败: "+firstLine(err.Error()), http.StatusBadGateway)
			return
		}
		if len(links) == 0 {
			// 回 404 而不是空串：客户端遇到空订阅会把已有节点清空，
			// 非 200 则保留上一份，比被清光好。
			http.Error(w, "还没有可订阅的节点，先开出口并建节点链接", http.StatusNotFound)
			return
		}

		body := []byte(encodeSub(links, target))
		if target == "clash" {
			body, err = renderClash(links)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "no-store")
		// 客户端据此决定多久自动拉一次；出口增删之外的变化不影响链接，12 小时够
		w.Header().Set("Profile-Update-Interval", "12")
		w.Header().Set("Content-Disposition", "inline; filename=fanout")
		if target == "clash" {
			w.Header().Set("Content-Disposition", "inline; filename=xnvgatebox-clash.yaml")
		}
		_, _ = w.Write(body)
	}
}

func subscriptionProxyIDs(text string) (map[int]bool, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > 8192 {
		return nil, fmt.Errorf("第三方选择过长")
	}
	out := map[int]bool{}
	for _, v := range strings.Split(text, ",") {
		id, err := strconv.Atoi(v)
		if err != nil || id < 1 || id > 1000000000 || out[id] {
			return nil, fmt.Errorf("第三方编号无效")
		}
		out[id] = true
	}
	return out, nil
}

// encodeSub 把链接列表转成订阅正文。
//
// base64 是各家客户端的通用吃法：整份文本一次编码，不是逐行。
func encodeSub(links []string, target string) string {
	body := strings.Join(links, "\n")
	if target == "base64" {
		return base64.StdEncoding.EncodeToString([]byte(body))
	}
	return body
}

func subscriptionSlots(text string) (map[int]bool, error) {
	if text == "" {
		return nil, nil
	}
	out := map[int]bool{}
	for _, v := range strings.Split(text, ",") {
		slot, err := strconv.Atoi(v)
		if err != nil || slot < 1 || slot > maximumSlots || out[slot] {
			return nil, fmt.Errorf("出口选择无效")
		}
		out[slot] = true
	}
	return out, nil
}
