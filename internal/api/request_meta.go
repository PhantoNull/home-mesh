package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

type requestMetadata struct {
	trustedProxyCIDRs []netip.Prefix
	allowedHosts      map[string]struct{}
}

func newRequestMetadata(cidrs []string, allowedHostLists ...[]string) (*requestMetadata, error) {
	trustedProxyCIDRs := make([]netip.Prefix, 0, len(cidrs))
	for _, value := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid HOME_MESH_TRUSTED_PROXY_CIDRS entry %q: %w", value, err)
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, prefix.Masked())
	}

	allowedHosts := make(map[string]struct{})
	for _, values := range allowedHostLists {
		for _, value := range values {
			host, ok := canonicalAllowedHost(value)
			if !ok {
				return nil, fmt.Errorf("invalid HOME_MESH_ALLOWED_HOSTS entry %q", value)
			}
			allowedHosts[host] = struct{}{}
		}
	}

	return &requestMetadata{trustedProxyCIDRs: trustedProxyCIDRs, allowedHosts: allowedHosts}, nil
}

func (m *requestMetadata) clientIP(r *http.Request) string {
	peer, ok := remoteAddr(r)
	if !ok {
		return strings.TrimSpace(r.RemoteAddr)
	}
	if !m.isTrustedProxy(peer) {
		return peer.String()
	}

	if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		chain, valid := parseForwardedFor(forwardedFor)
		if !valid {
			return peer.String()
		}
		for i := len(chain) - 1; i >= 0; i-- {
			if !m.isTrustedProxy(chain[i]) {
				return chain[i].String()
			}
		}
		return chain[0].String()
	}

	if realIP, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return realIP.Unmap().String()
	}
	return peer.String()
}

func (m *requestMetadata) effectiveScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}

	peer, ok := remoteAddr(r)
	if !ok || !m.isTrustedProxy(peer) {
		return "http"
	}

	forwardedProto := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")
	if len(forwardedProto) == 0 {
		return "http"
	}
	switch strings.ToLower(strings.TrimSpace(forwardedProto[len(forwardedProto)-1])) {
	case "https":
		return "https"
	case "http":
		return "http"
	default:
		return "http"
	}
}

func (m *requestMetadata) isSecureRequest(r *http.Request) bool {
	return m.effectiveScheme(r) == "https"
}

func (m *requestMetadata) isTrustedProxy(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range m.trustedProxyCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (m *requestMetadata) isAllowedHost(hostport string) bool {
	host, _, ok := splitHostPort(hostport)
	if !ok {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsValid() {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" {
		return true
	}
	_, allowed := m.allowedHosts[host]
	return allowed
}

func canonicalAllowedHost(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "/?#@") {
		return "", false
	}
	host, _, ok := splitHostPort(value)
	if !ok {
		return "", false
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsValid() {
		return address.Unmap().String(), true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", false
			}
		}
	}
	return host, true
}

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	if addressPort, err := netip.ParseAddrPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return addressPort.Addr().Unmap(), true
	}
	address, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func parseForwardedFor(headerValue string) ([]netip.Addr, bool) {
	parts := strings.Split(headerValue, ",")
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		candidate := strings.Trim(strings.TrimSpace(part), "\"")
		address, err := netip.ParseAddr(candidate)
		if err != nil {
			return nil, false
		}
		chain = append(chain, address.Unmap())
	}
	return chain, len(chain) > 0
}
