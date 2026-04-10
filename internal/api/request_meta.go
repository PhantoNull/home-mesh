package api

import (
	"net"
	"net/http"
	"strings"
)

func extractClientIP(r *http.Request) string {
	peerIP := remoteIP(r)
	if isTrustedProxy(peerIP) {
		if clientIP := parseForwardedClientIP(r.Header.Get("X-Forwarded-For")); clientIP != "" {
			return clientIP
		}
		if clientIP := parseForwardedClientIP(r.Header.Get("X-Real-IP")); clientIP != "" {
			return clientIP
		}
	}

	return peerIP
}

func effectiveRequestHost(r *http.Request) string {
	peerIP := remoteIP(r)
	if isTrustedProxy(peerIP) {
		if host := parseForwardedHost(r.Header.Get("X-Forwarded-Host")); host != "" {
			return host
		}
		if host := parseForwardedHostFromForwarded(r.Header.Get("Forwarded")); host != "" {
			return host
		}
	}

	return strings.TrimSpace(r.Host)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if ip := net.ParseIP(strings.TrimSpace(r.RemoteAddr)); ip != nil {
			return ip.String()
		}
		return strings.TrimSpace(r.RemoteAddr)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4[0] == 10 ||
			(ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) ||
			(ipv4[0] == 192 && ipv4[1] == 168)
	}

	return len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc
}

func parseForwardedClientIP(headerValue string) string {
	for _, part := range strings.Split(headerValue, ",") {
		candidate := strings.Trim(strings.TrimSpace(part), "\"")
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String()
		}
	}

	return ""
}

func parseForwardedHost(headerValue string) string {
	for _, part := range strings.Split(headerValue, ",") {
		if host := strings.Trim(strings.TrimSpace(part), "\""); host != "" {
			return host
		}
	}

	return ""
}

func parseForwardedHostFromForwarded(headerValue string) string {
	for _, section := range strings.Split(headerValue, ",") {
		for _, field := range strings.Split(section, ";") {
			name, value, ok := strings.Cut(field, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "host") {
				continue
			}
			if host := strings.Trim(strings.TrimSpace(value), "\""); host != "" {
				return host
			}
		}
	}

	return ""
}
