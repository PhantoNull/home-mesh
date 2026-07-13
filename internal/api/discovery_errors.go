package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/PhantoNull/home-mesh/internal/discovery"
)

func validateDiscoveryCIDR(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	ip, network, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil {
		return errors.New("discovery CIDR must be a valid IPv4 network")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 16 {
		return errors.New("discovery CIDR must be /16 or more specific")
	}
	return nil
}

func discoveryErrorStatus(err error) int {
	switch {
	case errors.Is(err, discovery.ErrScanInProgress):
		return http.StatusConflict
	case errors.Is(err, discovery.ErrNetworkNotAllowed):
		return http.StatusForbidden
	case errors.Is(err, discovery.ErrNmapUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}

func discoveryClientMessage(err error) string {
	switch {
	case errors.Is(err, discovery.ErrScanInProgress):
		return "a discovery scan is already in progress"
	case errors.Is(err, discovery.ErrNetworkNotAllowed):
		return "the requested network is not allowed"
	case errors.Is(err, discovery.ErrNmapUnavailable):
		return "nmap is not available in the current runtime"
	case errors.Is(err, context.DeadlineExceeded):
		return "discovery scan timed out"
	default:
		return "discovery scan failed"
	}
}
