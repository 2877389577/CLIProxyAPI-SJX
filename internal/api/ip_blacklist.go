package api

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

type ipBlacklistSnapshot struct {
	prefixes []netip.Prefix
}

type ipBlacklist struct {
	snapshot atomic.Pointer[ipBlacklistSnapshot]
}

func newIPBlacklist(entries []string) (*ipBlacklist, error) {
	blacklist := &ipBlacklist{}
	if err := blacklist.Update(entries); err != nil {
		return nil, err
	}
	return blacklist, nil
}

func (b *ipBlacklist) Update(entries []string) error {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for index, entry := range entries {
		prefix, errParse := parseIPBlacklistPrefix(strings.TrimSpace(entry))
		if errParse != nil {
			return fmt.Errorf("entry %d (%q): %w", index, entry, errParse)
		}
		prefixes = append(prefixes, prefix)
	}
	b.snapshot.Store(&ipBlacklistSnapshot{prefixes: prefixes})
	return nil
}

func parseIPBlacklistPrefix(entry string) (netip.Prefix, error) {
	if entry == "" {
		return netip.Prefix{}, fmt.Errorf("entry is empty")
	}
	if strings.Contains(entry, "/") {
		prefix, errParse := netip.ParsePrefix(entry)
		if errParse != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP prefix: %w", errParse)
		}
		if prefix.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("IPv6 zones are not supported")
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return prefix.Masked(), nil
	}

	addr, errParse := netip.ParseAddr(entry)
	if errParse != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address: %w", errParse)
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("IPv6 zones are not supported")
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func (b *ipBlacklist) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if b.ContainsRemoteAddr(c.Request.RemoteAddr) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func (b *ipBlacklist) ContainsRemoteAddr(remoteAddr string) bool {
	if b == nil {
		return false
	}
	host, _, errSplit := net.SplitHostPort(remoteAddr)
	if errSplit != nil {
		return false
	}
	addr, errParse := netip.ParseAddr(host)
	if errParse != nil {
		return false
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	addr = addr.Unmap()

	snapshot := b.snapshot.Load()
	if snapshot == nil {
		return false
	}
	for _, prefix := range snapshot.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
