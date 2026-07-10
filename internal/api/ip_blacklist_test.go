package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestIPBlacklistMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	blacklist, errNew := newIPBlacklist([]string{
		"192.0.2.10",
		"198.51.100.0/24",
		"2001:db8::10",
		"2001:db8:1::/48",
	})
	if errNew != nil {
		t.Fatalf("newIPBlacklist() error = %v", errNew)
	}

	engine := gin.New()
	engine.Use(blacklist.Middleware())
	engine.GET("/test", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		realIP     string
		wantStatus int
	}{
		{name: "exact IPv4", remoteAddr: "192.0.2.10:1234", wantStatus: http.StatusForbidden},
		{name: "IPv4 CIDR", remoteAddr: "198.51.100.25:1234", wantStatus: http.StatusForbidden},
		{name: "outside IPv4 CIDR", remoteAddr: "198.51.101.25:1234", wantStatus: http.StatusNoContent},
		{name: "exact IPv6", remoteAddr: "[2001:db8::10]:1234", wantStatus: http.StatusForbidden},
		{name: "IPv6 CIDR", remoteAddr: "[2001:db8:1::25]:1234", wantStatus: http.StatusForbidden},
		{name: "forwarded header ignored", remoteAddr: "203.0.113.1:1234", forwarded: "192.0.2.10", realIP: "192.0.2.10", wantStatus: http.StatusNoContent},
		{name: "forwarded header cannot bypass", remoteAddr: "192.0.2.10:1234", forwarded: "203.0.113.1", realIP: "203.0.113.1", wantStatus: http.StatusForbidden},
		{name: "malformed remote address", remoteAddr: "not-a-socket-address", wantStatus: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			if tt.realIP != "" {
				req.Header.Set("X-Real-IP", tt.realIP)
			}
			rr := httptest.NewRecorder()
			engine.ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tt.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestIPBlacklistPrecedesAPIKeyAuthentication(t *testing.T) {
	server := newTestServer(t)
	if errUpdate := server.ipBlacklist.Update([]string{"192.0.2.10"}); errUpdate != nil {
		t.Fatalf("update blacklist: %v", errUpdate)
	}

	blocked := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	blocked.RemoteAddr = "192.0.2.10:1234"
	blockedRecorder := httptest.NewRecorder()
	server.engine.ServeHTTP(blockedRecorder, blocked)
	if blockedRecorder.Code != http.StatusForbidden {
		t.Fatalf("blocked status = %d, want %d; body=%s", blockedRecorder.Code, http.StatusForbidden, blockedRecorder.Body.String())
	}

	allowed := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	allowed.RemoteAddr = "203.0.113.10:1234"
	allowedRecorder := httptest.NewRecorder()
	server.engine.ServeHTTP(allowedRecorder, allowed)
	if allowedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("allowed status = %d, want auth status %d; body=%s", allowedRecorder.Code, http.StatusUnauthorized, allowedRecorder.Body.String())
	}
}

func TestIPBlacklistHotReload(t *testing.T) {
	server := newTestServer(t)
	requestHealthz := func() int {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "192.0.2.10:1234"
		rr := httptest.NewRecorder()
		server.engine.ServeHTTP(rr, req)
		return rr.Code
	}

	if got := requestHealthz(); got != http.StatusOK {
		t.Fatalf("initial status = %d, want %d", got, http.StatusOK)
	}

	blockedCfg := server.cfg.CloneForRuntime()
	blockedCfg.IPBlacklist = []string{"192.0.2.0/24"}
	server.UpdateClients(blockedCfg)
	if got := requestHealthz(); got != http.StatusForbidden {
		t.Fatalf("status after adding blacklist = %d, want %d", got, http.StatusForbidden)
	}

	invalidCfg := server.cfg.CloneForRuntime()
	invalidCfg.IPBlacklist = []string{"not-an-ip"}
	server.UpdateClients(invalidCfg)
	if got := requestHealthz(); got != http.StatusForbidden {
		t.Fatalf("status after invalid update = %d, want previous blacklist status %d", got, http.StatusForbidden)
	}

	allowedCfg := server.cfg.CloneForRuntime()
	allowedCfg.IPBlacklist = nil
	server.UpdateClients(allowedCfg)
	if got := requestHealthz(); got != http.StatusOK {
		t.Fatalf("status after removing blacklist = %d, want %d", got, http.StatusOK)
	}
}
