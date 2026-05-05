package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

type refreshRetryCapExecutor struct {
	provider string
	errs     []error
	calls    int
}

func (e *refreshRetryCapExecutor) Identifier() string { return e.provider }

func (e *refreshRetryCapExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *refreshRetryCapExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *refreshRetryCapExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.calls++
	if e.calls <= len(e.errs) && e.errs[e.calls-1] != nil {
		return nil, e.errs[e.calls-1]
	}
	return auth, nil
}

func (e *refreshRetryCapExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *refreshRetryCapExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestManagerRefreshAuth_CodexStopsAfterThreeFailuresAndClearsOnSuccess(t *testing.T) {
	lead := time.Hour
	setRefreshLeadFactory(t, "codex", func() *time.Duration {
		d := lead
		return &d
	})

	var logBuf bytes.Buffer
	logger := log.StandardLogger()
	prevOut := logger.Out
	prevFormatter := logger.Formatter
	log.SetOutput(&logBuf)
	log.SetFormatter(&log.TextFormatter{DisableTimestamp: true})
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFormatter(prevFormatter)
	})

	errRefresh := errors.New("refresh failed")
	executor := &refreshRetryCapExecutor{
		provider: "codex",
		errs:     []error{errRefresh, errRefresh, errRefresh, nil},
	}
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "codex-auth",
		Provider: "codex",
		FileName: "auths/codex-user.json",
		Metadata: map[string]any{
			"email": "codex@example.com",
		},
	}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		before := time.Now()
		manager.refreshAuth(context.Background(), auth.ID)
		after := time.Now()

		current := authFromManager(t, manager, auth.ID)
		if current.RefreshFailureCount != attempt {
			t.Fatalf("attempt %d RefreshFailureCount = %d, want %d", attempt, current.RefreshFailureCount, attempt)
		}
		if current.RefreshStoppedAt != nil {
			t.Fatalf("attempt %d RefreshStoppedAt = %v, want nil", attempt, current.RefreshStoppedAt)
		}
		requireNextRefreshAfter(t, current.NextRefreshAfter, before, after)
	}

	manager.refreshAuth(context.Background(), auth.ID)
	current := authFromManager(t, manager, auth.ID)
	if current.RefreshFailureCount != codexRefreshMaxFailures {
		t.Fatalf("RefreshFailureCount = %d, want %d", current.RefreshFailureCount, codexRefreshMaxFailures)
	}
	if current.RefreshStoppedAt == nil {
		t.Fatal("RefreshStoppedAt = nil, want timestamp")
	}
	if !current.NextRefreshAfter.IsZero() {
		t.Fatalf("NextRefreshAfter = %s, want zero after terminal failure", current.NextRefreshAfter)
	}
	if current.LastError == nil || !strings.Contains(current.LastError.Message, errRefresh.Error()) {
		t.Fatalf("LastError = %#v, want refresh error", current.LastError)
	}
	if _, ok := nextRefreshCheckAt(time.Now(), current, refreshCheckInterval); ok {
		t.Fatal("nextRefreshCheckAt() ok = true after terminal Codex refresh failure, want false")
	}
	if logText := logBuf.String(); !strings.Contains(logText, "codex-user.json") {
		t.Fatalf("terminal refresh log = %q, want auth file name", logText)
	}

	now := time.Now()
	manager.refreshAuth(context.Background(), auth.ID)
	current = authFromManager(t, manager, auth.ID)
	if current.RefreshFailureCount != 0 {
		t.Fatalf("RefreshFailureCount after success = %d, want 0", current.RefreshFailureCount)
	}
	if current.RefreshStoppedAt != nil {
		t.Fatalf("RefreshStoppedAt after success = %v, want nil", current.RefreshStoppedAt)
	}
	if current.LastError != nil {
		t.Fatalf("LastError after success = %#v, want nil", current.LastError)
	}
	if !current.NextRefreshAfter.IsZero() {
		t.Fatalf("NextRefreshAfter after success = %s, want zero", current.NextRefreshAfter)
	}
	next, ok := nextRefreshCheckAt(now, current, refreshCheckInterval)
	if !ok {
		t.Fatal("nextRefreshCheckAt() ok = false after successful Codex refresh, want true")
	}
	if next.Before(current.LastRefreshedAt.Add(lead)) {
		t.Fatalf("nextRefreshCheckAt() = %s, want at or after %s", next, current.LastRefreshedAt.Add(lead))
	}
	if executor.calls != 4 {
		t.Fatalf("refresh calls = %d, want 4", executor.calls)
	}
}

func TestManagerRefreshAuth_NonCodexKeepsExistingFailureBackoff(t *testing.T) {
	errRefresh := errors.New("refresh failed")
	executor := &refreshRetryCapExecutor{
		provider: "gemini",
		errs:     []error{errRefresh},
	}
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "gemini-auth",
		Provider: "gemini",
		Metadata: map[string]any{
			"email": "gemini@example.com",
		},
	}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	before := time.Now()
	manager.refreshAuth(context.Background(), auth.ID)
	after := time.Now()

	current := authFromManager(t, manager, auth.ID)
	if current.RefreshFailureCount != 0 {
		t.Fatalf("RefreshFailureCount = %d, want 0 for non-Codex auth", current.RefreshFailureCount)
	}
	if current.RefreshStoppedAt != nil {
		t.Fatalf("RefreshStoppedAt = %v, want nil for non-Codex auth", current.RefreshStoppedAt)
	}
	requireNextRefreshAfter(t, current.NextRefreshAfter, before, after)
}

func authFromManager(t *testing.T, manager *Manager, id string) *Auth {
	t.Helper()
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	auth := manager.auths[id]
	if auth == nil {
		t.Fatalf("auth %q not found", id)
	}
	return auth.Clone()
}

func requireNextRefreshAfter(t *testing.T, got time.Time, before time.Time, after time.Time) {
	t.Helper()
	min := before.Add(refreshFailureBackoff)
	max := after.Add(refreshFailureBackoff).Add(time.Second)
	if got.Before(min) || got.After(max) {
		t.Fatalf("NextRefreshAfter = %s, want between %s and %s", got, min, max)
	}
}
