package executor

import (
	"context"
	"errors"
	"testing"

	codexauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type codexTokenRefresherStub struct {
	calls int
	data  *codexauth.CodexTokenData
	err   error
}

func (s *codexTokenRefresherStub) RefreshTokens(context.Context, string) (*codexauth.CodexTokenData, error) {
	s.calls++
	return s.data, s.err
}

func TestCodexExecutorRefreshUsesSingleTokenRefreshAttempt(t *testing.T) {
	stub := &codexTokenRefresherStub{
		err: errors.New("token refresh failed"),
	}
	prevFactory := newCodexTokenRefresher
	newCodexTokenRefresher = func(*config.Config, string) codexTokenRefresher {
		return stub
	}
	t.Cleanup(func() {
		newCodexTokenRefresher = prevFactory
	})

	executor := NewCodexExecutor(&config.Config{})
	_, err := executor.Refresh(context.Background(), &cliproxyauth.Auth{
		Metadata: map[string]any{
			"refresh_token": "refresh-token",
		},
	})
	if err == nil {
		t.Fatal("Refresh() error = nil, want token refresh error")
	}
	if stub.calls != 1 {
		t.Fatalf("RefreshTokens calls = %d, want 1", stub.calls)
	}
}
