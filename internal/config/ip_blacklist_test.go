package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseConfigBytesIPBlacklistOptional(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "missing", data: "port: 8317\n"},
		{name: "null", data: "ip-blacklist: null\n"},
		{name: "empty", data: "ip-blacklist: []\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, errParse := ParseConfigBytes([]byte(tt.data))
			if errParse != nil {
				t.Fatalf("ParseConfigBytes() error = %v", errParse)
			}
			if len(cfg.IPBlacklist) != 0 {
				t.Fatalf("IPBlacklist = %#v, want empty", cfg.IPBlacklist)
			}
		})
	}
}

func TestParseConfigBytesNormalizesIPBlacklist(t *testing.T) {
	data := []byte(`ip-blacklist:
  - " 203.0.113.8 "
  - "203.0.113.8"
  - "10.0.0.15/8"
  - "2001:0db8::1"
  - "2001:db8::1"
`)
	cfg, errParse := ParseConfigBytes(data)
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	want := []string{"203.0.113.8", "10.0.0.0/8", "2001:db8::1"}
	if !reflect.DeepEqual(cfg.IPBlacklist, want) {
		t.Fatalf("IPBlacklist = %#v, want %#v", cfg.IPBlacklist, want)
	}
}

func TestParseConfigBytesRejectsInvalidIPBlacklist(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{name: "empty", entry: `""`},
		{name: "invalid IP", entry: `"not-an-ip"`},
		{name: "invalid prefix", entry: `"10.0.0.0/99"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errParse := ParseConfigBytes([]byte("ip-blacklist:\n  - " + tt.entry + "\n"))
			if errParse == nil {
				t.Fatal("ParseConfigBytes() error = nil, want validation error")
			}
			if !strings.Contains(errParse.Error(), "ip-blacklist") {
				t.Fatalf("ParseConfigBytes() error = %q, want ip-blacklist context", errParse)
			}
		})
	}
}

func TestLoadConfigOptionalKeepsOptionalInvalidConfigSemantics(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte("ip-blacklist:\n  - not-an-ip\n"), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}

	cfg, errLoad := LoadConfigOptional(configPath, true)
	if errLoad != nil {
		t.Fatalf("LoadConfigOptional() error = %v", errLoad)
	}
	if len(cfg.IPBlacklist) != 0 {
		t.Fatalf("IPBlacklist = %#v, want empty optional config", cfg.IPBlacklist)
	}

	if _, errLoad = LoadConfigOptional(configPath, false); errLoad == nil {
		t.Fatal("LoadConfigOptional(optional=false) error = nil, want validation error")
	}
}
