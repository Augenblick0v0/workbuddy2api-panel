package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyReloginPreservesIdentityAndLatestCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workbuddy-a.json")
	old := &Auth{UID: "a", AccessToken: "synthetic-old", RefreshToken: "synthetic-old-refresh", FilePath: path, DeviceToken: "fixture-device"}
	candidate := &Auth{UID: "a", AccessToken: "synthetic-new", RefreshToken: "synthetic-new-refresh", FilePath: filepath.Join(t.TempDir(), "other.json")}
	if err := old.ReplaceCredentials(candidate); err != nil {
		t.Fatal(err)
	}
	if err := old.SaveAtomic(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "synthetic-new-refresh") || strings.Contains(string(raw), "CredentialEpoch") || old.CredentialEpoch != 1 || old.DeviceToken != "fixture-device" {
		t.Fatal("replacement lost state or exposed runtime epoch")
	}
}
