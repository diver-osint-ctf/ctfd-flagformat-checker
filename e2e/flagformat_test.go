// Package e2e tests the ctfd-flagformat-checker plugin against a running CTFd
// instance set up by ctfd-plugin-e2e.
//
// The plugin intercepts /api/v1/challenges/attempt and rejects submissions
// that do not match a configured regex with HTTP 400.
//
// Tests in this package touch global plugin configuration, so they cannot
// t.Parallel(). The cleanup hook restores the previous config.
package e2e

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

const (
	configAPI    = "/admin/flag-format/api/config"
	configAdmin  = "/admin/flag-format"
	defaultRegex = `flag\{[a-z0-9_]+\}`
)

type flagFormatConfig struct {
	Enabled       bool   `json:"enabled"`
	FlagFormat    string `json:"flag_format"`
	ErrorMessage  string `json:"error_message"`
	CaseSensitive bool   `json:"case_sensitive"`
}

// setConfig posts the admin form. CTFd's tokens() middleware only injects
// admin auth when the request is JSON, so admin form posts must come from a
// session client. The form is also CSRF-protected by CTFd's standard nonce
// check, hence PostFormWithNonce.
func setConfig(t *testing.T, sess *testutil.Client, cfg flagFormatConfig) {
	t.Helper()
	form := url.Values{}
	if cfg.Enabled {
		form.Set("enabled", "on")
	}
	if cfg.CaseSensitive {
		form.Set("case_sensitive", "on")
	}
	form.Set("flag_format", cfg.FlagFormat)
	form.Set("error_message", cfg.ErrorMessage)
	resp, err := sess.PostFormWithNonce(configAdmin, form)
	if err != nil {
		t.Fatalf("set flag-format config: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("set flag-format config: HTTP %s", resp.Status)
	}
}

func TestFlagFormatChecker_RejectsBadFormat(t *testing.T) {
	admin := testutil.AdminClient(t)
	ns := testutil.Namespace(t)

	var orig flagFormatConfig
	if _, err := admin.GetJSON(configAPI, &orig); err != nil {
		t.Fatalf("read original flag-format config: %v", err)
	}
	sess := testutil.AdminSessionClient(t)
	t.Cleanup(func() { setConfig(t, sess, orig) })

	setConfig(t, sess, flagFormatConfig{
		Enabled:      true,
		FlagFormat:   defaultRegex,
		ErrorMessage: "Bad flag format",
	})

	user := testutil.CreateUser(t, admin, ns, 1)
	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{good_flag}",
	})

	uc := testutil.UserClient(t, user.Name, user.Password)

	// 形式不正 → 400
	bad := testutil.Submit(t, uc, chal.ID, "this-is-not-a-flag")
	testutil.RequireBadFlagFormat(t, bad)

	// 正しい形式 → 200 / status=correct
	ok := testutil.Submit(t, uc, chal.ID, "flag{good_flag}")
	if ok.HTTPStatus != http.StatusOK {
		t.Fatalf("expected 200 for well-formed flag, got %d (%s)", ok.HTTPStatus, ok.Message)
	}
	if ok.Status != "correct" {
		t.Errorf("expected status=correct, got %q (%s)", ok.Status, ok.Message)
	}
}

func TestFlagFormatChecker_AllowsAnyWhenDisabled(t *testing.T) {
	admin := testutil.AdminClient(t)
	ns := testutil.Namespace(t)

	var orig flagFormatConfig
	if _, err := admin.GetJSON(configAPI, &orig); err != nil {
		t.Fatalf("read original flag-format config: %v", err)
	}
	sess := testutil.AdminSessionClient(t)
	t.Cleanup(func() { setConfig(t, sess, orig) })

	// 設定を「明示的に無効」にする — 既存の正規表現に依存しない。
	setConfig(t, sess, flagFormatConfig{Enabled: false, FlagFormat: defaultRegex})

	user := testutil.CreateUser(t, admin, ns, 1)
	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{good_flag}",
	})
	uc := testutil.UserClient(t, user.Name, user.Password)

	// 形式不正でも 400 にならない (CTFd 標準の incorrect 200 で帰る)
	res := testutil.Submit(t, uc, chal.ID, "totally-not-a-flag")
	if res.HTTPStatus != http.StatusOK {
		t.Errorf("expected 200 when checker is disabled, got %d (%s)", res.HTTPStatus, res.Message)
	}
}
