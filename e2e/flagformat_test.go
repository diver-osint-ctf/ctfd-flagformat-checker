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

// withConfig installs cfg, restores the prior config on cleanup, and returns
// an admin client the test can reuse for further API calls / entity creation.
func withConfig(t *testing.T, cfg flagFormatConfig) *testutil.Client {
	t.Helper()
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	var orig flagFormatConfig
	if _, err := admin.GetJSON(configAPI, &orig); err != nil {
		t.Fatalf("read original config: %v", err)
	}
	t.Cleanup(func() { setConfig(t, sess, orig) })
	setConfig(t, sess, cfg)
	return admin
}

// newChallengeUser creates a standard challenge with the given flag plus a
// fresh user, returning the challenge ID and the user's client — the two
// things every submission test actually needs.
func newChallengeUser(t *testing.T, admin *testutil.Client, flag string) (int, *testutil.Client) {
	t.Helper()
	ns := testutil.Namespace(t)
	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: flag,
	})
	user := testutil.CreateUser(t, admin, ns, 1)
	return chal.ID, testutil.UserClient(t, user.Name, user.Password)
}

// assertFormatRejected posts badFormat through the admin form and asserts the
// plugin's validator refused to persist it. Used for the invalid-regex and
// unescaped-braces cases, which differ only in the rejected string.
func assertFormatRejected(t *testing.T, badFormat string) {
	t.Helper()
	sess := testutil.AdminSessionClient(t)
	form := url.Values{}
	form.Set("enabled", "on")
	form.Set("flag_format", badFormat)
	form.Set("error_message", "Bad")
	resp, err := sess.PostFormWithNonce(configAdmin, form)
	if err != nil {
		t.Fatalf("post bad format %q: %v", badFormat, err)
	}
	resp.Body.Close()
	// Reset to a known-good config so we don't poison subsequent tests.
	t.Cleanup(func() { setConfig(t, sess, flagFormatConfig{Enabled: false}) })

	admin := testutil.AdminClient(t)
	var got flagFormatConfig
	if _, err := admin.GetJSON(configAPI, &got); err != nil {
		t.Fatalf("read config: %v", err)
	}
	if got.FlagFormat == badFormat {
		t.Errorf("bad format %q should not have been saved; got %+v", badFormat, got)
	}
}

func TestFlagFormatChecker_RejectsBadFormat(t *testing.T) {
	admin := withConfig(t, flagFormatConfig{
		Enabled:      true,
		FlagFormat:   defaultRegex,
		ErrorMessage: "Bad flag format",
	})
	chalID, uc := newChallengeUser(t, admin, "flag{good_flag}")

	// 形式不正 → 400
	bad := testutil.Submit(t, uc, chalID, "this-is-not-a-flag")
	testutil.RequireBadFlagFormat(t, bad)

	// 正しい形式 → 200 / status=correct
	ok := testutil.Submit(t, uc, chalID, "flag{good_flag}")
	if ok.HTTPStatus != http.StatusOK || ok.Status != "correct" {
		t.Fatalf("well-formed flag: expected 200/correct, got %d/%s (%s)", ok.HTTPStatus, ok.Status, ok.Message)
	}
}

func TestFlagFormatChecker_AllowsAnyWhenDisabled(t *testing.T) {
	// 設定を「明示的に無効」にする — 既存の正規表現に依存しない。
	admin := withConfig(t, flagFormatConfig{Enabled: false, FlagFormat: defaultRegex})
	chalID, uc := newChallengeUser(t, admin, "flag{good_flag}")

	// 形式不正でも 400 にならない (CTFd 標準の incorrect 200 で帰る)
	res := testutil.Submit(t, uc, chalID, "totally-not-a-flag")
	if res.HTTPStatus != http.StatusOK {
		t.Errorf("expected 200 when checker is disabled, got %d (%s)", res.HTTPStatus, res.Message)
	}
}
