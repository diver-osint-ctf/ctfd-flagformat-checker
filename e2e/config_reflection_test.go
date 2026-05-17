// Admin-form persistence and hot-reload tests: every setting saved via POST
// must round-trip through the admin HTML, and changes to the live config
// must take effect immediately without needing a CTFd restart.
package e2e

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

const defaultErrorMessage = "Flag format does not match the required pattern."

func fetchAdminHTML(t *testing.T, sess *testutil.Client) string {
	t.Helper()
	resp, err := sess.HTTP.Get(sess.BaseURL + configAdmin)
	if err != nil {
		t.Fatalf("get admin page: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read admin page: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin page: HTTP %s", resp.Status)
	}
	return string(body)
}

// isCheckboxChecked returns true if <input id="<id>" ... checked ...> is
// rendered. The template emits a bare `checked` only when the config flag is
// truthy.
func isCheckboxChecked(html, id string) bool {
	re := regexp.MustCompile(`(?s)id="` + regexp.QuoteMeta(id) + `"([^>]*)>`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return false
	}
	return regexp.MustCompile(`\bchecked\b`).MatchString(m[1])
}

// extractInputValue pulls value="..." from <input id="<id>" ... value="...">.
func extractInputValue(t *testing.T, html, id string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)id="` + regexp.QuoteMeta(id) + `"[^>]*?value="([^"]*)"`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("could not find value for input id=%q in admin HTML", id)
	}
	return m[1]
}

// extractTextareaContent pulls the inner text of <textarea id="<id>">...</textarea>.
func extractTextareaContent(t *testing.T, html, id string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)<textarea[^>]*id="` + regexp.QuoteMeta(id) + `"[^>]*>(.*?)</textarea>`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("could not find <textarea id=%q> in admin HTML", id)
	}
	return strings.TrimSpace(m[1])
}

// TestFlagFormat_AdminFormReflectsSavedSettings — every field saved via the
// admin form must show up on the next GET. Covers enabled, case_sensitive,
// flag_format pattern, and the error_message textarea.
func TestFlagFormat_AdminFormReflectsSavedSettings(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)

	var orig flagFormatConfig
	if _, err := admin.GetJSON(configAPI, &orig); err != nil {
		t.Fatalf("read original config: %v", err)
	}
	t.Cleanup(func() { setConfig(t, sess, orig) })

	cases := []flagFormatConfig{
		{Enabled: true, CaseSensitive: true, FlagFormat: `flag\{[a-z]+\}`, ErrorMessage: "Need lowercase"},
		{Enabled: false, CaseSensitive: false, FlagFormat: `CTF\{.+\}`, ErrorMessage: "Try CTF prefix"},
		{Enabled: true, CaseSensitive: false, FlagFormat: `[0-9][0-9][0-9]`, ErrorMessage: "ダメだぞ"},
	}
	for _, c := range cases {
		name := c.FlagFormat + "/enabled=" + boolStr(c.Enabled) + "/case=" + boolStr(c.CaseSensitive)
		t.Run(name, func(t *testing.T) {
			setConfig(t, sess, c)
			html := fetchAdminHTML(t, sess)

			if got := isCheckboxChecked(html, "enabled"); got != c.Enabled {
				t.Errorf("enabled checkbox: checked=%t, want %t", got, c.Enabled)
			}
			if got := isCheckboxChecked(html, "case_sensitive"); got != c.CaseSensitive {
				t.Errorf("case_sensitive checkbox: checked=%t, want %t", got, c.CaseSensitive)
			}
			if got := extractInputValue(t, html, "flag_format"); got != c.FlagFormat {
				t.Errorf("flag_format value=%q, want %q", got, c.FlagFormat)
			}
			if got := extractTextareaContent(t, html, "error_message"); got != c.ErrorMessage {
				t.Errorf("error_message=%q, want %q", got, c.ErrorMessage)
			}
		})
	}
}

// TestFlagFormat_EmptyErrorMessageFallsBackToDefault — POSTing an empty
// error_message must cause the server to substitute the canned default
// (admin.py line ~114). The default must be both persisted (visible in the
// admin form on next GET) and surfaced to users on rejection.
func TestFlagFormat_EmptyErrorMessageFallsBackToDefault(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	var orig flagFormatConfig
	if _, err := admin.GetJSON(configAPI, &orig); err != nil {
		t.Fatalf("read original config: %v", err)
	}
	t.Cleanup(func() { setConfig(t, sess, orig) })

	setConfig(t, sess, flagFormatConfig{
		Enabled:      true,
		FlagFormat:   `flag\{[a-z]+\}`,
		ErrorMessage: "", // explicitly blank
	})

	// (1) The admin form should now show the default message in the textarea.
	html := fetchAdminHTML(t, sess)
	if got := extractTextareaContent(t, html, "error_message"); got != defaultErrorMessage {
		t.Errorf("admin textarea after blank submit: got %q, want %q", got, defaultErrorMessage)
	}

	// (2) A rejected submission should carry that same default message.
	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{good}",
	})
	user := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, user.Name, user.Password)

	bad := testutil.Submit(t, uc, chal.ID, "WRONG")
	testutil.RequireBadFlagFormat(t, bad)
	if !strings.Contains(bad.Message, defaultErrorMessage) {
		t.Errorf("rejection message=%q, want it to contain %q", bad.Message, defaultErrorMessage)
	}
}

// TestFlagFormat_PatternHotReload — change the pattern at runtime; the next
// submission must be judged by the new pattern, not the previous one. Guards
// against a regression where the plugin caches config in memory and only
// picks up changes on restart.
func TestFlagFormat_PatternHotReload(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	var orig flagFormatConfig
	if _, err := admin.GetJSON(configAPI, &orig); err != nil {
		t.Fatalf("read original config: %v", err)
	}
	t.Cleanup(func() { setConfig(t, sess, orig) })

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{any}",
	})
	user := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, user.Name, user.Password)

	// Phase 1: pattern requires "flag" prefix. "CTF{x}" must be rejected.
	setConfig(t, sess, flagFormatConfig{
		Enabled: true, FlagFormat: `flag\{[a-z]+\}`, ErrorMessage: "Bad",
	})
	testutil.RequireBadFlagFormat(t, testutil.Submit(t, uc, chal.ID, "CTF{x}"))

	// Phase 2: switch to a pattern that requires "CTF{" instead. The same
	// "CTF{x}" should now pass the format check (and come back as standard
	// incorrect 200 since the challenge flag is "flag{any}").
	setConfig(t, sess, flagFormatConfig{
		Enabled: true, FlagFormat: `CTF\{[a-z]+\}`, ErrorMessage: "Bad",
	})
	r := testutil.Submit(t, uc, chal.ID, "CTF{x}")
	if r.HTTPStatus != http.StatusOK {
		t.Fatalf("after pattern swap, CTF{x} expected 200/incorrect, got %d (%s)", r.HTTPStatus, r.Message)
	}
	// And the old "flag{any}" pattern that previously matched must now be the
	// rejected one — to prove the change is bidirectional.
	testutil.RequireBadFlagFormat(t, testutil.Submit(t, uc, chal.ID, "flag{any}"))
}

// TestFlagFormat_CaseSensitiveHotReload — toggling case_sensitive at runtime
// changes how the same uppercase submission is judged.
func TestFlagFormat_CaseSensitiveHotReload(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	var orig flagFormatConfig
	if _, err := admin.GetJSON(configAPI, &orig); err != nil {
		t.Fatalf("read original config: %v", err)
	}
	t.Cleanup(func() { setConfig(t, sess, orig) })

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{x}",
	})
	user := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, user.Name, user.Password)

	// Phase 1: case_sensitive=true → uppercase rejected.
	setConfig(t, sess, flagFormatConfig{
		Enabled: true, FlagFormat: `flag\{[a-z]+\}`, ErrorMessage: "Bad", CaseSensitive: true,
	})
	testutil.RequireBadFlagFormat(t, testutil.Submit(t, uc, chal.ID, "FLAG{X}"))

	// Phase 2: case_sensitive=false → same uppercase now passes the format
	// check (and goes through to CTFd's standard incorrect 200 because the
	// flag itself doesn't match).
	setConfig(t, sess, flagFormatConfig{
		Enabled: true, FlagFormat: `flag\{[a-z]+\}`, ErrorMessage: "Bad", CaseSensitive: false,
	})
	r := testutil.Submit(t, uc, chal.ID, "FLAG{X}")
	if r.HTTPStatus != http.StatusOK {
		t.Fatalf("after case toggle off, expected 200, got %d (%s)", r.HTTPStatus, r.Message)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
