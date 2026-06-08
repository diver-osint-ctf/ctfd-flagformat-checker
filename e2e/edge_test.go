// Edge-case and configuration tests for ctfd-flagformat-checker beyond the
// basic accept/reject smoke. These exercise case sensitivity, the empty-regex
// bypass, fullmatch semantics, complex patterns, error messages, and the
// admin form's input validation (invalid regex, unescaped braces).
//
// Shared helpers (withConfig, newChallengeUser, setConfig, assertFormatRejected)
// live in flagformat_test.go.
package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

func TestFlagFormat_CaseSensitive_True(t *testing.T) {
	admin := withConfig(t, flagFormatConfig{
		Enabled:       true,
		FlagFormat:    defaultRegex,
		ErrorMessage:  "Bad",
		CaseSensitive: true,
	})
	chalID, uc := newChallengeUser(t, admin, "flag{good}")

	// Uppercase variant must be rejected when case_sensitive is on.
	bad := testutil.Submit(t, uc, chalID, "FLAG{GOOD}")
	testutil.RequireBadFlagFormat(t, bad)
}

func TestFlagFormat_CaseSensitive_False(t *testing.T) {
	admin := withConfig(t, flagFormatConfig{
		Enabled:       true,
		FlagFormat:    defaultRegex,
		ErrorMessage:  "Bad",
		CaseSensitive: false,
	})
	chalID, uc := newChallengeUser(t, admin, "flag{good}")

	// Uppercase passes the format check (still standard "incorrect" 200).
	r := testutil.Submit(t, uc, chalID, "FLAG{GOOD}")
	if r.HTTPStatus != http.StatusOK {
		t.Fatalf("expected 200 (case-insensitive), got %d (%s)", r.HTTPStatus, r.Message)
	}
}

func TestFlagFormat_EmptyRegexBypassesCheck(t *testing.T) {
	admin := withConfig(t, flagFormatConfig{Enabled: true, FlagFormat: ""})
	chalID, uc := newChallengeUser(t, admin, "flag{good}")

	// Without a pattern the plugin must skip its check entirely.
	r := testutil.Submit(t, uc, chalID, "anything-goes")
	if r.HTTPStatus != http.StatusOK {
		t.Fatalf("expected 200 with empty regex, got %d (%s)", r.HTTPStatus, r.Message)
	}
}

func TestFlagFormat_FullmatchNotPartial(t *testing.T) {
	// fullmatch behaviour means substring matches must fail.
	admin := withConfig(t, flagFormatConfig{Enabled: true, FlagFormat: `flag`, ErrorMessage: "Bad"})
	chalID, uc := newChallengeUser(t, admin, "flag")

	bad := testutil.Submit(t, uc, chalID, "prefix_flag_suffix")
	testutil.RequireBadFlagFormat(t, bad)

	ok := testutil.Submit(t, uc, chalID, "flag")
	if ok.HTTPStatus != http.StatusOK || ok.Status != "correct" {
		t.Fatalf("exact match should be 200/correct, got %d/%s", ok.HTTPStatus, ok.Status)
	}
}

func TestFlagFormat_ComplexRegex(t *testing.T) {
	// The plugin's admin validator rejects any pattern that contains an
	// unescaped `{` (it treats `{6}` quantifiers the same as `{flag}`,
	// see TestFlagFormat_UnescapedBracesRejected), so a 6-digit pattern can
	// only be expressed long-hand as repeated character classes.
	admin := withConfig(t, flagFormatConfig{
		Enabled:      true,
		FlagFormat:   `[0-9][0-9][0-9][0-9][0-9][0-9]`,
		ErrorMessage: "Bad",
	})
	chalID, uc := newChallengeUser(t, admin, "123456")

	// Letters in a digits-only pattern → 400.
	letters := testutil.Submit(t, uc, chalID, "abcdef")
	testutil.RequireBadFlagFormat(t, letters)

	// Exactly 6 digits → passes the format check (correct flag → 200/correct).
	ok := testutil.Submit(t, uc, chalID, "123456")
	if ok.HTTPStatus != http.StatusOK || ok.Status != "correct" {
		t.Fatalf("6-digit correct flag: expected 200/correct, got %d/%s", ok.HTTPStatus, ok.Status)
	}
}

func TestFlagFormat_ErrorMessageCustomization(t *testing.T) {
	admin := withConfig(t, flagFormatConfig{
		Enabled:      true,
		FlagFormat:   `flag\{x\}`,
		ErrorMessage: "ダメだぞ",
	})
	chalID, uc := newChallengeUser(t, admin, "flag{x}")

	bad := testutil.Submit(t, uc, chalID, "wrong")
	testutil.RequireBadFlagFormat(t, bad)
	if !strings.Contains(bad.Message, "ダメだぞ") {
		t.Errorf("expected custom error message in response, got: %q", bad.Message)
	}
}

func TestFlagFormat_ConfigAPIShape(t *testing.T) {
	admin := withConfig(t, flagFormatConfig{
		Enabled:      true,
		FlagFormat:   `flag\{x\}`,
		ErrorMessage: "Bad",
	})
	var got flagFormatConfig
	resp, err := admin.GetJSON(configAPI, &got)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("config API: status=%v err=%v", resp.Status, err)
	}
	if !got.Enabled || got.FlagFormat == "" || got.ErrorMessage == "" {
		t.Errorf("config API returned unexpected payload: %+v", got)
	}
}

func TestFlagFormat_NoSubmissionField(t *testing.T) {
	// CTFd's own challenges_attempt schema rejects a request with a missing
	// `submission` field. The plugin's hook guards that case
	// (`if "submission" not in data: return`) and must fall through to CTFd
	// rather than inject its own 400 carrying the configured error message.
	admin := withConfig(t, flagFormatConfig{
		Enabled:      true,
		FlagFormat:   `flag\{x\}`,
		ErrorMessage: "Bad",
	})
	chalID, uc := newChallengeUser(t, admin, "flag{x}")

	resp, err := uc.PostJSON("/api/v1/challenges/attempt",
		map[string]any{"challenge_id": chalID}, nil)
	if err != nil {
		t.Fatalf("malformed submit: %v", err)
	}
	defer resp.Body.Close()

	// The missing-key guard regressed if the response carries the plugin's
	// configured error message.
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "Bad") {
		t.Errorf("missing-submission guard regressed: response carries flagformat error message: %s", body)
	}
}

func TestFlagFormat_InvalidRegexFlashesError(t *testing.T) {
	// Invalid regex must NOT be persisted.
	assertFormatRejected(t, `flag\{[unterminated`)
}

func TestFlagFormat_UnescapedBracesRejected(t *testing.T) {
	// Plugin's admin handler treats unescaped { } as a validation error and
	// redirects without persisting the new format string.
	assertFormatRejected(t, "flag{abc}")
}
