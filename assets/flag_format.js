/**
 * Flag Format Settings JavaScript
 * Handles client-side test flag functionality and pattern suggestions
 * Validation occurs only on Save Settings (server-side)
 * Test Flag Format runs entirely on the client-side
 */

// Simple test to verify JavaScript is loading
console.log("Flag Format JavaScript file loaded");

document.addEventListener("DOMContentLoaded", function () {
  console.log("Flag Format JavaScript DOM loaded");

  const flagFormatInput = document.getElementById("flag_format");
  const testFlagInput = document.getElementById("test_flag");
  const testFormatBtn = document.getElementById("test-format-btn");
  const regexStatus = document.getElementById("regex-status");
  const testResult = document.getElementById("test-result");
  const enabledCheckbox = document.getElementById("enabled");

  console.log("Elements found:", {
    flagFormatInput: !!flagFormatInput,
    testFlagInput: !!testFlagInput,
    testFormatBtn: !!testFormatBtn,
    regexStatus: !!regexStatus,
    testResult: !!testResult,
    enabledCheckbox: !!enabledCheckbox,
  });

  // Get CSRF token
  const csrfToken = document.querySelector('input[name="nonce"]')?.value;
  console.log("CSRF token found:", !!csrfToken);
  console.log(
    "CSRF token value (first 10 chars):",
    csrfToken ? csrfToken.substring(0, 10) + "..." : "null"
  );


  /**
   * Show regex validation status
   */
  function showRegexStatus(message, type) {
    if (!message) {
      regexStatus.innerHTML = "";
      return;
    }

    const alertClass = `alert alert-${type}`;
    regexStatus.innerHTML = `<div class="${alertClass} alert-sm">${message}</div>`;
  }

  /**
   * Test flag format against pattern (client-side only)
   */
  function testFlagFormat() {
    console.log("testFlagFormat called (client-side)");

    const pattern = flagFormatInput.value.trim();
    const testFlag = testFlagInput.value.trim();

    console.log("Pattern:", pattern);
    console.log("Test flag:", testFlag);

    if (!pattern) {
      showTestResult("Please enter a regex pattern first", "warning");
      return;
    }

    if (!testFlag) {
      showTestResult("Please enter a test flag", "warning");
      return;
    }

    testFormatBtn.disabled = true;
    testFormatBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';

    // Simulate brief processing time for UX
    setTimeout(() => {
      try {
        // Client-side regex testing
        const regex = new RegExp("^" + pattern + "$");
        const matches = regex.test(testFlag);

        console.log("Client-side test result:", matches);

        if (matches) {
          showTestResult("✓ Flag matches the pattern!", "success");
        } else {
          showTestResult("✗ Flag does not match the pattern", "warning");
        }

      } catch (error) {
        console.error("Regex error:", error);
        showTestResult("✗ Invalid regular expression: " + error.message, "danger");
      } finally {
        testFormatBtn.disabled = false;
        testFormatBtn.innerHTML = "Test Format";
      }
    }, 300); // Small delay for UX
  }

  /**
   * Show test result
   */
  function showTestResult(message, type) {
    const alertClass = `alert alert-${type}`;
    testResult.innerHTML = `<div class="${alertClass} alert-sm">${message}</div>`;
  }

  /**
   * Handle form submission validation
   */
  function validateForm(event) {
    const enabled = enabledCheckbox.checked;
    const pattern = flagFormatInput.value.trim();

    if (enabled && !pattern) {
      event.preventDefault();
      showRegexStatus(
        "✗ Flag format is required when validation is enabled",
        "danger"
      );
      flagFormatInput.focus();
      return false;
    }

    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
    }

    return true;
  }

  /**
   * Auto-populate common patterns
   */
  function setupPatternSuggestions() {
    const patterns = {
      "flag{...}": "flag\\{.*\\}",
      "CTF{...}": "CTF\\{.*\\}",
      "CTF{alphanumeric}": "CTF\\{[a-zA-Z0-9_]+\\}",
      "flag{hex}": "flag\\{[0-9a-f]+\\}",
      "CTF{32-char-hex}": "CTF\\{[0-9a-f]{32}\\}",
    };

    // Create a dropdown or suggestions
    const suggestionsContainer = document.createElement("div");
    suggestionsContainer.className = "mt-2";
    suggestionsContainer.innerHTML =
      '<small class="text-muted">Quick patterns: </small>';

    Object.entries(patterns).forEach(([name, pattern]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "btn btn-sm btn-outline-secondary me-1 mb-1";
      button.textContent = name;
      button.onclick = () => {
        flagFormatInput.value = pattern;
        showRegexStatus("Pattern set. Click 'Save Settings' to validate.", "info");
      };
      suggestionsContainer.appendChild(button);
    });

    flagFormatInput.parentNode.appendChild(suggestionsContainer);
  }


  /**
   * Handle keyboard shortcuts
   */
  function setupKeyboardShortcuts() {
    // Ctrl+Enter to test format
    testFlagInput.addEventListener("keydown", function (event) {
      if (event.ctrlKey && event.key === "Enter") {
        event.preventDefault();
        testFlagFormat();
      }
    });

    // Escape to clear test result
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        testResult.innerHTML = "";
        regexStatus.innerHTML = "";
      }
    });
  }

  // Event listeners (validation removed, only for UI state)
  if (flagFormatInput) {
    console.log("Flag format input found (no real-time validation)");
  }

  if (testFormatBtn) {
    console.log("Adding click event listener to test format button");
    testFormatBtn.addEventListener("click", testFlagFormat);

    // Test if the button can be clicked
    testFormatBtn.addEventListener("click", function () {
      console.log("Test Format button clicked!");
    });
  } else {
    console.error("Test format button not found!");
  }

  // Form validation
  const form = document.querySelector("form");
  if (form) {
    form.addEventListener("submit", validateForm);
  }

  // Initialize enhancements
  setupPatternSuggestions();
  setupKeyboardShortcuts();

  // Handle checkbox state changes
  if (enabledCheckbox) {
    enabledCheckbox.addEventListener("change", function () {
      const isEnabled = this.checked;
      flagFormatInput.disabled = !isEnabled;

      if (!isEnabled) {
        showRegexStatus("", "info");
      }
    });

    // Initial state
    const isEnabled = enabledCheckbox.checked;
    flagFormatInput.disabled = !isEnabled;
  }

  // Show success message if settings were just saved
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get("saved") === "true") {
    const alertDiv = document.createElement("div");
    alertDiv.className = "alert alert-success alert-dismissible fade show";
    alertDiv.innerHTML = `
            Settings saved successfully!
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
    document.querySelector(".container .row .col-md-12").prepend(alertDiv);
  }
});
