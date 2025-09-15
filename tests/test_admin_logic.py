import unittest
import re


class MockAdminBlueprint:
    """Mock implementation of admin blueprint for testing."""

    def __init__(self):
        self.routes = {}

    def add_route(self, path, methods, handler):
        self.routes[path] = {"methods": methods, "handler": handler}


def validate_regex_pattern(pattern):
    """
    Standalone regex validation logic for testing.
    """
    if not pattern:
        return True, "Empty pattern"

    try:
        re.compile(pattern)
        return True, "Valid regex pattern"
    except re.error as e:
        return False, f"Invalid regex: {str(e)}"


def validate_flag_format_match(pattern, test_flag):
    """
    Standalone flag format testing logic.
    """
    if not pattern:
        return False, "No pattern provided", True

    if not test_flag:
        return False, "No test flag provided", True

    try:
        compiled_pattern = re.compile(pattern)
        matches = bool(compiled_pattern.fullmatch(test_flag))

        return (
            matches,
            "Match successful" if matches else "No match",
            True,
        )
    except re.error as e:
        return False, f"Invalid regex: {str(e)}", False


def validate_admin_form_data(enabled, flag_format, error_message):
    """
    Validate admin form submission data.
    """
    errors = []

    # Validate enabled status
    if enabled and not flag_format:
        errors.append("Flag format is required when validation is enabled")

    # Validate regex if provided
    if flag_format:
        try:
            re.compile(flag_format)
        except re.error as e:
            errors.append(f"Invalid regular expression: {str(e)}")

    # Set default error message if empty
    if not error_message:
        error_message = "Flag format does not match the required pattern."

    return len(errors) == 0, errors, error_message


class TestAdminLogic(unittest.TestCase):
    """Test cases for admin functionality logic."""

    def test_regex_validation_valid(self):
        """Test regex validation with valid patterns."""
        valid_patterns = [
            r"flag\{.*\}",
            r"CTF\{[a-zA-Z0-9_]+\}",
            r"[A-Z]{3}\{[a-f0-9]{32}\}",
            r"flag\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
        ]

        for pattern in valid_patterns:
            with self.subTest(pattern=pattern):
                valid, message = validate_regex_pattern(pattern)
                self.assertTrue(valid, f"Pattern {pattern} should be valid")
                self.assertEqual(message, "Valid regex pattern")

    def test_regex_validation_invalid(self):
        """Test regex validation with invalid patterns."""
        invalid_patterns = [
            "[invalid_regex",  # Missing closing bracket
            "*invalid",  # Invalid quantifier
            "(?P<invalid)",  # Invalid group name
            "\\",  # Incomplete escape
        ]

        for pattern in invalid_patterns:
            with self.subTest(pattern=pattern):
                valid, message = validate_regex_pattern(pattern)
                self.assertFalse(valid, f"Pattern {pattern} should be invalid")
                self.assertIn("Invalid regex:", message)

    def test_regex_validation_empty(self):
        """Test regex validation with empty pattern."""
        valid, message = validate_regex_pattern("")
        self.assertTrue(valid)
        self.assertEqual(message, "Empty pattern")

    def validate_flag_format_matching(self):
        """Test flag format matching functionality."""
        test_cases = [
            # (pattern, test_flag, should_match)
            (r"flag\{.*\}", "flag{test123}", True),
            (r"flag\{.*\}", "invalid_flag", False),
            (r"CTF\{[a-zA-Z0-9_]+\}", "CTF{test123}", True),
            (r"CTF\{[a-zA-Z0-9_]+\}", "CTF{test-123}", False),  # Hyphen not allowed
            (r"[A-Z]{3}\{[a-f0-9]{32}\}", "ABC{" + "a" * 32 + "}", True),
            (r"[A-Z]{3}\{[a-f0-9]{32}\}", "ABC{" + "a" * 31 + "}", False),  # Too short
        ]

        for pattern, test_flag, should_match in test_cases:
            with self.subTest(pattern=pattern, test_flag=test_flag):
                matches, message, valid = validate_flag_format_match(pattern, test_flag)
                self.assertTrue(valid, "Pattern should be valid")
                if should_match:
                    self.assertTrue(matches, f"'{test_flag}' should match '{pattern}'")
                    self.assertEqual(message, "Match successful")
                else:
                    self.assertFalse(
                        matches, f"'{test_flag}' should not match '{pattern}'"
                    )
                    self.assertEqual(message, "No match")

    def validate_flag_format_matching_edge_cases(self):
        """Test edge cases for flag format matching."""
        # Empty pattern
        matches, message, valid = validate_flag_format_match("", "flag{test}")
        self.assertFalse(matches)
        self.assertEqual(message, "No pattern provided")
        self.assertTrue(valid)

        # Empty test flag
        matches, message, valid = validate_flag_format_match(r"flag\{.*\}", "")
        self.assertFalse(matches)
        self.assertEqual(message, "No test flag provided")
        self.assertTrue(valid)

        # Invalid regex
        matches, message, valid = validate_flag_format_match("[invalid", "flag{test}")
        self.assertFalse(matches)
        self.assertIn("Invalid regex:", message)
        self.assertFalse(valid)

    def test_admin_form_validation(self):
        """Test admin form data validation."""
        # Valid form data
        valid, errors, msg = validate_admin_form_data(
            True, r"flag\{.*\}", "Custom error message"
        )
        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)
        self.assertEqual(msg, "Custom error message")

        # Disabled with no format (should be valid)
        valid, errors, msg = validate_admin_form_data(False, "", "")
        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)

        # Enabled but no format (should be invalid)
        valid, errors, msg = validate_admin_form_data(True, "", "")
        self.assertFalse(valid)
        self.assertIn("Flag format is required when validation is enabled", errors)

        # Invalid regex (should be invalid)
        valid, errors, msg = validate_admin_form_data(True, "[invalid", "Error")
        self.assertFalse(valid)
        self.assertIn("Invalid regular expression:", errors[0])

        # Empty error message gets default
        valid, errors, msg = validate_admin_form_data(False, r"flag\{.*\}", "")
        self.assertTrue(valid)
        self.assertEqual(msg, "Flag format does not match the required pattern.")

    def test_complex_regex_patterns(self):
        """Test complex regex patterns that might be used in CTFs."""
        complex_patterns = [
            # UUID format
            (
                r"flag\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
                "flag{550e8400-e29b-41d4-a716-446655440000}",
                True,
            ),
            # Base64-like format
            (r"CTF\{[A-Za-z0-9+/]+=*\}", "CTF{SGVsbG9Xb3JsZA==}", True),
            # Hex format with specific length
            (r"flag\{[0-9a-f]{32}\}", "flag{" + "a" * 32 + "}", True),
            (r"flag\{[0-9a-f]{32}\}", "flag{" + "a" * 31 + "}", False),  # Wrong length
            # Mixed alphanumeric with underscores
            (r"CTF\{[a-zA-Z0-9_]{10,50}\}", "CTF{test_flag_123}", True),
            (r"CTF\{[a-zA-Z0-9_]{10,50}\}", "CTF{short}", False),  # Too short
        ]

        for pattern, test_flag, should_match in complex_patterns:
            with self.subTest(pattern=pattern, test_flag=test_flag):
                # First validate the pattern
                valid, _ = validate_regex_pattern(pattern)
                self.assertTrue(valid, f"Pattern {pattern} should be valid")

                # Then test matching
                matches, _, _ = validate_flag_format_match(pattern, test_flag)
                if should_match:
                    self.assertTrue(matches, f"'{test_flag}' should match '{pattern}'")
                else:
                    self.assertFalse(
                        matches, f"'{test_flag}' should not match '{pattern}'"
                    )

    def test_case_sensitivity(self):
        """Test case sensitivity in pattern matching."""
        # Case-sensitive pattern
        pattern = r"flag\{[a-z]+\}"

        # Should match lowercase
        matches, _, _ = validate_flag_format_match(pattern, "flag{test}")
        self.assertTrue(matches)

        # Should not match uppercase
        matches, _, _ = validate_flag_format_match(pattern, "flag{TEST}")
        self.assertFalse(matches)

        # Mixed case pattern
        pattern = r"[Ff]lag\{.*\}"

        matches, _, _ = validate_flag_format_match(pattern, "Flag{test}")
        self.assertTrue(matches)

        matches, _, _ = validate_flag_format_match(pattern, "flag{test}")
        self.assertTrue(matches)

    def test_special_characters_escaping(self):
        """Test proper escaping of special regex characters."""
        # Literal braces (properly escaped)
        pattern = r"flag\{.*\}"
        matches, _, _ = validate_flag_format_match(pattern, "flag{test}")
        self.assertTrue(matches)

        # Literal dots
        pattern = r"flag\.txt\{.*\}"
        matches, _, _ = validate_flag_format_match(pattern, "flag.txt{test}")
        self.assertTrue(matches)

        # Should not match without proper escaping expectation
        matches, _, _ = validate_flag_format_match(pattern, "flagXtxt{test}")
        self.assertFalse(matches)


if __name__ == "__main__":
    unittest.main()
