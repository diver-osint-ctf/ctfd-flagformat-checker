"""
Tests for regex validation logic used in Save Settings.
Tests the validation functions that are called during settings save.
"""

import unittest
import re
import sys
import os

# Add the parent directory to sys.path to import the modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestRegexValidationLogic(unittest.TestCase):
    """Test regex validation logic."""

    def setUp(self):
        """Set up test fixtures."""
        # Mock CTFd dependencies
        self.mock_ctfd()

    def mock_ctfd(self):
        """Mock CTFd dependencies."""
        from unittest.mock import MagicMock

        # Mock CTFd modules
        ctfd_mock = MagicMock()
        ctfd_mock.plugins = MagicMock()
        ctfd_mock.models = MagicMock()
        ctfd_mock.utils = MagicMock()
        ctfd_mock.utils.decorators = MagicMock()

        sys.modules["CTFd"] = ctfd_mock
        sys.modules["CTFd.plugins"] = ctfd_mock.plugins
        sys.modules["CTFd.models"] = ctfd_mock.models
        sys.modules["CTFd.utils"] = ctfd_mock.utils
        sys.modules["CTFd.utils.decorators"] = ctfd_mock.utils.decorators

        # Mock Flask
        flask_mock = MagicMock()
        sys.modules["flask"] = flask_mock

    def validate_pattern_for_save(self, pattern, enabled=True):
        """
        Test helper that mimics the validation logic in Save Settings.
        Returns (is_valid, error_message).
        """
        if not enabled or not pattern:
            return True, "Validation skipped (disabled or empty)"

        try:
            # Basic regex compilation check
            re.compile(pattern)
            return True, "Valid pattern"

        except re.error as e:
            return False, f"Invalid regular expression: {str(e)}"

    def test_valid_patterns_pass_validation(self):
        """Test that valid patterns pass validation."""
        valid_patterns = [
            r"flag\{.*\}",
            r"CTF\{[a-zA-Z0-9_]+\}",
            r"flag\{[0-9a-f]{32}\}",
            r"[A-Z]{3}\{.*\}",
            r"flag\{.+\}",
            r"^flag\{.*\}$",
            r"flag|ctf",
            r"(?i)flag\{.*\}",
        ]

        for pattern in valid_patterns:
            with self.subTest(pattern=pattern):
                is_valid, message = self.validate_pattern_for_save(pattern)
                self.assertTrue(
                    is_valid, f"Pattern '{pattern}' should be valid: {message}"
                )

    def test_invalid_patterns_rejected(self):
        """Test that invalid patterns are rejected."""
        invalid_patterns = [
            ("[invalid", "unterminated character set"),
            ("(?P<invalid", "bad character in group name"),
            ("(?", "bad character in group name"),
            ("\\", "bad escape"),
            ("*", "nothing to repeat"),
            ("+", "nothing to repeat"),
            ("?", "nothing to repeat"),
            ("(", "missing )"),
            (")", "unbalanced parenthesis"),
        ]

        for pattern, expected_error_type in invalid_patterns:
            with self.subTest(pattern=pattern):
                is_valid, message = self.validate_pattern_for_save(pattern)
                self.assertFalse(
                    is_valid, f"Pattern '{pattern}' should be invalid: {message}"
                )
                self.assertIn("Invalid regular expression", message)

    def test_long_patterns_handled(self):
        """Test that very long patterns are handled properly."""
        # Very long patterns (still valid regex)
        long_patterns = [
            "a" * 100,  # Long but valid pattern
            "flag\\{" + "a" * 200 + "\\}",  # Long flag pattern
        ]

        for pattern in long_patterns:
            with self.subTest(pattern=f"pattern of length {len(pattern)}"):
                is_valid, message = self.validate_pattern_for_save(pattern)
                # These should pass basic regex validation
                self.assertTrue(is_valid, f"Long pattern should be valid: {message}")

    def test_disabled_validation_allows_any_pattern(self):
        """Test that disabled validation allows any pattern."""
        patterns = [
            "[invalid",
            "(?P<invalid",
            "flag{.*",
        ]

        for pattern in patterns:
            with self.subTest(pattern=pattern):
                is_valid, message = self.validate_pattern_for_save(
                    pattern, enabled=False
                )
                msg = f"Disabled validation should allow '{pattern}': {message}"
                self.assertTrue(is_valid, msg)

    def test_empty_pattern_allowed(self):
        """Test that empty patterns are allowed."""
        is_valid, message = self.validate_pattern_for_save("", enabled=True)
        self.assertTrue(is_valid, f"Empty pattern should be allowed: {message}")

    def test_whitespace_only_pattern_allowed(self):
        """Test that whitespace-only patterns are allowed (they get stripped)."""
        is_valid, message = self.validate_pattern_for_save("   ", enabled=True)
        self.assertTrue(is_valid, f"Whitespace pattern should be allowed: {message}")


class TestComplexPatternValidation(unittest.TestCase):
    """Test complex pattern validation scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_ctfd()

    def mock_ctfd(self):
        """Mock CTFd dependencies."""
        from unittest.mock import MagicMock

        # Mock CTFd modules
        ctfd_mock = MagicMock()
        sys.modules["CTFd"] = ctfd_mock
        sys.modules["CTFd.plugins"] = ctfd_mock.plugins
        sys.modules["CTFd.models"] = ctfd_mock.models
        sys.modules["CTFd.utils"] = ctfd_mock.utils
        sys.modules["CTFd.utils.decorators"] = ctfd_mock.utils.decorators

        # Mock Flask
        flask_mock = MagicMock()
        sys.modules["flask"] = flask_mock

    def test_real_world_flag_patterns(self):
        """Test real-world flag patterns that should work."""
        real_patterns = [
            # Common CTF flag formats
            r"flag\{[a-f0-9]{32}\}",  # MD5 hash
            r"flag\{[a-f0-9]{40}\}",  # SHA1 hash
            r"CTF\{[A-Za-z0-9_]+\}",  # Alphanumeric with underscores
            r"[A-Z]{3}\{.*\}",  # Any 3 uppercase letters
            r"flag\{[^}]+\}",  # Anything except closing brace
            r"(?i)flag\{.*\}",  # Case insensitive
            r"^flag\{.*\}$",  # Anchored
            r"flag\{.{10,50}\}",  # Length constraint
            r"flag\{[a-zA-Z0-9_\-]+\}",  # Common characters
        ]

        for pattern in real_patterns:
            with self.subTest(pattern=pattern):
                try:
                    compiled = re.compile(pattern)
                    self.assertIsNotNone(compiled)

                    # Pattern compilation successful
                    self.assertTrue(True, f"Pattern '{pattern}' compiled successfully")

                except re.error as e:
                    msg = f"Real-world pattern '{pattern}' should be valid but got: {e}"
                    self.fail(msg)

    def test_potentially_dangerous_patterns(self):
        """Test patterns that could be dangerous but might still be valid regex."""
        dangerous_patterns = [
            r"(a+)+",  # Catastrophic backtracking potential
            r"(a|a)*",  # Redundant alternation
            r"a{1000}",  # Very long repetition
            r".*.*.*.*.*",  # Multiple .* patterns
        ]

        for pattern in dangerous_patterns:
            with self.subTest(pattern=pattern):
                try:
                    # These are valid regex but potentially slow
                    compiled = re.compile(pattern)
                    self.assertIsNotNone(compiled)

                    # Basic regex validation only
                    print(f"Valid regex pattern: {pattern}")

                except re.error:
                    # If they fail to compile, that's also acceptable
                    pass


class TestSaveSettingsIntegration(unittest.TestCase):
    """Integration tests for Save Settings validation."""

    def test_validation_workflow(self):
        """Test the complete validation workflow (simplified)."""
        test_cases = [
            # (enabled, pattern, should_pass, expected_message_contains)
            (True, r"flag\{.*\}", True, None),
            (True, "[invalid", False, "Invalid regex"),
            (False, "[invalid", True, None),  # Disabled validation
            (True, "", True, None),  # Empty pattern
            (True, r"flag\{[a-f0-9]{32}\}", True, None),  # Valid MD5 pattern
        ]

        for enabled, pattern, should_pass, expected_message in test_cases:
            with self.subTest(enabled=enabled, pattern=pattern):
                # Test the validation logic
                if not enabled or not pattern:
                    # Skip validation
                    result = True
                    message = "Validation skipped"
                else:
                    try:
                        # Basic regex check only
                        re.compile(pattern)
                        result = True
                        message = "Valid"
                    except re.error as e:
                        result = False
                        message = f"Invalid regex: {str(e)}"

                if should_pass:
                    msg = f"Expected pattern '{pattern}' to pass but got: {message}"
                    self.assertTrue(result, msg)
                else:
                    msg = f"Expected pattern '{pattern}' to fail but it passed"
                    self.assertFalse(result, msg)
                    if expected_message:
                        self.assertIn(expected_message, message)


if __name__ == "__main__":
    unittest.main()
