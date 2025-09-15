import unittest
import re
from datetime import datetime, timezone


class MockFlagFormatConfig:
    """Mock implementation of FlagFormatConfig for testing."""

    def __init__(self, enabled=False, flag_format=None, error_message=None):
        self.enabled = enabled
        self.flag_format = flag_format
        self.error_message = error_message or (
            "Flag format does not match the required pattern."
        )
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)


def validate_flag_format(submitted_flag, config):
    """
    Standalone flag validation logic for testing.
    """
    if not config.enabled or not config.flag_format:
        return True, None

    try:
        pattern = re.compile(config.flag_format)
        if pattern.fullmatch(submitted_flag):
            return True, None
        else:
            return False, config.error_message
    except re.error:
        # Invalid regex pattern
        return True, None  # Allow through on invalid regex


class TestFlagFormatLogic(unittest.TestCase):
    """Test cases for flag format validation logic."""

    def test_flag_validation_disabled(self):
        """Test that validation is skipped when disabled."""
        config = MockFlagFormatConfig(enabled=False, flag_format=r"flag\{.*\}")

        valid, message = validate_flag_format("invalid_flag", config)

        self.assertTrue(valid)
        self.assertIsNone(message)

    def test_flag_validation_no_format(self):
        """Test that validation is skipped when no format is specified."""
        config = MockFlagFormatConfig(enabled=True, flag_format=None)

        valid, message = validate_flag_format("any_flag", config)

        self.assertTrue(valid)
        self.assertIsNone(message)

    def test_flag_validation_valid_format(self):
        """Test validation with valid flag format."""
        config = MockFlagFormatConfig(
            enabled=True, flag_format=r"flag\{.*\}", error_message="Invalid flag format"
        )

        valid, message = validate_flag_format("flag{test123}", config)

        self.assertTrue(valid)
        self.assertIsNone(message)

    def test_flag_validation_invalid_format(self):
        """Test validation with invalid flag format."""
        config = MockFlagFormatConfig(
            enabled=True, flag_format=r"flag\{.*\}", error_message="Invalid flag format"
        )

        valid, message = validate_flag_format("invalid_flag", config)

        self.assertFalse(valid)
        self.assertEqual(message, "Invalid flag format")

    def test_flag_validation_complex_pattern(self):
        """Test validation with complex regex pattern."""
        config = MockFlagFormatConfig(
            enabled=True,
            flag_format=r"CTF\{[a-zA-Z0-9_]+\}",
            error_message="Flag must be CTF{alphanumeric_underscore}",
        )

        # Valid cases
        valid_flags = ["CTF{test123}", "CTF{hello_world}", "CTF{ABC123_def456}"]

        for flag in valid_flags:
            with self.subTest(flag=flag):
                valid, message = validate_flag_format(flag, config)
                self.assertTrue(valid, f"Flag {flag} should be valid")
                self.assertIsNone(message)

        # Invalid cases
        invalid_flags = [
            "flag{test123}",  # Wrong prefix
            "CTF{test-123}",  # Hyphen not allowed
            "CTF{test 123}",  # Space not allowed
            "CTF{test123",  # Missing closing brace
            "CTF test123}",  # Missing opening brace
        ]

        for flag in invalid_flags:
            with self.subTest(flag=flag):
                valid, message = validate_flag_format(flag, config)
                self.assertFalse(valid, f"Flag {flag} should be invalid")
                self.assertEqual(message, "Flag must be CTF{alphanumeric_underscore}")

    def test_flag_validation_invalid_regex(self):
        """Test validation with invalid regex pattern."""
        config = MockFlagFormatConfig(
            enabled=True,
            flag_format="[invalid_regex",  # Invalid regex
            error_message="Invalid flag format",
        )

        # Should return True (allow through) when regex is invalid
        valid, message = validate_flag_format("any_flag", config)

        self.assertTrue(valid)
        self.assertIsNone(message)

    def test_case_sensitive_validation(self):
        """Test that validation is case sensitive."""
        config = MockFlagFormatConfig(
            enabled=True, flag_format=r"flag\{.*\}", error_message="Invalid flag format"
        )

        # Lowercase should work
        valid, message = validate_flag_format("flag{test}", config)
        self.assertTrue(valid)

        # Uppercase should not work
        valid, message = validate_flag_format("FLAG{test}", config)
        self.assertFalse(valid)
        self.assertEqual(message, "Invalid flag format")

    def test_partial_match_rejection(self):
        """Test that partial matches are rejected (must match entire string)."""
        config = MockFlagFormatConfig(
            enabled=True, flag_format=r"flag\{.*\}", error_message="Invalid flag format"
        )

        # Should reject partial matches
        invalid_flags = [
            "prefix_flag{test}",
            "flag{test}_suffix",
            "prefix_flag{test}_suffix",
        ]

        for flag in invalid_flags:
            with self.subTest(flag=flag):
                valid, message = validate_flag_format(flag, config)
                self.assertFalse(
                    valid, f"Flag {flag} should be invalid (partial match)"
                )

    def test_empty_flag_handling(self):
        """Test handling of empty flag submission."""
        config = MockFlagFormatConfig(
            enabled=True, flag_format=r"flag\{.*\}", error_message="Invalid flag format"
        )

        valid, message = validate_flag_format("", config)

        self.assertFalse(valid)
        self.assertEqual(message, "Invalid flag format")


if __name__ == "__main__":
    unittest.main()
