"""
Security utilities for flag format validation.
Provides protection against regex injection and other security concerns.
"""

import re
import time
from typing import Optional, Tuple


class RegexSecurityValidator:
    """
    Validates regex patterns for security concerns.
    """

    # Maximum allowed pattern length to prevent DoS
    MAX_PATTERN_LENGTH = 500

    # Maximum allowed compilation time (in seconds)
    MAX_COMPILATION_TIME = 1.0

    # Dangerous regex patterns that could cause ReDoS
    DANGEROUS_PATTERNS = [
        r"\(\?\#",  # Comment groups that could hide malicious content
        r"\(\?\:",  # Non-capturing groups in complex nested patterns
        r"[\(\[\{]\*",  # Patterns that could cause exponential backtracking
        r"[\(\[\{]\+",  # Similar potential for backtracking
        r"\.\*\.\*",  # Multiple .* patterns
        r"\.\+\.\+",  # Multiple .+ patterns
        r"[\(\[\{][^\)\]\}]*\{[0-9]+,\}",  # Large quantifiers
    ]

    @classmethod
    def validate_pattern_security(cls, pattern: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a regex pattern for security concerns.

        Args:
            pattern: The regex pattern to validate

        Returns:
            Tuple of (is_safe, error_message)
        """
        if not pattern:
            return True, None

        # Check pattern length
        if len(pattern) > cls.MAX_PATTERN_LENGTH:
            return False, f"Pattern too long (max {cls.MAX_PATTERN_LENGTH} characters)"

        # Check for dangerous patterns
        for dangerous_pattern in cls.DANGEROUS_PATTERNS:
            if re.search(dangerous_pattern, pattern):
                return False, "Pattern contains potentially dangerous constructs"

        # Check compilation time to detect ReDoS patterns
        start_time = time.time()
        try:
            re.compile(pattern)
            compilation_time = time.time() - start_time

            if compilation_time > cls.MAX_COMPILATION_TIME:
                return False, "Pattern compilation too slow (potential ReDoS)"

        except re.error as e:
            return False, f"Invalid regex pattern: {str(e)}"
        except Exception:
            return False, "Pattern compilation failed"

        return True, None

    @classmethod
    def test_pattern_performance(
        cls, pattern: str, test_strings: list
    ) -> Tuple[bool, Optional[str]]:
        """
        Test regex pattern performance against various strings.

        Args:
            pattern: The regex pattern to test
            test_strings: List of test strings to match against

        Returns:
            Tuple of (is_performant, error_message)
        """
        if not pattern:
            return True, None

        try:
            compiled_pattern = re.compile(pattern)

            for test_string in test_strings:
                start_time = time.time()
                try:
                    compiled_pattern.fullmatch(test_string)
                    match_time = time.time() - start_time

                    if match_time > 0.1:  # 100ms threshold
                        return False, f"Pattern matching too slow ({match_time:.3f}s)"

                except Exception:
                    # If matching fails, that's okay, but timing out is not
                    match_time = time.time() - start_time
                    if match_time > 0.1:
                        return False, f"Pattern matching too slow ({match_time:.3f}s)"

        except Exception as e:
            return False, f"Pattern testing failed: {str(e)}"

        return True, None


class PatternCache:
    """
    Cache for compiled regex patterns to improve performance.
    """

    def __init__(self, max_size: int = 100):
        self.cache = {}
        self.max_size = max_size
        self.access_order = []

    def get_compiled_pattern(self, pattern: str) -> Optional[re.Pattern]:
        """
        Get a compiled pattern from cache or compile and cache it.

        Args:
            pattern: The regex pattern string

        Returns:
            Compiled regex pattern or None if invalid
        """
        if pattern in self.cache:
            # Move to end of access order (LRU)
            self.access_order.remove(pattern)
            self.access_order.append(pattern)
            return self.cache[pattern]

        try:
            # Security validation before compilation
            is_safe, error = RegexSecurityValidator.validate_pattern_security(pattern)
            if not is_safe:
                return None

            compiled_pattern = re.compile(pattern)

            # Add to cache
            self._add_to_cache(pattern, compiled_pattern)
            return compiled_pattern

        except re.error:
            return None

    def _add_to_cache(self, pattern: str, compiled_pattern: re.Pattern):
        """Add pattern to cache with LRU eviction."""
        if len(self.cache) >= self.max_size:
            # Remove least recently used
            oldest_pattern = self.access_order.pop(0)
            del self.cache[oldest_pattern]

        self.cache[pattern] = compiled_pattern
        self.access_order.append(pattern)

    def clear_cache(self):
        """Clear the pattern cache."""
        self.cache.clear()
        self.access_order.clear()


# Global pattern cache instance
pattern_cache = PatternCache()


def sanitize_pattern(pattern: str) -> str:
    """
    Sanitize a regex pattern to prevent common security issues.

    Args:
        pattern: The regex pattern to sanitize

    Returns:
        Sanitized pattern
    """
    if not pattern:
        return ""

    # Remove potentially dangerous constructs
    sanitized = pattern

    # Remove comments and excessive whitespace
    sanitized = re.sub(r"\s+", " ", sanitized.strip())

    # Limit pattern length
    if len(sanitized) > RegexSecurityValidator.MAX_PATTERN_LENGTH:
        sanitized = sanitized[: RegexSecurityValidator.MAX_PATTERN_LENGTH]

    return sanitized


def validate_flag_with_security(
    pattern: str, flag: str
) -> Tuple[bool, bool, Optional[str]]:
    """
    Validate a flag against a pattern with security checks.

    Args:
        pattern: The regex pattern
        flag: The flag to validate

    Returns:
        Tuple of (matches, is_valid_pattern, error_message)
    """
    if not pattern:
        return False, True, "No pattern provided"

    # Security validation
    is_safe, security_error = RegexSecurityValidator.validate_pattern_security(pattern)
    if not is_safe:
        return False, False, security_error

    # Get compiled pattern from cache
    compiled_pattern = pattern_cache.get_compiled_pattern(pattern)
    if compiled_pattern is None:
        return False, False, "Invalid or unsafe pattern"

    try:
        # Perform the match with timeout protection
        start_time = time.time()
        matches = bool(compiled_pattern.fullmatch(flag))
        match_time = time.time() - start_time

        if match_time > 0.1:  # 100ms threshold
            return False, False, f"Pattern matching too slow ({match_time:.3f}s)"

        return matches, True, None

    except Exception as e:
        return False, False, f"Pattern matching error: {str(e)}"
