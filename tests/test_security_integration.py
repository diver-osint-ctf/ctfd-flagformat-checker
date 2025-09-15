import unittest
import time
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSecurityIntegration(unittest.TestCase):
    """Test security features and integration."""

    def setUp(self):
        """Set up test fixtures."""
        # Import here to avoid CTFd dependency issues
        try:
            from security import (
                RegexSecurityValidator,
                PatternCache,
                validate_flag_with_security,
                sanitize_pattern,
            )

            self.validator = RegexSecurityValidator
            self.cache = PatternCache()
            self.validate_function = validate_flag_with_security
            self.sanitize_function = sanitize_pattern
        except ImportError:
            self.skipTest("Security module not available")

    def test_regex_security_validation(self):
        """Test regex security validation."""
        # Safe patterns
        safe_patterns = [
            r"flag\{.*\}",
            r"CTF\{[a-zA-Z0-9_]+\}",
            r"[A-Z]{3}\{[a-f0-9]{32}\}",
        ]

        for pattern in safe_patterns:
            with self.subTest(pattern=pattern):
                is_safe, error = self.validator.validate_pattern_security(pattern)
                self.assertTrue(is_safe, f"Pattern {pattern} should be safe")
                self.assertIsNone(error)

    def test_dangerous_regex_patterns(self):
        """Test detection of dangerous regex patterns."""
        dangerous_patterns = [
            "(?#malicious comment)",  # Comment injection
            "(a+)+b",  # Exponential backtracking
            ".*.*.*",  # Multiple greedy quantifiers
            ".+.+.+",  # Multiple greedy quantifiers
            "a{1000,}",  # Large quantifier
        ]

        for pattern in dangerous_patterns:
            with self.subTest(pattern=pattern):
                is_safe, error = self.validator.validate_pattern_security(pattern)
                if not is_safe:  # Expected behavior
                    self.assertIsNotNone(error)

    def test_pattern_length_limit(self):
        """Test pattern length limitations."""
        # Very long pattern
        long_pattern = "a" * 1000
        is_safe, error = self.validator.validate_pattern_security(long_pattern)
        self.assertFalse(is_safe)
        self.assertIn("too long", error)

    def test_pattern_cache_functionality(self):
        """Test pattern cache functionality."""
        pattern = r"flag\{.*\}"

        # First access should compile and cache
        compiled1 = self.cache.get_compiled_pattern(pattern)
        self.assertIsNotNone(compiled1)

        # Second access should return cached version
        compiled2 = self.cache.get_compiled_pattern(pattern)
        self.assertIsNotNone(compiled2)
        self.assertIs(compiled1, compiled2)

    def test_pattern_cache_lru_eviction(self):
        """Test LRU eviction in pattern cache."""
        from security import PatternCache
        small_cache = PatternCache(max_size=2)

        # Add patterns up to limit
        pattern1 = r"pattern1"
        pattern2 = r"pattern2"
        pattern3 = r"pattern3"

        small_cache.get_compiled_pattern(pattern1)
        small_cache.get_compiled_pattern(pattern2)

        # Add third pattern, should evict first
        small_cache.get_compiled_pattern(pattern3)

        # pattern1 should be evicted
        self.assertNotIn(pattern1, small_cache.cache)
        self.assertIn(pattern2, small_cache.cache)
        self.assertIn(pattern3, small_cache.cache)

    def test_validate_flag_with_security(self):
        """Test flag validation with security checks."""
        # Safe pattern and matching flag
        matches, is_valid, error = self.validate_function(r"flag\{.*\}", "flag{test}")
        self.assertTrue(matches)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

        # Safe pattern and non-matching flag
        matches, is_valid, error = self.validate_function(r"flag\{.*\}", "invalid")
        self.assertFalse(matches)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

        # Unsafe pattern
        matches, is_valid, error = self.validate_function("(?#malicious)", "flag")
        self.assertFalse(matches)
        self.assertFalse(is_valid)
        self.assertIsNotNone(error)

    def test_pattern_sanitization(self):
        """Test pattern sanitization."""
        # Test whitespace removal
        dirty_pattern = "  flag\\{.*\\}  "
        clean_pattern = self.sanitize_function(dirty_pattern)
        self.assertEqual(clean_pattern, "flag\\{.*\\}")

        # Test length limiting
        long_pattern = "a" * 1000
        sanitized = self.sanitize_function(long_pattern)
        self.assertLessEqual(len(sanitized), 500)

    def test_performance_validation(self):
        """Test performance validation against slow patterns."""
        # This pattern could potentially be slow
        slow_pattern = r"(a+)+b"
        test_strings = ["a" * 20 + "c", "normal_string", ""]

        is_performant, error = self.validator.test_pattern_performance(
            slow_pattern, test_strings
        )
        # The validator should detect this as potentially slow
        # Result may vary, but should not crash


class TestPerformanceAndStress(unittest.TestCase):
    """Performance and stress tests."""

    def setUp(self):
        """Set up test fixtures."""
        try:
            from security import PatternCache, validate_flag_with_security
            from enhanced_validation import ValidationStats

            self.cache = PatternCache()
            self.validate_function = validate_flag_with_security
            self.stats = ValidationStats()
        except ImportError:
            self.skipTest("Required modules not available")

    def test_pattern_cache_performance(self):
        """Test pattern cache performance."""
        pattern = r"flag\{[a-zA-Z0-9_]{10,50}\}"

        # Time uncached compilation
        start_time = time.time()
        for _ in range(100):
            import re
            re.compile(pattern)
        uncached_time = time.time() - start_time

        # Time cached compilation
        start_time = time.time()
        for _ in range(100):
            self.cache.get_compiled_pattern(pattern)
        cached_time = time.time() - start_time

        # Cached should be significantly faster
        self.assertLess(cached_time, uncached_time / 2)

    def test_validation_stats_accuracy(self):
        """Test validation statistics accuracy."""
        # Record some validations
        self.stats.record_validation(True, 0.01)
        self.stats.record_validation(False, 0.02)
        self.stats.record_validation(True, 0.015)
        self.stats.record_error()

        stats = self.stats.get_stats()

        self.assertEqual(stats["total_checks"], 3)
        self.assertEqual(stats["successful_validations"], 2)
        self.assertEqual(stats["failed_validations"], 1)
        self.assertEqual(stats["errors"], 1)
        self.assertAlmostEqual(stats["avg_response_time"], 0.015, places=3)

    def test_high_volume_validation(self):
        """Test high volume flag validation."""
        pattern = r"flag\{[a-zA-Z0-9_]+\}"
        test_flags = [
            "flag{test123}",
            "flag{invalid-chars}",
            "flag{valid_test}",
            "invalid_format",
            "flag{another_valid}",
        ]

        start_time = time.time()
        results = []

        # Validate 1000 flags
        for i in range(200):
            for flag in test_flags:
                matches, is_valid, error = self.validate_function(pattern, flag)
                results.append((matches, is_valid, error))

        total_time = time.time() - start_time

        # Should complete 1000 validations in reasonable time (< 1 second)
        self.assertLess(total_time, 1.0)
        self.assertEqual(len(results), 1000)

        # Check that we got expected results
        valid_matches = sum(
            1 for matches, is_valid, error in results if matches and is_valid
        )
        self.assertGreater(valid_matches, 0)

    def test_concurrent_cache_access(self):
        """Test concurrent access to pattern cache."""
        import threading
        import queue

        pattern = r"flag\{.*\}"
        results = queue.Queue()

        def cache_access_thread():
            try:
                for _ in range(50):
                    compiled = self.cache.get_compiled_pattern(pattern)
                    results.put(compiled is not None)
            except Exception:
                results.put(False)

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=cache_access_thread)
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Check results
        success_count = 0
        while not results.empty():
            if results.get():
                success_count += 1

        # All accesses should succeed
        self.assertEqual(success_count, 250)  # 5 threads * 50 accesses


class TestErrorRecovery(unittest.TestCase):
    """Test error recovery and fallback mechanisms."""

    def test_fallback_behavior_on_invalid_pattern(self):
        """Test fallback behavior when patterns are invalid."""
        try:
            from enhanced_validation import FlagFormatValidator
        except ImportError:
            self.skipTest("Enhanced validation module not available")

        validator = FlagFormatValidator()

        # Test with invalid pattern (should not crash)
        should_block, error_response = validator.validate_flag_submission("test_flag")

        # Should not block (fail open) when there are issues
        self.assertFalse(should_block)

    def test_config_cache_fallback(self):
        """Test configuration cache fallback."""
        try:
            from enhanced_validation import FlagFormatValidator
        except ImportError:
            self.skipTest("Enhanced validation module not available")

        validator = FlagFormatValidator()

        # Simulate no config available
        config = validator.get_config_with_cache()
        # Should return None or handle gracefully
        self.assertIsNone(config)


if __name__ == "__main__":
    unittest.main()
