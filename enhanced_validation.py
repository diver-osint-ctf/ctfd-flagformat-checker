"""
Enhanced flag validation with improved error handling and performance.
"""

import logging
import time
from typing import Optional, Tuple, Dict, Any, TYPE_CHECKING
from flask import request, jsonify
try:
    from .security import validate_flag_with_security, pattern_cache
except ImportError:
    from security import validate_flag_with_security, pattern_cache

if TYPE_CHECKING:
    try:
        from .models import FlagFormatConfig
    except ImportError:
        from models import FlagFormatConfig


# Configure logging
logger = logging.getLogger(__name__)


class ValidationStats:
    """Track validation statistics for monitoring."""

    def __init__(self):
        self.total_checks = 0
        self.successful_validations = 0
        self.failed_validations = 0
        self.errors = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.avg_response_time = 0.0
        self._response_times = []

    def record_validation(self, success: bool, response_time: float):
        """Record a validation attempt."""
        self.total_checks += 1
        if success:
            self.successful_validations += 1
        else:
            self.failed_validations += 1

        self._response_times.append(response_time)
        if len(self._response_times) > 1000:  # Keep last 1000 measurements
            self._response_times.pop(0)

        self.avg_response_time = sum(self._response_times) / len(self._response_times)

    def record_error(self):
        """Record an error occurrence."""
        self.errors += 1

    def record_cache_hit(self):
        """Record a cache hit."""
        self.cache_hits += 1

    def record_cache_miss(self):
        """Record a cache miss."""
        self.cache_misses += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        return {
            "total_checks": self.total_checks,
            "successful_validations": self.successful_validations,
            "failed_validations": self.failed_validations,
            "errors": self.errors,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": (
                self.cache_hits / (self.cache_hits + self.cache_misses)
                if (self.cache_hits + self.cache_misses) > 0
                else 0
            ),
            "avg_response_time": self.avg_response_time,
            "error_rate": (
                self.errors / self.total_checks if self.total_checks > 0 else 0
            ),
        }


# Global stats instance
validation_stats = ValidationStats()


class FlagFormatValidator:
    """Enhanced flag format validator with robust error handling."""

    def __init__(self, app=None):
        self.app = app
        self._config_cache = None
        self._config_cache_time = 0
        self._cache_timeout = 60  # Cache config for 60 seconds
        self._fallback_mode = False

    def get_config_with_cache(self) -> Optional["FlagFormatConfig"]:
        """
        Get configuration with caching and fallback handling.
        """
        current_time = time.time()

        # Check if cached config is still valid
        if (
            self._config_cache is not None
            and current_time - self._config_cache_time < self._cache_timeout
        ):
            return self._config_cache

        try:
            # Try to get fresh config from database
            try:
                from .models import FlagFormatConfig
            except ImportError:
                from models import FlagFormatConfig
            config = FlagFormatConfig.get_config()
            self._config_cache = config
            self._config_cache_time = current_time
            self._fallback_mode = False
            return config

        except Exception as e:
            logger.error(f"Database error when fetching config: {str(e)}")
            validation_stats.record_error()

            # Fall back to cached config if available
            if self._config_cache is not None:
                logger.warning("Using cached config due to database error")
                self._fallback_mode = True
                return self._config_cache

            # Ultimate fallback: disabled validation
            logger.critical("No config available, disabling validation")
            self._fallback_mode = True
            return None

    def validate_flag_submission(
        self, submitted_flag: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate a flag submission with comprehensive error handling.

        Args:
            submitted_flag: The flag to validate

        Returns:
            Tuple of (should_block, error_response)
        """
        start_time = time.time()

        try:
            # Get configuration
            config = self.get_config_with_cache()

            # If no config or disabled, allow through
            if config is None or not config.enabled or not config.flag_format:
                validation_stats.record_validation(True, time.time() - start_time)
                return False, None

            # Validate flag with security checks
            matches, is_valid_pattern, error_message = validate_flag_with_security(
                config.flag_format, submitted_flag
            )

            response_time = time.time() - start_time

            # If pattern is invalid, log error and allow through (fail open)
            if not is_valid_pattern:
                logger.error(
                    f"Invalid or unsafe pattern in config: {config.flag_format}, "
                    f"Error: {error_message}"
                )
                validation_stats.record_error()
                validation_stats.record_validation(True, response_time)
                return False, None

            # If flag matches pattern, allow through
            if matches:
                validation_stats.record_validation(True, response_time)
                return False, None

            # Flag doesn't match pattern, block submission
            validation_stats.record_validation(False, response_time)
            error_response = {
                "success": False,
                "data": {
                    "status": "incorrect",
                    "message": config.error_message,
                },
            }

            # Add debug info in fallback mode
            if self._fallback_mode:
                error_response["data"][
                    "warning"
                ] = "Validation running in fallback mode"

            return True, error_response

        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Unexpected error in flag validation: {str(e)}")
            validation_stats.record_error()
            validation_stats.record_validation(True, response_time)

            # Fail open - allow submission to proceed
            return False, None

    def clear_cache(self):
        """Clear configuration cache."""
        self._config_cache = None
        self._config_cache_time = 0
        pattern_cache.clear_cache()

    def get_health_status(self) -> Dict[str, Any]:
        """Get validator health status."""
        return {
            "fallback_mode": self._fallback_mode,
            "config_cached": self._config_cache is not None,
            "config_cache_age": time.time() - self._config_cache_time,
            "stats": validation_stats.get_stats(),
        }


# Global validator instance
flag_validator = FlagFormatValidator()


def enhanced_check_flag_format(app) -> Optional[Tuple[Any, int]]:
    """
    Enhanced flag format checking with improved error handling.

    Args:
        app: Flask app instance

    Returns:
        Error response tuple if validation fails, None otherwise
    """
    # Only check flag submission endpoints
    if not (
        request.endpoint
        and "api" in request.endpoint
        and "attempt" in request.endpoint
        and request.method == "POST"
    ):
        return None

    try:
        # Get submitted flag from request
        data = request.get_json()
        if not data or "submission" not in data:
            return None

        submitted_flag = data["submission"]

        # Validate flag
        should_block, error_response = flag_validator.validate_flag_submission(
            submitted_flag
        )

        if should_block and error_response:
            return jsonify(error_response), 400

        return None

    except Exception as e:
        logger.error(f"Critical error in flag format checker: {str(e)}")
        validation_stats.record_error()
        # Fail open - allow submission to proceed
        return None


def get_validation_stats() -> Dict[str, Any]:
    """Get validation statistics for monitoring."""
    return validation_stats.get_stats()


def get_validator_health() -> Dict[str, Any]:
    """Get validator health status."""
    return flag_validator.get_health_status()


def clear_validation_cache():
    """Clear all validation caches."""
    flag_validator.clear_cache()
