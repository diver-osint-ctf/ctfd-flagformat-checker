import unittest
from unittest.mock import patch, MagicMock, Mock
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock Flask and CTFd modules before importing
sys.modules["flask"] = MagicMock()
sys.modules["CTFd"] = MagicMock()
sys.modules["CTFd.plugins"] = MagicMock()
sys.modules["CTFd.models"] = MagicMock()

flask_mock = Mock()
flask_mock.request = Mock()
flask_mock.jsonify = Mock()
sys.modules["flask"] = flask_mock

# Mock the relative imports before importing
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Create proper mock modules for the dependencies
models_mock = MagicMock()
models_mock.FlagFormatConfig = MagicMock()

enhanced_validation_mock = MagicMock()
enhanced_validation_mock.enhanced_check_flag_format = MagicMock()
enhanced_validation_mock.flag_validator = MagicMock()
enhanced_validation_mock.get_validation_stats = MagicMock()
enhanced_validation_mock.get_validator_health = MagicMock()
enhanced_validation_mock.clear_validation_cache = MagicMock()

admin_mock = MagicMock()
admin_mock.admin_blueprint = MagicMock()

# Add mocks to sys.modules with relative import names
sys.modules[".models"] = models_mock
sys.modules[".enhanced_validation"] = enhanced_validation_mock
sys.modules[".admin"] = admin_mock

sys.path.insert(0, parent_dir)
import __init__ as plugin_init  # noqa: E402


class TestPluginInit(unittest.TestCase):
    """Test cases for plugin initialization and flag format checking."""

    def setUp(self):
        """Set up test fixtures."""
        self.app_mock = MagicMock()
        self.app_mock.db = MagicMock()
        self.app_mock.logger = MagicMock()
        self.app_mock.blueprints = {}
        self.app_mock.url_map = MagicMock()
        self.app_mock.url_map.iter_rules.return_value = []

    def test_load_function(self):
        """Test the load function."""
        with patch("__init__.register_plugin_assets_directory") as mock_register:
            # Ensure plugin is not marked as loaded
            if hasattr(self.app_mock, "_flag_format_checker_loaded"):
                delattr(self.app_mock, "_flag_format_checker_loaded")

            plugin_init.load(self.app_mock)

            # Verify database creation is called with checkfirst=True
            self.app_mock.db.create_all.assert_called_once_with(checkfirst=True)

            # Verify assets directory registration
            mock_register.assert_called_once_with(
                self.app_mock, base_path="/plugins/ctfd-flagformat-checker/assets/"
            )

            # Verify before_request hook is registered
            self.app_mock.before_request.assert_called_once()

            # Verify plugin is marked as loaded
            self.assertTrue(hasattr(self.app_mock, "_flag_format_checker_loaded"))

    def test_load_function_duplicate_prevention(self):
        """Test that duplicate loading is prevented."""
        with patch("__init__.register_plugin_assets_directory") as mock_register:
            # Mark plugin as already loaded
            setattr(self.app_mock, "_flag_format_checker_loaded", True)

            plugin_init.load(self.app_mock)

            # Verify nothing is called when already loaded
            self.app_mock.db.create_all.assert_not_called()
            mock_register.assert_not_called()
            self.app_mock.before_request.assert_not_called()

    def test_init_db(self):
        """Test database initialization."""
        with patch("__init__.db") as mock_db:
            plugin_init.init_db()
            mock_db.create_all.assert_called_once_with(checkfirst=True)

    def test_init_tables_safely_success(self):
        """Test safe table initialization success case."""
        logger_mock = MagicMock()
        plugin_init.init_tables_safely(self.app_mock, logger_mock)

        self.app_mock.db.create_all.assert_called_once_with(checkfirst=True)
        logger_mock.debug.assert_called_once_with(
            "Database tables created/verified successfully"
        )

    def test_init_tables_safely_with_exception(self):
        """Test safe table initialization with exception handling."""
        logger_mock = MagicMock()
        self.app_mock.db.create_all.side_effect = Exception("Table already exists")

        with patch("__init__.FlagFormatConfig") as mock_config:
            mock_config.query.first.return_value = None

            plugin_init.init_tables_safely(self.app_mock, logger_mock)

            self.app_mock.db.create_all.assert_called_once_with(checkfirst=True)
            logger_mock.warning.assert_called_once_with(
                "Database table creation warning: Table already exists"
            )
            logger_mock.info.assert_called_once_with(
                "Flag format config table already exists and is accessible"
            )

    def test_get_plugin_config(self):
        """Test plugin configuration getter."""
        config = plugin_init.get_plugin_config()

        expected_config = {
            "name": "Flag Format Checker",
            "description": (
                "Validates flag submissions against specified format patterns"
            ),
            "version": "1.0.0",
        }

        self.assertEqual(config, expected_config)

    @patch("__init__.request")
    @patch("__init__.FlagFormatConfig")
    def test_check_flag_format_not_api_endpoint(self, mock_config, mock_request):
        """Test flag format check skips non-API endpoints."""
        mock_request.endpoint = "some_other_endpoint"
        mock_request.method = "POST"

        result = plugin_init.check_flag_format(self.app_mock)

        self.assertIsNone(result)
        mock_config.get_config.assert_not_called()

    @patch("__init__.request")
    @patch("__init__.FlagFormatConfig")
    def test_check_flag_format_disabled(self, mock_config, mock_request):
        """Test flag format check when disabled."""
        mock_request.endpoint = "api.challenges_attempt"
        mock_request.method = "POST"

        config_instance = MagicMock()
        config_instance.enabled = False
        mock_config.get_config.return_value = config_instance

        result = plugin_init.check_flag_format(self.app_mock)

        self.assertIsNone(result)

    @patch("__init__.request")
    @patch("__init__.FlagFormatConfig")
    @patch("__init__.jsonify")
    def test_check_flag_format_invalid_format(
        self, mock_jsonify, mock_config, mock_request
    ):
        """Test flag format check with invalid flag format."""
        mock_request.endpoint = "api.challenges_attempt"
        mock_request.method = "POST"
        mock_request.get_json.return_value = {"submission": "invalid_flag"}

        config_instance = MagicMock()
        config_instance.enabled = True
        config_instance.flag_format = r"flag\{.*\}"
        config_instance.error_message = "Invalid format"
        mock_config.get_config.return_value = config_instance

        mock_jsonify.return_value = {"error": "format_error"}

        plugin_init.check_flag_format(self.app_mock)

        # Should return error response
        mock_jsonify.assert_called_once_with(
            {
                "success": False,
                "data": {"status": "incorrect", "message": "Invalid format"},
            }
        )

    @patch("__init__.request")
    @patch("__init__.FlagFormatConfig")
    def test_check_flag_format_valid_format(self, mock_config, mock_request):
        """Test flag format check with valid flag format."""
        mock_request.endpoint = "api.challenges_attempt"
        mock_request.method = "POST"
        mock_request.get_json.return_value = {"submission": "flag{test123}"}

        config_instance = MagicMock()
        config_instance.enabled = True
        config_instance.flag_format = r"flag\{.*\}"
        config_instance.error_message = "Invalid format"
        mock_config.get_config.return_value = config_instance

        result = plugin_init.check_flag_format(self.app_mock)

        # Should return None (continue with normal processing)
        self.assertIsNone(result)

    @patch("__init__.request")
    @patch("__init__.FlagFormatConfig")
    def test_check_flag_format_invalid_regex(self, mock_config, mock_request):
        """Test flag format check with invalid regex pattern."""
        mock_request.endpoint = "api.challenges_attempt"
        mock_request.method = "POST"
        mock_request.get_json.return_value = {"submission": "flag{test123}"}

        config_instance = MagicMock()
        config_instance.enabled = True
        config_instance.flag_format = "[invalid_regex"  # Invalid regex
        config_instance.error_message = "Invalid format"
        mock_config.get_config.return_value = config_instance

        result = plugin_init.check_flag_format(self.app_mock)

        # Should log error and return None
        self.app_mock.logger.error.assert_called()
        self.assertIsNone(result)

    @patch("__init__.request")
    @patch("__init__.FlagFormatConfig")
    def test_check_flag_format_exception_handling(self, mock_config, mock_request):
        """Test flag format check exception handling."""
        mock_request.endpoint = "api.challenges_attempt"
        mock_request.method = "POST"

        # Simulate exception during config retrieval
        mock_config.get_config.side_effect = Exception("Database error")

        result = plugin_init.check_flag_format(self.app_mock)

        # Should log error and return None
        self.app_mock.logger.error.assert_called()
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
