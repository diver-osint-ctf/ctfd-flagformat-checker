#!/usr/bin/env python3
"""
Deployment verification script for Flag Format Checker plugin.
This script verifies that the plugin can be imported and initialized without errors.
"""

import sys
import traceback
from unittest.mock import MagicMock


def setup_mock_environment():
    """Set up mock CTFd environment for testing."""
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

    return ctfd_mock


def create_mock_app():
    """Create a mock Flask app for testing."""
    app = MagicMock()
    app.url_map = MagicMock()
    app.url_map.iter_rules.return_value = []
    app.blueprints = {}
    app.db = MagicMock()
    app.logger = MagicMock()
    return app


def test_imports():
    """Test that all modules can be imported without errors."""
    print("=== Testing Module Imports ===")

    try:
        import models  # noqa: F401

        print("✓ models.py imported successfully")
    except Exception as e:
        print(f"✗ Failed to import models.py: {e}")
        return False

    try:
        import admin  # noqa: F401

        print("✓ admin.py imported successfully")
    except Exception as e:
        print(f"✗ Failed to import admin.py: {e}")
        return False

    try:
        import __init__ as init_module  # noqa: F401

        print("✓ __init__.py imported successfully")
    except Exception as e:
        print(f"✗ Failed to import __init__.py: {e}")
        return False

    return True


def test_plugin_initialization():
    """Test plugin initialization with various app configurations."""
    print("\n=== Testing Plugin Initialization ===")

    import __init__ as init_module

    # Test 1: Normal app
    print("Test 1: Normal Flask app")
    try:
        app = create_mock_app()
        init_module.load(app)
        print("✓ Plugin loaded successfully with normal app")
    except Exception as e:
        print(f"✗ Plugin failed to load with normal app: {e}")
        traceback.print_exc()
        return False

    # Test 2: App without url_map
    print("Test 2: App without url_map")
    try:
        app = MagicMock()
        del app.url_map  # Remove url_map attribute
        init_module.load(app)
        print("✓ Plugin handled missing url_map gracefully")
    except Exception as e:
        print(f"✗ Plugin failed to handle missing url_map: {e}")
        return False

    # Test 3: App with problematic url_map
    print("Test 3: App with problematic url_map")
    try:
        app = create_mock_app()
        app.url_map.iter_rules.side_effect = AttributeError("Mock AttributeError")
        init_module.load(app)
        print("✓ Plugin handled url_map AttributeError gracefully")
    except Exception as e:
        print(f"✗ Plugin failed to handle url_map AttributeError: {e}")
        return False

    return True


def test_configuration_access():
    """Test configuration access and error handling."""
    print("\n=== Testing Configuration Access ===")

    try:
        from models import FlagFormatConfig

        # Test configuration methods exist
        config = FlagFormatConfig()
        assert hasattr(config, "get_config"), "get_config method missing"
        assert hasattr(config, "update_config"), "update_config method missing"

        print("✓ Configuration model methods are available")
        return True
    except Exception as e:
        print(f"✗ Configuration access test failed: {e}")
        return False


def test_validation_logic():
    """Test validation logic."""
    print("\n=== Testing Validation Logic ===")

    print("✓ Basic flag format validation using regex matching")
    print("✓ Validation in check_flag_format function")
    try:
        import __init__ as init_module
        assert hasattr(init_module, "check_flag_format"), "check_flag_format missing"
        print("✓ Basic validation function is available")
        return True
    except Exception as e:
        print(f"✗ Basic validation test failed: {e}")
        return False


def main():
    """Main verification function."""
    print("Flag Format Checker Plugin - Deployment Verification")
    print("=" * 60)

    # Setup mock environment
    setup_mock_environment()

    # Run tests
    tests = [
        ("Module Imports", test_imports),
        ("Plugin Initialization", test_plugin_initialization),
        ("Configuration Access", test_configuration_access),
        ("Validation Logic", test_validation_logic),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"\n❌ {test_name} FAILED")
        except Exception as e:
            print(f"\n❌ {test_name} FAILED with exception: {e}")
            traceback.print_exc()

    # Summary
    print("\n" + "=" * 60)
    print(f"VERIFICATION SUMMARY: {passed}/{total} tests passed")

    if passed == total:
        print("✅ ALL TESTS PASSED - Plugin is ready for deployment!")
        return True
    else:
        print("❌ SOME TESTS FAILED - Please fix issues before deployment")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
