"""
Pytest configuration and fixtures for CTFd Flag Format Checker tests.
"""

import sys
from unittest.mock import Mock


def pytest_configure(config):
    """Configure pytest with CTFd mocks."""
    # Mock CTFd modules before any imports
    ctfd_mock = Mock()
    ctfd_models_mock = Mock()
    ctfd_plugins_mock = Mock()
    ctfd_utils_mock = Mock()
    ctfd_decorators_mock = Mock()
    db_mock = Mock()

    # Complete CTFd mock structure
    ctfd_models_mock.db = db_mock
    ctfd_mock.models = ctfd_models_mock
    ctfd_mock.plugins = ctfd_plugins_mock
    ctfd_mock.utils = ctfd_utils_mock
    ctfd_utils_mock.decorators = ctfd_decorators_mock

    # Mock specific functions
    ctfd_plugins_mock.register_plugin_assets_directory = Mock()
    # Decorator that returns function unchanged
    ctfd_decorators_mock.admins_only = lambda f: f

    # Mock the specific modules that will be imported
    sys.modules["CTFd"] = ctfd_mock
    sys.modules["CTFd.models"] = ctfd_models_mock
    sys.modules["CTFd.plugins"] = ctfd_plugins_mock
    sys.modules["CTFd.utils"] = ctfd_utils_mock
    sys.modules["CTFd.utils.decorators"] = ctfd_decorators_mock
