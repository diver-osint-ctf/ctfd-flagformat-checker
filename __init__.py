import re
import logging
from flask import request, jsonify
from CTFd.plugins import register_plugin_assets_directory
from CTFd.models import db
try:
    # Try relative imports first (for CTFd plugin context)
    from .models import FlagFormatConfig
    from .admin import admin_blueprint
    from .enhanced_validation import (
        enhanced_check_flag_format,
        flag_validator,
        get_validation_stats,
        get_validator_health,
        clear_validation_cache,
    )
except ImportError:
    # Fall back to absolute imports for testing
    from models import FlagFormatConfig
    from admin import admin_blueprint
    from enhanced_validation import (
        enhanced_check_flag_format,
        flag_validator,
        get_validation_stats,
        get_validator_health,
        clear_validation_cache,
    )


def init_tables_safely(app, logger):
    """
    Safely initialize database tables with existence checking.
    """
    try:
        # Use checkfirst=True to only create tables if they don't exist
        app.db.create_all(checkfirst=True)
        logger.debug("Database tables created/verified successfully")
    except Exception as e:
        # Log warning but don't fail - tables might already exist
        logger.warning(f"Database table creation warning: {str(e)}")

        # Try to verify if our specific table exists
        try:
            # Check if flag_format_config table exists by querying it
            FlagFormatConfig.query.first()
            logger.info("Flag format config table already exists and is accessible")
        except Exception as check_e:
            logger.error(f"Cannot access flag_format_config table: {str(check_e)}")
            # Continue anyway - the table might be created later


def load(app):
    """
    Main function to load the Flag Format Checker plugin.
    """
    # Configure logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # Validate app object
    if not hasattr(app, 'url_map'):
        logger.error("Invalid Flask app object: missing url_map attribute")
        return

    if not hasattr(app, 'blueprints'):
        logger.error("Invalid Flask app object: missing blueprints attribute")
        return

    # Check if plugin is already loaded to prevent duplicate registration
    plugin_loaded_key = '_flag_format_checker_loaded'
    if hasattr(app, plugin_loaded_key) and getattr(app, plugin_loaded_key):
        logger.info(
            "Flag Format Checker plugin already loaded, skipping duplicate registration"
        )
        return

    # Create database tables only if they don't exist
    init_tables_safely(app, logger)

    # Register plugin assets directory
    register_plugin_assets_directory(
        app, base_path="/plugins/ctfd-flagformat-checker/assets/"
    )

    # Initialize the enhanced validator with app context
    flag_validator.app = app

    # Register admin blueprint (check if already registered)
    blueprint_name = admin_blueprint.name
    logger.info(f"Registering blueprint: {blueprint_name}")
    if blueprint_name not in app.blueprints:
        app.register_blueprint(admin_blueprint)
        logger.info(f"Blueprint {blueprint_name} registered successfully")

        # Log all registered routes (with error handling)
        logger.info("=== ALL REGISTERED ROUTES ===")
        try:
            for rule in app.url_map.iter_rules():
                if '/admin/flag-format' in str(rule.rule):
                    methods = ','.join(rule.methods)
                    logger.info(f"Flag Format Route: {rule.rule} -> {rule.endpoint} [{methods}]")
        except (AttributeError, RuntimeError) as e:
            logger.warning(f"Could not access URL map for route logging: {str(e)}")
    else:
        logger.warning(f"Blueprint {blueprint_name} already registered")

    # Direct API routes removed - Test Flag Format now runs client-side only

    # Register enhanced hooks
    @app.before_request
    def enhanced_flag_format_hook():
        result = enhanced_check_flag_format(app)
        if result:
            return result

    # Register monitoring endpoints for admin use only if not already registered
    stats_endpoint = "/admin/flag-format/stats"
    cache_endpoint = "/admin/flag-format/clear-cache"

    # Check if routes are already registered (with error handling)
    existing_rules = []
    try:
        existing_rules = [str(rule.rule) for rule in app.url_map.iter_rules()]
    except (AttributeError, RuntimeError) as e:
        logger.warning(f"Could not access URL map for route checking: {str(e)}")
        # Fall back to always registering routes (they'll be ignored if already exist)
        existing_rules = []

    if stats_endpoint not in existing_rules:
        @app.route(stats_endpoint, methods=["GET"])
        def flag_format_stats():
            """Get validation statistics."""
            try:
                stats = get_validation_stats()
                health = get_validator_health()
                return jsonify({"stats": stats, "health": health})
            except Exception as e:
                logger.error(f"Error getting stats: {str(e)}")
                return jsonify({"error": "Failed to get statistics"}), 500

    if cache_endpoint not in existing_rules:
        @app.route(cache_endpoint, methods=["POST"])
        def clear_flag_format_cache():
            """Clear validation cache."""
            try:
                clear_validation_cache()
                return jsonify({"message": "Cache cleared successfully"})
            except Exception as e:
                logger.error(f"Error clearing cache: {str(e)}")
                return jsonify({"error": "Failed to clear cache"}), 500

    # Mark plugin as loaded to prevent duplicate registration
    setattr(app, plugin_loaded_key, True)
    logger.info("Flag Format Checker plugin loaded successfully")


def check_flag_format(app):
    """
    Hook function to check flag format before processing submission.
    Intercepts flag submission requests and validates format.
    """
    # Only check flag submission endpoints
    if (
        request.endpoint
        and "api" in request.endpoint
        and "attempt" in request.endpoint
        and request.method == "POST"
    ):

        try:
            # Get flag format configuration
            config = FlagFormatConfig.get_config()

            # Skip validation if disabled or no format specified
            if not config.enabled or not config.flag_format:
                return

            # Get submitted flag from request
            data = request.get_json()
            if not data or "submission" not in data:
                return

            submitted_flag = data["submission"]

            # Validate flag format using regex
            try:
                pattern = re.compile(config.flag_format)
                if not pattern.fullmatch(submitted_flag):
                    # Return error response if format doesn't match
                    return (
                        jsonify(
                            {
                                "success": False,
                                "data": {
                                    "status": "incorrect",
                                    "message": config.error_message,
                                },
                            }
                        ),
                        400,
                    )
            except re.error:
                # Invalid regex pattern - log error and continue
                app.logger.error(
                    f"Invalid regex pattern in flag format: {config.flag_format}"
                )
                return

        except Exception as e:
            # Log error and continue with normal processing
            app.logger.error(f"Error in flag format checker: {str(e)}")
            return


def init_db():
    """
    Initialize database tables for the plugin.
    """
    try:
        db.create_all(checkfirst=True)
        logger = logging.getLogger(__name__)
        logger.debug("Database tables initialized successfully")
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.warning(f"Database table initialization warning: {str(e)}")
        # Continue even if table creation fails


def get_plugin_config():
    """
    Get plugin configuration for admin interface.
    """
    return {
        "name": "Flag Format Checker",
        "description": "Validates flag submissions against specified format patterns",
        "version": "1.0.0",
    }
