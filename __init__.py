import re
import logging
from flask import request, jsonify
from CTFd.plugins import register_plugin_assets_directory
from CTFd.models import db

try:
    from sqlalchemy import inspect, text
except ImportError:
    # For testing environments where sqlalchemy might not be available
    inspect = None
    text = None

try:
    # Try relative imports first (for CTFd plugin context)
    from .models import FlagFormatConfig
    from .admin import admin_blueprint
except ImportError:
    # Fall back to absolute imports for testing
    from models import FlagFormatConfig
    from admin import admin_blueprint


def init_tables_safely(app, logger):
    """
    Safely initialize database tables with existence checking.
    """
    try:
        # Create tables if they don't exist (checkfirst is default behavior)
        app.db.create_all()
        logger.debug("Database tables created/verified successfully")
    except Exception as e:
        # Log warning but don't fail - tables might already exist
        logger.warning(f"Database table creation warning: {str(e)}")
        # Don't try to query the table here - it may not have all columns yet


def migrate_database(app, logger):
    """
    Perform database migrations for schema updates.
    """
    # Skip migration if sqlalchemy tools are not available (testing environment)
    if inspect is None or text is None:
        logger.debug("SQLAlchemy tools not available, skipping migration")
        return

    try:
        # Check if table exists first
        inspector = inspect(app.db.engine)

        # Check if table exists
        if "flag_format_config" not in inspector.get_table_names():
            logger.debug(
                "flag_format_config table does not exist yet, skipping migration"
            )
            return

        # Get existing columns
        columns = [col["name"] for col in inspector.get_columns("flag_format_config")]

        if "case_sensitive" not in columns:
            logger.info("Migrating database: Adding case_sensitive column")

            # Add case_sensitive column with default value
            dialect_name = app.db.engine.dialect.name

            if dialect_name == "mysql":
                sql = "ALTER TABLE flag_format_config ADD COLUMN case_sensitive TINYINT(1) NOT NULL DEFAULT 0"
            elif dialect_name == "postgresql":
                sql = "ALTER TABLE flag_format_config ADD COLUMN case_sensitive BOOLEAN NOT NULL DEFAULT FALSE"
            else:  # sqlite
                sql = "ALTER TABLE flag_format_config ADD COLUMN case_sensitive BOOLEAN NOT NULL DEFAULT 0"

            # Execute the migration
            with app.db.engine.begin() as conn:
                conn.execute(text(sql))

            logger.info("Successfully added case_sensitive column")
        else:
            logger.debug("case_sensitive column already exists")

    except Exception as e:
        logger.error(f"Database migration error: {str(e)}")
        import traceback

        logger.error(traceback.format_exc())
        # Continue anyway - the table might be created later


def load(app):
    """
    Main function to load the Flag Format Checker plugin.
    """
    # Configure logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # Validate app object
    if not hasattr(app, "url_map"):
        logger.error("Invalid Flask app object: missing url_map attribute")
        return

    if not hasattr(app, "blueprints"):
        logger.error("Invalid Flask app object: missing blueprints attribute")
        return

    # Check if plugin is already loaded to prevent duplicate registration
    plugin_loaded_key = "_flag_format_checker_loaded"
    if hasattr(app, plugin_loaded_key) and getattr(app, plugin_loaded_key):
        logger.info(
            "Flag Format Checker plugin already loaded, skipping duplicate registration"
        )
        return

    # Create database tables only if they don't exist
    init_tables_safely(app, logger)

    # Run database migrations for schema updates
    migrate_database(app, logger)

    # Register plugin assets directory
    register_plugin_assets_directory(
        app, base_path="/plugins/ctfd-flagformat-checker/assets/"
    )

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
                if "/admin/flag-format" in str(rule.rule):
                    methods = ",".join(rule.methods)
                    logger.info(
                        f"Flag Format Route: {rule.rule} -> {rule.endpoint} [{methods}]"
                    )
        except (AttributeError, RuntimeError) as e:
            logger.warning(f"Could not access URL map for route logging: {str(e)}")
    else:
        logger.warning(f"Blueprint {blueprint_name} already registered")

    # Register flag format validation hook
    @app.before_request
    def flag_format_hook():
        result = check_flag_format(app)
        if result:
            return result

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
                # Use case-insensitive matching if case_sensitive is False
                regex_flags = 0 if config.case_sensitive else re.IGNORECASE
                pattern = re.compile(config.flag_format, regex_flags)
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
        db.create_all()
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
