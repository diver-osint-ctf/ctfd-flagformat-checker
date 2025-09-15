import re
from flask import (
    Blueprint, render_template, request, jsonify, flash, redirect, url_for, session
)
from CTFd.utils.decorators import admins_only

# Try to import CSRF exemption tools
try:
    from flask_wtf.csrf import exempt as csrf_exempt
except ImportError:
    try:
        from CTFd.utils.decorators import csrf
        csrf_exempt = csrf.exempt
    except (ImportError, AttributeError):
        # Ultimate fallback - create a no-op decorator
        def csrf_exempt(f):
            return f
try:
    from .models import FlagFormatConfig
except ImportError:
    from models import FlagFormatConfig


def create_admin_blueprint():
    """
    Create and configure the admin blueprint for flag format settings.
    """
    print("=== CREATING ADMIN BLUEPRINT ===")
    admin_bp = Blueprint(
        "flag_format_admin",
        __name__,
        template_folder="templates",
    )

    print(f"Blueprint created: {admin_bp.name}")
    print(f"Blueprint template folder: {admin_bp.template_folder}")

    @admin_bp.route("/admin/flag-format", methods=["GET"])
    @admins_only
    def flag_format_settings():
        """
        Display the flag format configuration page.
        """
        config = FlagFormatConfig.get_config()
        return render_template(
            "flag_format_settings.html",
            config=config,
            title="Flag Format Settings",
            nonce=session.get("nonce"),
        )

    @admin_bp.route("/admin/flag-format", methods=["POST"])
    @admins_only
    def update_flag_format_settings():
        """
        Update the flag format configuration.
        """
        try:
            enabled = request.form.get("enabled") == "on"
            flag_format = request.form.get("flag_format", "").strip()
            error_message = request.form.get("error_message", "").strip()

            # Validate flag format if provided
            if enabled and flag_format:
                try:
                    # Import security validator
                    try:
                        from .security import RegexSecurityValidator
                    except ImportError:
                        from security import RegexSecurityValidator

                    # Basic regex compilation check
                    re.compile(flag_format)

                    # Security validation
                    validator = RegexSecurityValidator()
                    is_safe, security_error = validator.validate_pattern_security(flag_format)
                    if not is_safe:
                        flash(f"Unsafe regular expression pattern: {security_error}", "error")
                        return redirect(
                            url_for("flag_format_admin.flag_format_settings")
                        )

                    # Additional flag format validation (common mistakes)
                    validation_warnings = []

                    # Check for unescaped braces (common mistake)
                    if '{' in flag_format and '\\{' not in flag_format:
                        validation_warnings.append(
                            "Pattern contains '{' - did you mean '\\{' for literal braces?"
                        )
                    if '}' in flag_format and '\\}' not in flag_format:
                        validation_warnings.append(
                            "Pattern contains '}' - did you mean '\\}' for literal braces?"
                        )

                    # Check for common flag format patterns
                    if flag_format.startswith('flag{') and not flag_format.startswith('flag\\{'):
                        msg = "Pattern starts with 'flag{' - use 'flag\\{' for literal braces"
                        validation_warnings.append(msg)

                    # Strict flag validation - treat validation issues as errors
                    if validation_warnings:
                        # Treat validation issues as errors and block saving
                        for warning in validation_warnings:
                            flash(f"Error: {warning}", "error")
                        return redirect(
                            url_for("flag_format_admin.flag_format_settings")
                        )

                except re.error as e:
                    flash(f"Invalid regular expression: {str(e)}", "error")
                    return redirect(
                        url_for("flag_format_admin.flag_format_settings")
                    )

            # Set default error message if empty
            if not error_message:
                error_message = (
                    "Flag format does not match the required pattern."
                )

            # Update configuration
            config = FlagFormatConfig.get_config()
            config.update_config(
                enabled=enabled, flag_format=flag_format, error_message=error_message
            )

            flash("Flag format settings updated successfully!", "success")

        except Exception as e:
            flash(f"Error updating settings: {str(e)}", "error")

        return redirect(url_for("flag_format_admin.flag_format_settings"))

    @admin_bp.route("/admin/flag-format/api/config", methods=["GET"])
    @admins_only
    def get_config():
        """
        API endpoint to get current configuration.
        """
        try:
            config = FlagFormatConfig.get_config()
            return jsonify(
                {
                    "enabled": config.enabled,
                    "flag_format": config.flag_format or "",
                    "error_message": config.error_message,
                    "created_at": (
                        config.created_at.isoformat() if config.created_at else None
                    ),
                    "updated_at": (
                        config.updated_at.isoformat() if config.updated_at else None
                    ),
                }
            )
        except Exception as e:
            return jsonify({"error": f"Failed to get configuration: {str(e)}"}), 500

    print("=== BLUEPRINT ROUTES REGISTERED ===")
    # Blueprint doesn't have url_map, routes will be visible after registration
    print(f"Blueprint {admin_bp.name} created with deferred route registration")

    return admin_bp


# Initialize the blueprint
print("=== INITIALIZING ADMIN BLUEPRINT ===")
admin_blueprint = create_admin_blueprint()
print(f"Admin blueprint initialized: {admin_blueprint.name}")
