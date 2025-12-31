from CTFd.models import db
from datetime import datetime, timezone


class FlagFormatConfig(db.Model):
    """
    Model for storing flag format configuration settings.
    """

    __tablename__ = "flag_format_config"
    __table_args__ = {"extend_existing": True}

    id = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    flag_format = db.Column(db.Text)
    error_message = db.Column(
        db.Text,
        default="Flag format does not match the required pattern.",
        nullable=False,
    )
    case_sensitive = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self):
        return f"<FlagFormatConfig id={self.id} enabled={self.enabled}>"

    @classmethod
    def get_config(cls):
        """
        Get the current flag format configuration.
        Returns the first configuration record or creates a default one.
        """
        config = cls.query.first()
        if not config:
            config = cls(
                enabled=False,
                flag_format=None,
                error_message="Flag format does not match the required pattern.",
                case_sensitive=False,
            )
            db.session.add(config)
            db.session.commit()
        return config

    def update_config(
        self, enabled=None, flag_format=None, error_message=None, case_sensitive=None
    ):
        """
        Update the configuration with new values.
        """
        if enabled is not None:
            self.enabled = enabled
        if flag_format is not None:
            self.flag_format = flag_format
        if error_message is not None:
            self.error_message = error_message
        if case_sensitive is not None:
            self.case_sensitive = case_sensitive

        self.updated_at = datetime.now(timezone.utc)
        db.session.commit()
