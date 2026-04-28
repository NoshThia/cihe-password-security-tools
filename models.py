from datetime import datetime

from flask_login import UserMixin

from extensions import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    totp_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # --- AI Behaviour / Risk Detection fields ---
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)
    last_failed_login_at = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    login_risk_score = db.Column(db.Integer, default=0, nullable=False)
    login_risk_level = db.Column(db.String(20), default="Low", nullable=False)
    last_risk_reason = db.Column(db.Text, nullable=True)

    updated_policies = db.relationship(
        "PasswordPolicy",
        backref="updated_by_user",
        lazy=True,
        foreign_keys="PasswordPolicy.updated_by"
    )

    audit_logs = db.relationship(
        "AuditLog",
        backref="user",
        lazy=True,
        foreign_keys="AuditLog.user_id"
    )

    saved_passwords = db.relationship(
        "SavedPassword",
        backref="owner",
        lazy=True,
        foreign_keys="SavedPassword.user_id",
        cascade="all, delete-orphan"
    )

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User {self.username}>"


class PasswordPolicy(db.Model):
    __tablename__ = "password_policies"

    id = db.Column(db.Integer, primary_key=True)
    min_length = db.Column(db.Integer, nullable=False, default=8)
    require_upper = db.Column(db.Boolean, default=True, nullable=False)
    require_lower = db.Column(db.Boolean, default=True, nullable=False)
    require_digit = db.Column(db.Boolean, default=True, nullable=False)
    require_symbol = db.Column(db.Boolean, default=True, nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<PasswordPolicy {self.id}>"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<AuditLog {self.action}>"


class SavedPassword(db.Model):
    __tablename__ = "saved_passwords"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    label = db.Column(db.String(100), nullable=False)
    password_value = db.Column(db.Text, nullable=False)
    mode = db.Column(db.String(20), nullable=False, default="random")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<SavedPassword {self.label}>"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))