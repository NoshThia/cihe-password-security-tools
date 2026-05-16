from flask import Blueprint, render_template
from flask_login import login_required

from models import AuditLog, User
from routes.auth import role_required


analyst_bp = Blueprint("analyst", __name__, url_prefix="/analyst")


@analyst_bp.route("/dashboard")
@login_required
@role_required("admin", "analyst")
def dashboard():
    total_users = User.query.count()
    users_without_mfa = User.query.filter_by(mfa_enabled=False).count()
    users_with_mfa = User.query.filter_by(mfa_enabled=True).count()
    active_users = User.query.filter_by(is_active=True).count()

    failed_login_attempts = AuditLog.query.filter(
        AuditLog.action.in_(["FAILED_LOGIN", "FAILED_LOGIN_DISABLED_ACCOUNT", "MFA_VERIFY_FAILED"])
    ).count()

    compromised_checks = AuditLog.query.filter_by(action="PASSWORD_BLACKLIST_CHECK").count()
    compromised_found = AuditLog.query.filter_by(action="PASSWORD_BLACKLIST_MATCH").count()

    recent_failed_logins = AuditLog.query.filter(
        AuditLog.action.in_(["FAILED_LOGIN", "FAILED_LOGIN_DISABLED_ACCOUNT", "MFA_VERIFY_FAILED"])
    ).order_by(AuditLog.timestamp.desc()).limit(10).all()

    recent_compromised_checks = AuditLog.query.filter(
        AuditLog.action.in_(["PASSWORD_BLACKLIST_CHECK", "PASSWORD_BLACKLIST_MATCH"])
    ).order_by(AuditLog.timestamp.desc()).limit(10).all()

    return render_template(
        "analyst/dashboard.html",
        total_users=total_users,
        users_without_mfa=users_without_mfa,
        users_with_mfa=users_with_mfa,
        active_users=active_users,
        failed_login_attempts=failed_login_attempts,
        compromised_checks=compromised_checks,
        compromised_found=compromised_found,
        recent_failed_logins=recent_failed_logins,
        recent_compromised_checks=recent_compromised_checks
    )


@analyst_bp.route("/reports")
@login_required
@role_required("admin", "analyst")
def reports():
    users_without_mfa = User.query.filter_by(mfa_enabled=False).order_by(User.created_at.desc()).all()

    failed_login_logs = AuditLog.query.filter(
        AuditLog.action.in_(["FAILED_LOGIN", "FAILED_LOGIN_DISABLED_ACCOUNT", "MFA_VERIFY_FAILED"])
    ).order_by(AuditLog.timestamp.desc()).all()

    compromised_password_logs = AuditLog.query.filter(
        AuditLog.action.in_(["PASSWORD_BLACKLIST_CHECK", "PASSWORD_BLACKLIST_MATCH"])
    ).order_by(AuditLog.timestamp.desc()).all()

    mfa_enable_logs = AuditLog.query.filter_by(action="MFA_ENABLED").order_by(AuditLog.timestamp.desc()).all()

    return render_template(
        "analyst/reports.html",
        users_without_mfa=users_without_mfa,
        failed_login_logs=failed_login_logs,
        compromised_password_logs=compromised_password_logs,
        mfa_enable_logs=mfa_enable_logs
    )