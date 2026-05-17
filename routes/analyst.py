from flask import Blueprint, render_template
from flask_login import login_required
from zxcvbn import zxcvbn

from models import AuditLog, User, SavedPassword
from routes.auth import role_required
from services.vault_crypto import decrypt_password
from services.report_ai import get_security_report_ai_advice


analyst_bp = Blueprint("analyst", __name__, url_prefix="/analyst")


def calculate_password_report():
    saved_items = SavedPassword.query.order_by(SavedPassword.created_at.desc()).all()
    users = User.query.all()
    user_map = {user.id: user for user in users}

    decrypted_records = []
    plain_passwords = []

    for item in saved_items:
        plain_password = decrypt_password(item.password_value)
        plain_passwords.append(plain_password)

        decrypted_records.append({
            "id": item.id,
            "label": item.label,
            "mode": item.mode,
            "created_at": item.created_at,
            "user": user_map.get(item.user_id),
            "password_value": plain_password
        })

    reuse_map = {}
    for pwd in plain_passwords:
        reuse_map[pwd] = reuse_map.get(pwd, 0) + 1

    weak_count = 0
    reused_count = 0
    secure_count = 0
    password_rows = []

    for record in decrypted_records:
        pwd = record["password_value"]
        score = None
        strength = "Unknown"

        if pwd and pwd != "[DECRYPTION_FAILED]":
            try:
                result = zxcvbn(pwd)
                score = result.get("score", 0)

                if score <= 1:
                    strength = "Weak"
                elif score == 2:
                    strength = "Moderate"
                elif score == 3:
                    strength = "Strong"
                else:
                    strength = "Very Strong"
            except Exception:
                score = None
                strength = "Unknown"

        reuse_count = reuse_map.get(pwd, 1)
        is_reused = reuse_count > 1 and pwd != "[DECRYPTION_FAILED]"
        is_weak = score is not None and score <= 1

        if is_reused:
            reused_count += 1

        if is_weak or is_reused:
            weak_count += 1
            risk_status = "Review"
        else:
            secure_count += 1
            risk_status = "Secure"

        password_rows.append({
            "username": record["user"].username if record["user"] else "Unknown",
            "email": record["user"].email if record["user"] else "Unknown",
            "label": record["label"],
            "mode": record["mode"],
            "strength": strength,
            "score": score,
            "is_reused": is_reused,
            "reuse_count": reuse_count,
            "risk_status": risk_status,
            "created_at": record["created_at"]
        })

    return {
        "total_vault_items": len(saved_items),
        "weak_count": weak_count,
        "reused_count": reused_count,
        "secure_count": secure_count,
        "password_rows": password_rows
    }


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
    compromised_found = AuditLog.query.filter(
        AuditLog.action.in_(["PASSWORD_BLACKLIST_MATCH", "PASSWORD_HIBP_MATCH"])
    ).count()

    recent_failed_logins = AuditLog.query.filter(
        AuditLog.action.in_(["FAILED_LOGIN", "FAILED_LOGIN_DISABLED_ACCOUNT", "MFA_VERIFY_FAILED"])
    ).order_by(AuditLog.timestamp.desc()).limit(10).all()

    recent_compromised_checks = AuditLog.query.filter(
        AuditLog.action.in_(["PASSWORD_BLACKLIST_CHECK", "PASSWORD_BLACKLIST_MATCH", "PASSWORD_HIBP_MATCH"])
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
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    mfa_enabled_users = User.query.filter_by(mfa_enabled=True).count()
    users_without_mfa = User.query.filter_by(mfa_enabled=False).order_by(User.created_at.desc()).all()

    failed_login_logs = AuditLog.query.filter(
        AuditLog.action.in_(["FAILED_LOGIN", "FAILED_LOGIN_DISABLED_ACCOUNT", "MFA_VERIFY_FAILED"])
    ).order_by(AuditLog.timestamp.desc()).limit(25).all()

    password_check_logs = AuditLog.query.filter(
        AuditLog.action.in_([
            "PASSWORD_STRENGTH_CHECK",
            "PASSWORD_BLACKLIST_CHECK",
            "PASSWORD_BLACKLIST_MATCH",
            "PASSWORD_HIBP_MATCH",
            "PASSWORD_ATTACK_SIMULATED",
            "PASSWORD_AI_PREDICTION",
            "PASSWORD_LLM_ADVICE"
        ])
    ).order_by(AuditLog.timestamp.desc()).limit(25).all()

    mfa_logs = AuditLog.query.filter(
        AuditLog.action.in_(["MFA_ENABLED", "MFA_VERIFY_FAILED"])
    ).order_by(AuditLog.timestamp.desc()).limit(25).all()

    attack_logs = AuditLog.query.filter_by(
        action="PASSWORD_ATTACK_SIMULATED"
    ).order_by(AuditLog.timestamp.desc()).limit(25).all()

    breach_logs = AuditLog.query.filter(
        AuditLog.action.in_(["PASSWORD_BLACKLIST_MATCH", "PASSWORD_HIBP_MATCH"])
    ).order_by(AuditLog.timestamp.desc()).limit(25).all()

    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(15).all()

    password_report = calculate_password_report()

    total_vault_items = password_report["total_vault_items"]
    weak_passwords = password_report["weak_count"]
    reused_passwords = password_report["reused_count"]
    secure_passwords = password_report["secure_count"]
    password_rows = password_report["password_rows"]

    failed_login_count = len(failed_login_logs)
    breach_match_count = len(breach_logs)
    attack_simulation_count = len(attack_logs)
    users_without_mfa_count = len(users_without_mfa)

    risk_points = 0
    risk_points += users_without_mfa_count * 10
    risk_points += weak_passwords * 15
    risk_points += reused_passwords * 12
    risk_points += failed_login_count * 5
    risk_points += breach_match_count * 20

    risk_score = min(risk_points, 100)

    if risk_score >= 70:
        risk_level = "High"
        risk_color = "danger"
    elif risk_score >= 35:
        risk_level = "Medium"
        risk_color = "warning"
    else:
        risk_level = "Low"
        risk_color = "success"

    ai_metadata = {
        "total_users": total_users,
        "active_users": active_users,
        "mfa_enabled_users": mfa_enabled_users,
        "users_without_mfa": users_without_mfa_count,
        "total_vault_items": total_vault_items,
        "weak_passwords": weak_passwords,
        "reused_passwords": reused_passwords,
        "secure_passwords": secure_passwords,
        "failed_logins": failed_login_count,
        "breach_matches": breach_match_count,
        "attack_simulations": attack_simulation_count,
        "risk_score": risk_score,
        "risk_level": risk_level
    }

    ai_report = get_security_report_ai_advice(ai_metadata)

    return render_template(
        "analyst/reports.html",
        total_users=total_users,
        active_users=active_users,
        mfa_enabled_users=mfa_enabled_users,
        users_without_mfa=users_without_mfa,
        users_without_mfa_count=users_without_mfa_count,
        failed_login_logs=failed_login_logs,
        failed_login_count=failed_login_count,
        password_check_logs=password_check_logs,
        mfa_logs=mfa_logs,
        attack_logs=attack_logs,
        attack_simulation_count=attack_simulation_count,
        breach_logs=breach_logs,
        breach_match_count=breach_match_count,
        recent_logs=recent_logs,
        total_vault_items=total_vault_items,
        weak_passwords=weak_passwords,
        reused_passwords=reused_passwords,
        secure_passwords=secure_passwords,
        password_rows=password_rows,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_color=risk_color,
        ai_report=ai_report
    )