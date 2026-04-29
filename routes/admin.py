from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from extensions import db
from models import AuditLog, PasswordPolicy, User, SavedPassword
from routes.auth import log_action, role_required
from services.vault_crypto import decrypt_password

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def calculate_password_stats(saved_passwords):
    decrypted_items = []
    plain_passwords = []

    for item in saved_passwords:
        plain_password = decrypt_password(item.password_value)
        plain_passwords.append(plain_password)
        decrypted_items.append({
            "id": item.id,
            "password_value": plain_password,
            "mode": item.mode
        })

    reuse_map = {}
    for pwd in plain_passwords:
        reuse_map[pwd] = reuse_map.get(pwd, 0) + 1

    weak_passwords = 0
    breaches_detected = 0
    secure_items = 0

    try:
        from zxcvbn import zxcvbn
    except Exception:
        zxcvbn = None

    for item in decrypted_items:
        pwd = item["password_value"]
        reuse_count = reuse_map.get(pwd, 1)

        is_reused = reuse_count > 1 and pwd != "[DECRYPTION_FAILED]"
        is_weak = False

        if zxcvbn and pwd and pwd != "[DECRYPTION_FAILED]":
            try:
                result = zxcvbn(pwd)
                is_weak = result.get("score", 0) <= 1
            except Exception:
                is_weak = False

        if is_reused or is_weak:
            weak_passwords += 1
        else:
            secure_items += 1

        if is_reused:
            breaches_detected += 1

    return {
        "total_items": len(saved_passwords),
        "weak_passwords": weak_passwords,
        "breaches_detected": breaches_detected,
        "secure_items": secure_items
    }


@admin_bp.route("/dashboard")
@login_required
@role_required("admin")
def dashboard():
    total_users = User.query.count()
    total_admins = User.query.filter_by(role="admin").count()
    total_analysts = User.query.filter_by(role="analyst").count()
    total_standard_users = User.query.filter_by(role="user").count()
    mfa_enabled_users = User.query.filter_by(mfa_enabled=True).count()
    active_users = User.query.filter_by(is_active=True).count()

    user_passwords = SavedPassword.query.filter_by(user_id=current_user.id).all()
    password_stats = calculate_password_stats(user_passwords)

    total_items = password_stats["total_items"]
    weak_passwords = password_stats["weak_passwords"]
    breaches_detected = password_stats["breaches_detected"]
    secure_items = password_stats["secure_items"]

    risk_percentage = int((weak_passwords / total_items) * 100) if total_items > 0 else 0

    if risk_percentage >= 70:
        system_risk_level = "High"
    elif risk_percentage >= 35:
        system_risk_level = "Medium"
    else:
        system_risk_level = "Low"

    latest_policy = PasswordPolicy.query.order_by(
        PasswordPolicy.updated_at.desc()
    ).first()

    recent_logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).limit(10).all()

    try:
        high_risk_users = User.query.filter_by(login_risk_level="High").count()
        medium_risk_users = User.query.filter_by(login_risk_level="Medium").count()
        low_risk_users = User.query.filter_by(login_risk_level="Low").count()
        risky_users = User.query.order_by(User.login_risk_score.desc()).limit(5).all()
    except Exception:
        high_risk_users = 0
        medium_risk_users = 0
        low_risk_users = total_users
        risky_users = []

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        total_admins=total_admins,
        total_analysts=total_analysts,
        total_standard_users=total_standard_users,
        mfa_enabled_users=mfa_enabled_users,
        active_users=active_users,
        total_items=total_items,
        weak_passwords=weak_passwords,
        secure_items=secure_items,
        breaches_detected=breaches_detected,
        latest_policy=latest_policy,
        recent_logs=recent_logs,
        high_risk_users=high_risk_users,
        medium_risk_users=medium_risk_users,
        low_risk_users=low_risk_users,
        risky_users=risky_users,
        avg_risk=risk_percentage,
        system_risk_level=system_risk_level
    )


@admin_bp.route("/users")
@login_required
@role_required("admin")
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()

    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    mfa_enabled_users = User.query.filter_by(mfa_enabled=True).count()
    total_admins = User.query.filter_by(role="admin").count()

    return render_template(
        "admin/users.html",
        users=all_users,
        total_users=total_users,
        active_users=active_users,
        mfa_enabled_users=mfa_enabled_users,
        total_admins=total_admins
    )


@admin_bp.route("/users/create", methods=["GET", "POST"])
@login_required
@role_required("admin")
def create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user").strip().lower()

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("admin.users"))

        if role not in ["admin", "analyst", "user"]:
            flash("Invalid role selected.", "danger")
            return redirect(url_for("admin.users"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("admin.users"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "danger")
            return redirect(url_for("admin.users"))

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            mfa_enabled=False,
            is_active=True
        )

        db.session.add(new_user)
        db.session.commit()

        log_action(
            action="USER_CREATED",
            detail=f"Admin {current_user.username} created user {username} with role {role}",
            user_id=current_user.id
        )

        flash("User created successfully.", "success")
        return redirect(url_for("admin.users"))

    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/update-password", methods=["POST"])
@login_required
@role_required("admin")
def update_user_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = request.form.get("new_password", "").strip()

    if not new_password:
        flash("Password cannot be empty.", "danger")
        return redirect(url_for("admin.users"))

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()

    log_action(
        action="USER_PASSWORD_UPDATED",
        detail=f"Admin {current_user.username} updated password for user {user.username}",
        user_id=current_user.id
    )

    flash(f"Password updated for {user.username}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.users"))

    username = user.username

    SavedPassword.query.filter_by(user_id=user.id).delete()
    AuditLog.query.filter_by(user_id=user.id).update({"user_id": None})

    db.session.delete(user)
    db.session.commit()

    log_action(
        action="USER_DELETED",
        detail=f"Admin {current_user.username} permanently deleted user {username}",
        user_id=current_user.id
    )

    flash(f"User {username} has been permanently deleted.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/toggle-status", methods=["POST"])
@login_required
@role_required("admin")
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot disable your own account.", "danger")
        return redirect(url_for("admin.users"))

    user.is_active = not user.is_active
    db.session.commit()

    status_text = "enabled" if user.is_active else "disabled"

    log_action(
        action="USER_STATUS_CHANGED",
        detail=f"Admin {current_user.username} {status_text} user {user.username}",
        user_id=current_user.id
    )

    flash(f"User {user.username} has been {status_text}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/change-role", methods=["POST"])
@login_required
@role_required("admin")
def change_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "").strip().lower()

    if new_role not in ["admin", "analyst", "user"]:
        flash("Invalid role selected.", "danger")
        return redirect(url_for("admin.users"))

    old_role = user.role
    user.role = new_role
    db.session.commit()

    log_action(
        action="ROLE_CHANGED",
        detail=f"Admin {current_user.username} changed role of {user.username} from {old_role} to {new_role}",
        user_id=current_user.id
    )

    flash(f"Role updated for {user.username}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/policies", methods=["GET", "POST"])
@login_required
@role_required("admin")
def policies():
    policy = PasswordPolicy.query.order_by(PasswordPolicy.updated_at.desc()).first()

    if request.method == "POST":
        min_length = request.form.get("min_length", "8").strip()
        require_upper = request.form.get("require_upper") == "on"
        require_lower = request.form.get("require_lower") == "on"
        require_digit = request.form.get("require_digit") == "on"
        require_symbol = request.form.get("require_symbol") == "on"

        try:
            min_length = int(min_length)
        except ValueError:
            flash("Minimum length must be a number.", "danger")
            return render_template("admin/policies.html", policy=policy)

        if min_length < 4:
            flash("Minimum length must be at least 4.", "danger")
            return render_template("admin/policies.html", policy=policy)

        if not policy:
            policy = PasswordPolicy()

        policy.min_length = min_length
        policy.require_upper = require_upper
        policy.require_lower = require_lower
        policy.require_digit = require_digit
        policy.require_symbol = require_symbol
        policy.updated_by = current_user.id

        db.session.add(policy)
        db.session.commit()

        log_action(
            action="POLICY_UPDATED",
            detail=(
                f"Admin {current_user.username} updated password policy: "
                f"min_length={min_length}, upper={require_upper}, lower={require_lower}, "
                f"digit={require_digit}, symbol={require_symbol}"
            ),
            user_id=current_user.id
        )

        flash("Password policy updated successfully.", "success")
        return redirect(url_for("admin.policies"))

    return render_template("admin/policies.html", policy=policy)


@admin_bp.route("/logs")
@login_required
@role_required("admin")
def logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("admin/logs.html", logs=all_logs)