import base64
import io
from datetime import datetime
from functools import wraps

import pyotp
import qrcode
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for
)
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash

from extensions import db
from models import AuditLog, User


auth_bp = Blueprint("auth", __name__)


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "Unknown"


def log_action(action, detail="", user_id=None):
    log = AuditLog(
        user_id=user_id,
        action=action,
        detail=detail,
        ip_address=get_client_ip()
    )
    db.session.add(log)
    db.session.commit()


def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in first.", "warning")
                return redirect(url_for("auth.login"))

            # Extra protection: if somehow logged in without MFA, force setup
            if not current_user.mfa_enabled:
                flash("You must complete MFA setup before accessing the system.", "warning")
                return redirect(url_for("auth.setup_mfa"))

            if current_user.role not in roles:
                flash("You do not have permission to access this page.", "danger")
                log_action(
                    action="UNAUTHORIZED_ACCESS",
                    detail=f"User attempted to access restricted resource requiring roles {roles}",
                    user_id=current_user.id
                )
                return redirect(url_for("auth.dashboard_redirect"))

            return func(*args, **kwargs)
        return wrapper
    return decorator


def generate_qr_code_base64(uri):
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(uri)
    qr.make(fit=True)

    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return encoded


def calculate_behavior_risk(user, current_ip):
    score = 0
    reasons = []

    current_hour = datetime.utcnow().hour

    if user.last_login_ip and user.last_login_ip != current_ip:
        score += 40
        reasons.append("Login attempt from a new IP address")

    if current_hour < 5 or current_hour > 23:
        score += 20
        reasons.append("Login attempt at an unusual time")

    if user.failed_login_attempts >= 3:
        score += 30
        reasons.append("Multiple failed login attempts detected before success")
    elif user.failed_login_attempts > 0:
        score += 10
        reasons.append("Recent failed login attempts detected")

    if not user.last_login_at:
        score += 5
        reasons.append("First recorded login for this account")

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    if not reasons:
        reasons.append("Normal login behaviour pattern detected")

    return score, level, "; ".join(reasons)


def update_user_login_risk(user, ip_address):
    score, level, reason = calculate_behavior_risk(user, ip_address)
    user.login_risk_score = score
    user.login_risk_level = level
    user.last_risk_reason = reason


def get_preauth_user():
    preauth_user_id = session.get("preauth_user_id")
    if not preauth_user_id:
        return None
    return User.query.get(preauth_user_id)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if not current_user.mfa_enabled:
            return redirect(url_for("auth.setup_mfa"))
        return redirect(url_for("auth.dashboard_redirect"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = get_client_ip()

        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Invalid username or password.", "danger")
            log_action(
                action="FAILED_LOGIN",
                detail=f"Failed login attempt for unknown username: {username}",
                user_id=None
            )
            return render_template("auth/login.html")

        if not user.is_active:
            flash("Your account is disabled. Please contact the administrator.", "danger")
            log_action(
                action="FAILED_LOGIN_DISABLED_ACCOUNT",
                detail=f"Disabled account login attempt for username: {username}",
                user_id=user.id
            )
            return render_template("auth/login.html")

        if not check_password_hash(user.password_hash, password):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            user.last_failed_login_at = datetime.utcnow()
            db.session.commit()

            flash("Invalid username or password.", "danger")
            log_action(
                action="FAILED_LOGIN",
                detail=f"Failed login attempt for username: {username}",
                user_id=user.id
            )
            return render_template("auth/login.html")

        update_user_login_risk(user, client_ip)
        db.session.commit()

        # Store temporary pre-auth session only
        session["preauth_user_id"] = user.id

        if user.mfa_enabled:
            flash(
                f"Enter your MFA verification code. Current behaviour risk: {user.login_risk_level}.",
                "info"
            )
            log_action(
                action="LOGIN_PASSWORD_VERIFIED",
                detail=(
                    f"Password verified, awaiting MFA verification for username: {username}. "
                    f"Risk Level: {user.login_risk_level}. "
                    f"Risk Score: {user.login_risk_score}. "
                    f"Reason: {user.last_risk_reason}"
                ),
                user_id=user.id
            )
            return redirect(url_for("auth.verify_mfa"))

        flash("Please set up MFA before continuing.", "warning")
        log_action(
            action="LOGIN_PASSWORD_VERIFIED_PENDING_MFA_SETUP",
            detail=(
                f"Password verified, awaiting MFA setup for username: {username}. "
                f"Risk Level: {user.login_risk_level}. "
                f"Risk Score: {user.login_risk_score}. "
                f"Reason: {user.last_risk_reason}"
            ),
            user_id=user.id
        )
        return redirect(url_for("auth.setup_mfa"))

    return render_template("auth/login.html")


@auth_bp.route("/setup-mfa", methods=["GET", "POST"])
def setup_mfa():
    # If already fully logged in and MFA enabled, no need to be here
    if current_user.is_authenticated and current_user.mfa_enabled:
        flash("MFA is already enabled for your account.", "info")
        return redirect(url_for("auth.dashboard_redirect"))

    # Allow setup from pre-auth session
    user = get_preauth_user()

    # Fallback if logged in but not enabled yet
    if not user and current_user.is_authenticated and not current_user.mfa_enabled:
        user = current_user

    if not user:
        flash("Your MFA setup session has expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(user.totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="CIHE ShieldX"
    )
    qr_code_base64 = generate_qr_code_base64(provisioning_uri)

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        if totp.verify(code):
            user.mfa_enabled = True
            user.last_login_at = datetime.utcnow()
            user.last_login_ip = get_client_ip()
            user.failed_login_attempts = 0
            db.session.commit()

            session.pop("preauth_user_id", None)
            login_user(user)

            flash("MFA has been enabled successfully.", "success")
            log_action(
                action="MFA_ENABLED_AND_LOGIN_SUCCESS",
                detail=(
                    f"MFA enabled and login completed for username: {user.username}. "
                    f"Risk Level: {user.login_risk_level}. "
                    f"Risk Score: {user.login_risk_score}. "
                    f"Reason: {user.last_risk_reason}"
                ),
                user_id=user.id
            )
            return redirect(url_for("auth.dashboard_redirect"))

        flash("Invalid MFA code. Please try again.", "danger")
        log_action(
            action="MFA_SETUP_FAILED",
            detail=f"Invalid MFA setup verification code for username: {user.username}",
            user_id=user.id
        )

    return render_template(
        "auth/setup_mfa.html",
        qr_code_base64=qr_code_base64,
        secret=user.totp_secret
    )


@auth_bp.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    user = get_preauth_user()

    if not user:
        flash("Your MFA session has expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        client_ip = get_client_ip()

        if not user.totp_secret:
            session.pop("preauth_user_id", None)
            flash("MFA is not configured for this account.", "danger")
            log_action(
                action="MFA_VERIFY_FAILED",
                detail=f"MFA verify attempted but no secret exists for username: {user.username}",
                user_id=user.id
            )
            return redirect(url_for("auth.login"))

        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code):
            session.pop("preauth_user_id", None)
            login_user(user)

            user.last_login_at = datetime.utcnow()
            user.last_login_ip = client_ip
            user.failed_login_attempts = 0
            db.session.commit()

            flash(
                f"Login successful. Behaviour risk: {user.login_risk_level} ({user.login_risk_score}).",
                "success"
            )
            log_action(
                action="MFA_VERIFIED_LOGIN_SUCCESS",
                detail=(
                    f"MFA verified successfully for username: {user.username}. "
                    f"Risk Level: {user.login_risk_level}. "
                    f"Risk Score: {user.login_risk_score}. "
                    f"Reason: {user.last_risk_reason}"
                ),
                user_id=user.id
            )
            return redirect(url_for("auth.dashboard_redirect"))

        flash("Invalid MFA code. Please try again.", "danger")
        log_action(
            action="MFA_VERIFY_FAILED",
            detail=f"Invalid MFA code entered for username: {user.username}",
            user_id=user.id
        )

    return render_template("auth/verify_mfa.html")


@auth_bp.route("/logout")
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    logout_user()
    session.pop("preauth_user_id", None)

    flash("You have been logged out.", "success")
    log_action(
        action="LOGOUT",
        detail=f"User logged out: {username}",
        user_id=user_id
    )
    return redirect(url_for("auth.login"))


@auth_bp.route("/dashboard")
@login_required
def dashboard_redirect():
    if not current_user.mfa_enabled:
        flash("You must complete MFA setup before accessing the dashboard.", "warning")
        return redirect(url_for("auth.setup_mfa"))

    if current_user.role == "admin":
        return redirect(url_for("admin.dashboard"))
    if current_user.role == "analyst":
        return redirect(url_for("analyst.dashboard"))
    return redirect(url_for("user.dashboard"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        flash("Password reset link sent (demo)", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html")


@auth_bp.route("/forgot-username", methods=["GET", "POST"])
def forgot_username():
    if request.method == "POST":
        email = request.form.get("email")
        flash("Username sent to your email (demo)", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_username.html")