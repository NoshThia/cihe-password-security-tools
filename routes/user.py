import hashlib
import secrets
import string

import requests
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import PasswordPolicy, SavedPassword
from routes.auth import log_action
from services.attack_simulator import simulate_password_attack
from services.hashcat_demo import run_hashcat_demo
from services.password_ai import predict_password_strength, generate_memorable_password_from_input
from services.vault_crypto import encrypt_password, decrypt_password
from services.llm_advisor import build_password_metadata, get_password_ai_advice
from services.chat_assistant import get_chat_response
from services.health_score import calculate_cyber_health_score


user_bp = Blueprint("user", __name__, url_prefix="/user")


def check_policy(password, policy):
    errors = []

    if not policy:
        return errors

    if len(password) < policy.min_length:
        errors.append(f"Password must be at least {policy.min_length} characters long.")

    if policy.require_upper and not any(char.isupper() for char in password):
        errors.append("Password must include at least one uppercase letter.")

    if policy.require_lower and not any(char.islower() for char in password):
        errors.append("Password must include at least one lowercase letter.")

    if policy.require_digit and not any(char.isdigit() for char in password):
        errors.append("Password must include at least one digit.")

    if policy.require_symbol and not any(char in string.punctuation for char in password):
        errors.append("Password must include at least one symbol.")

    return errors


def generate_secure_password(length, policy):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation

    all_chars = lowercase + uppercase + digits + symbols
    password_chars = []

    if policy:
        if policy.require_lower:
            password_chars.append(secrets.choice(lowercase))
        if policy.require_upper:
            password_chars.append(secrets.choice(uppercase))
        if policy.require_digit:
            password_chars.append(secrets.choice(digits))
        if policy.require_symbol:
            password_chars.append(secrets.choice(symbols))

        minimum_required = max(length, policy.min_length)
    else:
        minimum_required = length

    while len(password_chars) < minimum_required:
        password_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def check_hibp(password):
    if not password:
        return {
            "checked": False,
            "found": False,
            "count": 0,
            "error": None
        }

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "PSMS Password Security Tool"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue

            returned_suffix = parts[0].strip().upper()
            count = parts[1].strip()

            if returned_suffix == suffix:
                return {
                    "checked": True,
                    "found": True,
                    "count": int(count),
                    "error": None
                }

        return {
            "checked": True,
            "found": False,
            "count": 0,
            "error": None
        }

    except requests.RequestException as e:
        return {
            "checked": False,
            "found": False,
            "count": 0,
            "error": f"HIBP check failed: {str(e)}"
        }


@user_bp.route("/dashboard")
@login_required
def dashboard():
    latest_policy = PasswordPolicy.query.order_by(PasswordPolicy.updated_at.desc()).first()

    saved_items = SavedPassword.query.filter_by(user_id=current_user.id).all()

    decrypted_passwords = []
    weak_passwords = 0
    reused_passwords = 0
    secure_passwords = 0

    try:
        from zxcvbn import zxcvbn
    except Exception:
        zxcvbn = None

    for item in saved_items:
        plain_password = decrypt_password(item.password_value)
        decrypted_passwords.append(plain_password)

    reuse_map = {}
    for pwd in decrypted_passwords:
        reuse_map[pwd] = reuse_map.get(pwd, 0) + 1

    for pwd in decrypted_passwords:
        is_reused = reuse_map.get(pwd, 0) > 1 and pwd != "[DECRYPTION_FAILED]"
        is_weak = False

        if zxcvbn and pwd and pwd != "[DECRYPTION_FAILED]":
            try:
                result = zxcvbn(pwd)
                is_weak = result.get("score", 0) <= 1
            except Exception:
                is_weak = False

        if is_reused:
            reused_passwords += 1

        if is_weak or is_reused:
            weak_passwords += 1
        else:
            secure_passwords += 1

    total_items = len(saved_items)
    compromised_passwords = reused_passwords

    if total_items > 0:
        risk_score = int((weak_passwords / total_items) * 100)
    else:
        risk_score = 0

    if risk_score >= 70:
        risk_label = "High"
    elif risk_score >= 35:
        risk_label = "Medium"
    else:
        risk_label = "Low"

    mfa_enabled_count = 1 if current_user.mfa_enabled else 0

    return render_template(
        "user/dashboard.html",
        latest_policy=latest_policy,
        total_items=total_items,
        weak_passwords=weak_passwords,
        secure_passwords=secure_passwords,
        reused_passwords=reused_passwords,
        compromised_passwords=compromised_passwords,
        risk_score=risk_score,
        risk_label=risk_label,
        mfa_enabled_count=mfa_enabled_count
    )


@user_bp.route("/strength", methods=["GET", "POST"])
@login_required
def strength():
    from zxcvbn import zxcvbn

    result = None
    policy_errors = []
    password_value = ""
    ai_prediction = None
    ai_advice = None

    if request.method == "POST":
        password_value = request.form.get("password", "")
        latest_policy = PasswordPolicy.query.order_by(PasswordPolicy.updated_at.desc()).first()

        if password_value:
            result = zxcvbn(password_value)
            policy_errors = check_policy(password_value, latest_policy)

            blacklist = current_app.blacklist_passwords
            blacklist_match = password_value in blacklist
            hibp_result = check_hibp(password_value)

            ai_prediction = predict_password_strength(
                password=password_value,
                zxcvbn_result=result,
                policy_errors=policy_errors,
                hibp_result=hibp_result,
                blacklist_match=blacklist_match,
                policy=latest_policy
            )

            metadata = build_password_metadata(
                result=result,
                policy_errors=policy_errors,
                ai_prediction=ai_prediction,
                blacklist_match=blacklist_match,
                hibp_result=hibp_result
            )

            ai_advice = get_password_ai_advice(metadata)

            log_action(
                action="PASSWORD_STRENGTH_CHECK",
                detail=f"Password strength checked by user {current_user.username}. Score={result.get('score')}",
                user_id=current_user.id
            )

            log_action(
                action="PASSWORD_AI_PREDICTION",
                detail=(
                    f"AI password prediction used by {current_user.username}. "
                    f"Risk={ai_prediction['risk_label']}, "
                    f"CrackTime={ai_prediction['estimated_crack_time']}"
                ),
                user_id=current_user.id
            )

            advice_source = ai_advice.get("source", "unknown") if ai_advice else "unknown"

            log_action(
                action="PASSWORD_LLM_ADVICE",
                detail=f"AI security advisor used by {current_user.username}. Source={advice_source}",
                user_id=current_user.id
            )

    return render_template(
        "user/strength.html",
        result=result,
        policy_errors=policy_errors,
        password_value=password_value,
        ai_prediction=ai_prediction,
        ai_advice=ai_advice
    )


@user_bp.route("/generator", methods=["GET", "POST"])
@login_required
def generator():
    latest_policy = PasswordPolicy.query.order_by(PasswordPolicy.updated_at.desc()).first()
    generated_password = None
    requested_length = latest_policy.min_length if latest_policy else 12
    generator_mode = "random"
    seed_input = ""
    custom_password = ""

    if request.method == "POST":
        action = request.form.get("action", "generate")
        generator_mode = request.form.get("generator_mode", "random")
        seed_input = request.form.get("seed_input", "").strip()
        custom_password = request.form.get("custom_password", "").strip()
        requested_length_raw = request.form.get("length", str(requested_length)).strip()

        try:
            requested_length = int(requested_length_raw)
        except ValueError:
            requested_length = latest_policy.min_length if latest_policy else 12

        if requested_length < 4:
            requested_length = 4

        if latest_policy and requested_length < latest_policy.min_length:
            requested_length = latest_policy.min_length

        if action == "generate":
            if generator_mode == "memorable":
                generated_password = generate_memorable_password_from_input(seed_input, latest_policy)

            elif generator_mode == "custom":
                if not custom_password:
                    flash("Please enter your own password before continuing.", "danger")
                    generated_password = None
                else:
                    generated_password = custom_password

            else:
                generated_password = generate_secure_password(requested_length, latest_policy)

            if generated_password:
                log_action(
                    action="PASSWORD_GENERATED",
                    detail=(
                        f"Password prepared by user {current_user.username}. "
                        f"Mode={generator_mode}, Length={len(generated_password)}"
                    ),
                    user_id=current_user.id
                )

        elif action == "save":
            password_to_save = request.form.get("generated_password", "").strip()
            label = request.form.get("label", "").strip()
            generator_mode = request.form.get("generator_mode", "custom")

            if not password_to_save:
                flash("No password found to save.", "danger")
            elif not label:
                flash("Please enter a label before saving.", "danger")
                generated_password = password_to_save
            else:
                encrypted_password = encrypt_password(password_to_save)

                saved_password = SavedPassword(
                    user_id=current_user.id,
                    label=label,
                    password_value=encrypted_password,
                    mode=generator_mode
                )

                db.session.add(saved_password)
                db.session.commit()

                flash("Password saved securely in the vault.", "success")

                log_action(
                    action="PASSWORD_SAVED",
                    detail=(
                        f"Encrypted password saved by user {current_user.username} "
                        f"with label '{label}' and mode '{generator_mode}'"
                    ),
                    user_id=current_user.id
                )

                return redirect(url_for("user.saved_passwords"))

    return render_template(
        "user/generator.html",
        generated_password=generated_password,
        requested_length=requested_length,
        latest_policy=latest_policy,
        generator_mode=generator_mode,
        seed_input=seed_input,
        custom_password=custom_password
    )


@user_bp.route("/saved-passwords")
@login_required
def saved_passwords():
    passwords = SavedPassword.query.filter_by(
        user_id=current_user.id
    ).order_by(SavedPassword.created_at.desc()).all()

    decrypted_items = []
    plain_passwords = []

    for item in passwords:
        plain_password = decrypt_password(item.password_value)
        plain_passwords.append(plain_password)

        decrypted_items.append({
            "id": item.id,
            "label": item.label,
            "password_value": plain_password,
            "mode": item.mode,
            "created_at": item.created_at
        })

    reuse_count_map = {}
    for pwd in plain_passwords:
        reuse_count_map[pwd] = reuse_count_map.get(pwd, 0) + 1

    try:
        from zxcvbn import zxcvbn
    except Exception:
        zxcvbn = None

    for item in decrypted_items:
        pwd = item["password_value"]
        total_count = reuse_count_map.get(pwd, 1)

        item["is_reused"] = total_count > 1 and pwd != "[DECRYPTION_FAILED]"
        item["reuse_count"] = total_count

        if zxcvbn and pwd and pwd != "[DECRYPTION_FAILED]":
            try:
                result = zxcvbn(pwd)
                item["strength_score"] = result.get("score", 0)
                item["is_weak"] = item["strength_score"] <= 1
            except Exception:
                item["strength_score"] = None
                item["is_weak"] = False
        else:
            item["strength_score"] = None
            item["is_weak"] = False

        item["is_at_risk"] = item["is_reused"] or item["is_weak"]

    return render_template("user/saved_passwords.html", passwords=decrypted_items)


@user_bp.route("/saved-passwords/delete/<int:password_id>", methods=["POST"])
@login_required
def delete_saved_password(password_id):
    saved_password = SavedPassword.query.filter_by(
        id=password_id,
        user_id=current_user.id
    ).first_or_404()

    label = saved_password.label

    db.session.delete(saved_password)
    db.session.commit()

    flash("Saved password deleted successfully.", "success")

    log_action(
        action="PASSWORD_DELETED",
        detail=f"Saved password '{label}' deleted by user {current_user.username}",
        user_id=current_user.id
    )

    return redirect(url_for("user.saved_passwords"))


@user_bp.route("/checker", methods=["GET", "POST"])
@login_required
def checker():
    password_value = ""
    is_compromised = None
    hibp_result = {
        "checked": False,
        "found": False,
        "count": 0,
        "error": None
    }

    if request.method == "POST":
        password_value = request.form.get("password", "").strip()
        blacklist = current_app.blacklist_passwords

        if password_value:
            is_compromised = password_value in blacklist
            hibp_result = check_hibp(password_value)

            log_action(
                action="PASSWORD_BLACKLIST_CHECK",
                detail=f"Blacklist and HIBP password check performed by user {current_user.username}",
                user_id=current_user.id
            )

            if is_compromised:
                log_action(
                    action="PASSWORD_BLACKLIST_MATCH",
                    detail=f"Compromised password detected in local blacklist for user {current_user.username}",
                    user_id=current_user.id
                )

            if hibp_result["checked"] and hibp_result["found"]:
                log_action(
                    action="PASSWORD_HIBP_MATCH",
                    detail=(
                        f"HIBP match found for user {current_user.username}. "
                        f"Exposure count={hibp_result['count']}"
                    ),
                    user_id=current_user.id
                )

    return render_template(
        "user/checker.html",
        password_value=password_value,
        is_compromised=is_compromised,
        hibp_result=hibp_result
    )


@user_bp.route("/attack-simulator", methods=["GET", "POST"])
@login_required
def attack_simulator():
    password_value = ""
    simulation = None

    if request.method == "POST":
        password_value = request.form.get("password", "").strip()
        blacklist = current_app.blacklist_passwords

        if password_value:
            blacklist_match = password_value in blacklist
            hibp_result = check_hibp(password_value)

            simulation = simulate_password_attack(
                password=password_value,
                blacklist_match=blacklist_match,
                hibp_result=hibp_result
            )

            hashcat_result = run_hashcat_demo(
                password=password_value,
                wordlist_path=current_app.config["BLACKLIST_FILE"]
            )

            simulation["hashcat_result"] = hashcat_result

            attack_metadata = {
                "overall_resistance": simulation["overall_resistance"],
                "zxcvbn_score": simulation["zxcvbn_score"],
                "entropy_bits": simulation["entropy"],
                "password_length": simulation["password_length"],
                "charset_size": simulation["charset_size"],
                "detected_patterns": simulation["patterns"],
                "severe_patterns": simulation["severe_patterns"],
                "blacklist_match": simulation["blacklist_match"],
                "hibp_found": simulation["hibp_found"],
                "hibp_count": simulation["hibp_count"],
                "hashcat_available": hashcat_result["available"],
                "hashcat_cracked": hashcat_result["cracked"],
                "hashcat_message": hashcat_result["message"]
            }

            ai_advice = get_password_ai_advice(attack_metadata)
            simulation["ai_advice"] = ai_advice

            log_action(
                action="PASSWORD_ATTACK_SIMULATED",
                detail=(
                    f"Password attack simulation used by {current_user.username}. "
                    f"Resistance={simulation['overall_resistance']}, "
                    f"Entropy={simulation['entropy']}, "
                    f"Length={simulation['password_length']}, "
                    f"Charset={simulation['charset_size']}, "
                    f"HashcatAvailable={hashcat_result['available']}, "
                    f"HashcatCracked={hashcat_result['cracked']}, "
                    f"AIAdvisorSource={ai_advice.get('source', 'unknown')}"
                ),
                user_id=current_user.id
            )

    return render_template(
        "user/attack_simulator.html",
        password_value=password_value,
        simulation=simulation
    )

# ── SENTINEL AI Chat ──────────────────────────────────────────────────────────

@user_bp.route("/chat-assistant")
@login_required
def chat_assistant():
    return render_template("user/chat_assistant.html")


@user_bp.route("/chat-assistant/message", methods=["POST"])
@login_required
def chat_message():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    conversation_history = data.get("history", [])
    if not conversation_history:
        return jsonify({"error": "No history provided"}), 400

    conversation_history = conversation_history[-10:]
    response = get_chat_response(conversation_history)

    log_action(
        action="AI_CHAT_USED",
        detail=f"SENTINEL AI Chat used by {current_user.username}. Source={response.get('source', 'unknown')}",
        user_id=current_user.id
    )

    return jsonify({
        "reply": response.get("reply", "Sorry, I could not process that."),
        "source": response.get("source", "unknown"),
        "error": response.get("error")
    })


# ── Cyber Health Score ────────────────────────────────────────────────────────

@user_bp.route("/health-score")
@login_required
def health_score():
    result = calculate_cyber_health_score(current_user)

    log_action(
        action="CYBER_HEALTH_SCORE_VIEWED",
        detail=f"User {current_user.username} viewed Cyber Health Score. Score={result['score']}, Grade={result['grade']}",
        user_id=current_user.id
    )

    return render_template("user/health_score.html", result=result)
