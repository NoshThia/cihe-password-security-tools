from models import SavedPassword, AuditLog
from services.vault_crypto import decrypt_password


def calculate_cyber_health_score(user):
    """
    Calculates a Cyber Health Score (0-100) for the given user.
    Four pillars: MFA status, login risk, password reuse, tool engagement.
    """
    score = 100
    issues = []
    recommendations = []
    breakdown = []

    # ── 1. MFA STATUS (25 pts) ────────────────────────────────────────────────
    if user.mfa_enabled:
        breakdown.append({
            "label": "Multi-Factor Authentication",
            "points": 25, "max": 25, "status": "good",
            "detail": "MFA is enabled on your account."
        })
    else:
        score -= 25
        breakdown.append({
            "label": "Multi-Factor Authentication",
            "points": 0, "max": 25, "status": "danger",
            "detail": "MFA is not enabled on your account."
        })
        issues.append("MFA is not enabled — your account has no second layer of protection.")
        recommendations.append("Enable Multi-Factor Authentication immediately from your account settings.")

    # ── 2. LOGIN RISK LEVEL (25 pts) ──────────────────────────────────────────
    risk_level = user.login_risk_level or "Low"
    if risk_level == "Low":
        breakdown.append({
            "label": "Login Behaviour Risk",
            "points": 25, "max": 25, "status": "good",
            "detail": "No unusual login behaviour detected."
        })
    elif risk_level == "Medium":
        score -= 10
        breakdown.append({
            "label": "Login Behaviour Risk",
            "points": 15, "max": 25, "status": "warning",
            "detail": "Some unusual login behaviour was detected."
        })
        issues.append("Moderate login risk: " + (user.last_risk_reason or "unusual activity detected."))
        recommendations.append("Review your recent login activity and ensure no unauthorised access.")
    else:
        score -= 25
        breakdown.append({
            "label": "Login Behaviour Risk",
            "points": 0, "max": 25, "status": "danger",
            "detail": "High-risk login behaviour detected."
        })
        issues.append("High login risk: " + (user.last_risk_reason or "suspicious activity detected."))
        recommendations.append("Change your password and check active sessions immediately.")

    # ── 3. PASSWORD REUSE IN VAULT (25 pts) ───────────────────────────────────
    saved = SavedPassword.query.filter_by(user_id=user.id).all()
    if not saved:
        score -= 5
        breakdown.append({
            "label": "Password Reuse in Vault",
            "points": 20, "max": 25, "status": "warning",
            "detail": "No saved passwords — reuse cannot be checked."
        })
        issues.append("No passwords saved in vault — password reuse cannot be monitored.")
        recommendations.append("Save your passwords in the vault so reuse can be tracked.")
    else:
        plain_passwords = [decrypt_password(i.password_value) for i in saved]
        plain_passwords = [p for p in plain_passwords if p and p != "[DECRYPTION_FAILED]"]
        counts = {}
        for p in plain_passwords:
            counts[p] = counts.get(p, 0) + 1
        reused = len([p for p, c in counts.items() if c > 1])

        if reused == 0:
            breakdown.append({
                "label": "Password Reuse in Vault",
                "points": 25, "max": 25, "status": "good",
                "detail": f"No reused passwords across {len(saved)} saved entries."
            })
        elif reused <= 2:
            score -= 10
            breakdown.append({
                "label": "Password Reuse in Vault",
                "points": 15, "max": 25, "status": "warning",
                "detail": f"{reused} reused password(s) detected in your vault."
            })
            issues.append(f"{reused} password(s) are reused across multiple accounts.")
            recommendations.append("Use the Password Generator to create a unique password for each account.")
        else:
            score -= 25
            breakdown.append({
                "label": "Password Reuse in Vault",
                "points": 0, "max": 25, "status": "danger",
                "detail": f"{reused} reused passwords — high reuse risk."
            })
            issues.append(f"{reused} passwords are reused across accounts.")
            recommendations.append("Immediately replace all reused passwords with unique strong alternatives.")

    # ── 4. SECURITY TOOL ENGAGEMENT (25 pts) ──────────────────────────────────
    tool_actions = ["PASSWORD_STRENGTH_CHECK", "PASSWORD_BLACKLIST_CHECK",
                    "PASSWORD_ATTACK_SIMULATED", "PASSWORD_AI_PREDICTION"]
    usage_count = AuditLog.query.filter(
        AuditLog.user_id == user.id,
        AuditLog.action.in_(tool_actions)
    ).count()

    if usage_count >= 5:
        breakdown.append({
            "label": "Security Tool Engagement",
            "points": 25, "max": 25, "status": "good",
            "detail": f"Actively using security tools ({usage_count} checks recorded)."
        })
    elif usage_count >= 2:
        score -= 10
        breakdown.append({
            "label": "Security Tool Engagement",
            "points": 15, "max": 25, "status": "warning",
            "detail": f"Some tool usage detected ({usage_count} checks)."
        })
        issues.append("You have used the security tools infrequently.")
        recommendations.append("Regularly use the Strength Checker and Attack Simulator to monitor your passwords.")
    else:
        score -= 25
        breakdown.append({
            "label": "Security Tool Engagement",
            "points": 0, "max": 25, "status": "danger",
            "detail": "No security tool usage detected yet."
        })
        issues.append("You have not used any security tools yet.")
        recommendations.append("Start with the Strength Checker to analyse your passwords and understand your risks.")

    # ── FINAL SCORE + GRADE ───────────────────────────────────────────────────
    score = max(0, min(100, score))

    if score >= 85:
        grade, grade_label, grade_color = "A", "Excellent", "success"
        summary = "Your cyber health is excellent. Keep up the strong security habits."
    elif score >= 70:
        grade, grade_label, grade_color = "B", "Good", "primary"
        summary = "Your cyber health is good, but there are a few areas worth improving."
    elif score >= 50:
        grade, grade_label, grade_color = "C", "Moderate", "warning"
        summary = "Your account has moderate security. Several issues need your attention."
    elif score >= 30:
        grade, grade_label, grade_color = "D", "At Risk", "warning"
        summary = "Your account is at risk. Please act on the recommendations below."
    else:
        grade, grade_label, grade_color = "F", "Critical", "danger"
        summary = "Your account is critically exposed. Immediate action is required."

    if not issues:
        issues.append("No major security issues detected.")
    if not recommendations:
        recommendations.append("Maintain your current security habits and review your vault regularly.")

    return {
        "score": score,
        "grade": grade,
        "grade_label": grade_label,
        "grade_color": grade_color,
        "summary": summary,
        "issues": issues,
        "recommendations": recommendations,
        "breakdown": breakdown
    }
