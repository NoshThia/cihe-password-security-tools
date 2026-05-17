from flask import current_app


def build_local_security_summary(metadata):
    total_users = metadata.get("total_users", 0)
    users_without_mfa = metadata.get("users_without_mfa", 0)
    weak_passwords = metadata.get("weak_passwords", 0)
    reused_passwords = metadata.get("reused_passwords", 0)
    failed_logins = metadata.get("failed_logins", 0)
    breach_matches = metadata.get("breach_matches", 0)
    risk_level = metadata.get("risk_level", "Low")

    recommendations = []

    if users_without_mfa > 0:
        recommendations.append("Enable MFA for all remaining accounts.")

    if weak_passwords > 0:
        recommendations.append("Ask users to replace weak passwords with stronger generated passwords.")

    if reused_passwords > 0:
        recommendations.append("Review reused passwords in the vault and replace duplicates.")

    if failed_logins > 0:
        recommendations.append("Review failed login activity for suspicious access attempts.")

    if breach_matches > 0:
        recommendations.append("Reset passwords that match blacklist or breach indicators.")

    if not recommendations:
        recommendations.append("Current security posture appears healthy. Continue monitoring regularly.")

    advice = (
        f"The system currently monitors {total_users} user account(s). "
        f"The overall security risk level is {risk_level}. "
        f"There are {users_without_mfa} account(s) without MFA, {weak_passwords} weak password item(s), "
        f"{reused_passwords} reused password item(s), {failed_logins} failed login event(s), "
        f"and {breach_matches} breach-related match(es). "
        f"Recommended action: {' '.join(recommendations)}"
    )

    return {
        "enabled": True,
        "source": "local_fallback",
        "advice": advice,
        "error": None
    }


def get_security_report_ai_advice(metadata):
    api_key = current_app.config.get("GEMINI_API_KEY", "")
    model_name = current_app.config.get("LLM_MODEL", "gemini-1.5-flash")

    if not api_key:
        local_result = build_local_security_summary(metadata)
        local_result["error"] = "Gemini API key is not configured."
        return local_result

    try:
        import google.generativeai as genai

        genai.configure(api_key=api_key)

        prompt = f"""
You are a cybersecurity analyst for a university capstone project.

Create a short security report summary based only on the following system metrics.
Do not invent facts. Do not include raw passwords. Keep it professional and clear.

Security metadata:
{metadata}

Write:
1. Overall risk summary
2. Key issues found
3. Recommended actions

Keep the answer between 4 and 7 sentences.
"""

        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)

        advice_text = response.text.strip() if response and response.text else ""

        if not advice_text:
            local_result = build_local_security_summary(metadata)
            local_result["error"] = "Gemini returned an empty response."
            return local_result

        return {
            "enabled": True,
            "source": "gemini",
            "advice": advice_text,
            "error": None
        }

    except Exception as e:
        local_result = build_local_security_summary(metadata)
        local_result["error"] = f"Gemini unavailable, local fallback used: {str(e)}"
        return local_result