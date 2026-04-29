from flask import current_app
from google import genai


def build_password_metadata(result, policy_errors, ai_prediction, blacklist_match, hibp_result):
    features = ai_prediction.get("features", {}) if ai_prediction else {}

    metadata = {
        "zxcvbn_score": result.get("score") if result else None,
        "risk_label": ai_prediction.get("risk_label") if ai_prediction else None,
        "estimated_crack_time": ai_prediction.get("estimated_crack_time") if ai_prediction else None,
        "policy_errors": policy_errors or [],
        "risk_reasons": ai_prediction.get("reasons", []) if ai_prediction else [],
        "blacklist_match": bool(blacklist_match),
        "hibp_found": bool(hibp_result.get("found")) if hibp_result else False,
        "hibp_count": hibp_result.get("count", 0) if hibp_result else 0,
        "hibp_checked": bool(hibp_result.get("checked")) if hibp_result else False,
        "length": features.get("length"),
        "has_upper": features.get("has_upper"),
        "has_lower": features.get("has_lower"),
        "has_digit": features.get("has_digit"),
        "has_symbol": features.get("has_symbol"),
        "common_name_found": features.get("common_name_found"),
        "sequence_found": features.get("sequence_found"),
        "year_pattern_found": features.get("year_pattern_found"),
        "repeated_chars": features.get("repeated_chars"),
        "common_suffix_digits": features.get("common_suffix_digits"),
    }

    return metadata


def get_local_password_ai_advice(metadata):
    risk_label = metadata.get("risk_label", "Unknown")
    crack_time = metadata.get("estimated_crack_time", "Unknown")
    blacklist_match = metadata.get("blacklist_match", False)
    hibp_found = metadata.get("hibp_found", False)
    hibp_count = metadata.get("hibp_count", 0)
    policy_errors = metadata.get("policy_errors", [])
    risk_reasons = metadata.get("risk_reasons", [])

    sentences = []

    if risk_label in ["Very Weak", "Weak"]:
        sentences.append(
            f"This password is {risk_label.lower()} and could be compromised quickly. "
            f"The current estimated crack time is {str(crack_time).lower()}."
        )
    elif risk_label == "Moderate":
        sentences.append(
            f"This password has a moderate security level, but it still shows some weaknesses. "
            f"The current estimated crack time is {str(crack_time).lower()}."
        )
    else:
        sentences.append(
            f"This password appears relatively strong based on the current local analysis. "
            f"The estimated crack time is {str(crack_time).lower()}."
        )

    if blacklist_match:
        sentences.append(
            "It appears in the local blacklist of common passwords, which makes it highly unsafe to use."
        )

    if hibp_found:
        sentences.append(
            f"It was also found in known data breaches ({hibp_count} exposures), so it should not be reused."
        )

    if policy_errors:
        sentences.append(
            "It does not fully satisfy the current password policy requirements."
        )

    important_reasons = []
    for reason in risk_reasons:
        if reason not in important_reasons:
            important_reasons.append(reason)

    if important_reasons:
        sentences.append(
            "Key weakness factors include: " + "; ".join(important_reasons[:2]).rstrip(".") + "."
        )

    if risk_label in ["Very Weak", "Weak", "Moderate"]:
        sentences.append(
            "Use the Password Generator to create a longer password with uppercase letters, lowercase letters, digits, and symbols."
        )
    else:
        sentences.append(
            "Continue avoiding reuse across accounts and keep MFA enabled for better protection."
        )

    return {
        "enabled": True,
        "source": "local_fallback",
        "advice": " ".join(sentences),
        "error": None
    }


def get_password_ai_advice(metadata):
    llm_enabled = current_app.config.get("LLM_ENABLED", False)
    api_key = current_app.config.get("GEMINI_API_KEY", "")
    model_name = current_app.config.get("LLM_MODEL", "gemini-2.5-flash")

    if not llm_enabled or not api_key:
        local_result = get_local_password_ai_advice(metadata)
        local_result["error"] = "Gemini API key is not configured."
        return local_result

    try:
        client = genai.Client(api_key=api_key)

        prompt = f"""
You are a cybersecurity password advisor for a university capstone project.

Important rules:
- You will receive only derived password-security metadata.
- You must never ask for the raw password.
- Base your answer only on the metadata provided.
- Give a concise explanation in 3 to 5 sentences.
- Explain why the password is risky or acceptable.
- Mention breach, blacklist, policy, or pattern issues if present.
- Recommend the next best action.
- Do not invent facts that are not in the metadata.

Password security metadata:
{metadata}

Write a short user-friendly security explanation.
"""

        response = client.models.generate_content(
            model=model_name,
            contents=prompt
        )

        advice_text = response.text.strip() if response and response.text else ""

        if not advice_text:
            local_result = get_local_password_ai_advice(metadata)
            local_result["error"] = "Gemini returned an empty response."
            return local_result

        return {
            "enabled": True,
            "source": "gemini",
            "advice": advice_text,
            "error": None
        }

    except Exception as e:
        local_result = get_local_password_ai_advice(metadata)
        local_result["error"] = f"Gemini unavailable, local fallback used: {str(e)}"
        return local_result