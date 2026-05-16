from flask import current_app
import google.generativeai as genai


def get_local_phishing_advice(text):
    text = text or ""
    lower_text = text.lower()

    rules = {
        "urgent": "Creates urgency or pressure.",
        "immediately": "Pushes the user to act immediately.",
        "verify": "Asks the user to verify information.",
        "confirm": "Asks the user to confirm details.",
        "password": "Mentions password or login credentials.",
        "login": "Mentions login or account access.",
        "bank": "Pretends to be related to a bank or financial account.",
        "account locked": "Uses an account-lock threat.",
        "suspended": "Claims an account is suspended.",
        "limited": "Claims account access is limited.",
        "click": "Encourages clicking a link.",
        "24 hours": "Creates a deadline to pressure the user.",
        "prize": "Uses prize or reward bait.",
        "winner": "Uses winner/reward language.",
        "payment failed": "Uses payment failure as a scare tactic.",
        "billing": "Mentions billing or payment information.",
        "security alert": "Pretends to be a security warning.",
    }

    reasons = []

    for keyword, reason in rules.items():
        if keyword in lower_text:
            reasons.append(reason)

    if "http://" in lower_text or "https://" in lower_text:
        reasons.append("Contains a link, which could lead to a fake login or malware website.")

    suspicious_domains = [".xyz", ".top", ".click", ".info", ".ru"]
    if any(domain in lower_text for domain in suspicious_domains):
        reasons.append("Uses an unusual or suspicious domain name.")

    if "dear customer" in lower_text or "dear user" in lower_text:
        reasons.append("Uses a generic greeting instead of a real name.")

    if "@" in text and ("gmail.com" in lower_text or "outlook.com" in lower_text or "yahoo.com" in lower_text):
        reasons.append("May be using a free email account instead of an official company address.")

    score = len(reasons)

    if score >= 5:
        label = "High Risk"
        advice = (
            "This message is highly suspicious and shows several common phishing indicators. "
            "It may be trying to trick the user into clicking a fake link, entering login details, "
            "or responding quickly without thinking. The safest action is to not click any links, "
            "not download attachments, and contact the organisation directly using its official website or phone number."
        )
    elif score >= 2:
        label = "Medium Risk"
        advice = (
            "This message has some suspicious signs. It may not be definitely phishing, but it contains warning signs "
            "such as urgency, account-related pressure, suspicious wording, or links. The user should check the sender, "
            "avoid clicking unknown links, and verify the message through official channels."
        )
    else:
        label = "Low Risk"
        advice = (
            "No strong phishing indicators were detected in this message. However, users should still be careful with "
            "unexpected messages, links, attachments, or requests for personal information."
        )

    return {
        "label": label,
        "score": score,
        "reasons": reasons,
        "source": "local",
        "advice": advice
    }


def get_phishing_ai_advice(message_text):
    message_text = message_text or ""

    llm_enabled = current_app.config.get("LLM_ENABLED", False)
    api_key = current_app.config.get("GEMINI_API_KEY", "")
    model_name = current_app.config.get("LLM_MODEL", "gemini-1.5-flash")

    if not message_text.strip():
        return {
            "label": "Low Risk",
            "score": 0,
            "reasons": ["No message text was provided."],
            "source": "local",
            "advice": "Please paste an email, SMS, or message so the phishing detection tool can analyse it."
        }

    local_result = get_local_phishing_advice(message_text)

    if not llm_enabled or not api_key:
        return local_result

    try:
        genai.configure(api_key=api_key)

        model = genai.GenerativeModel(model_name)

        prompt = f"""
You are a cybersecurity expert specialising in phishing detection.

Analyse the message below and provide a detailed but easy-to-understand security report.

Include:
1. Risk Level: High, Medium, or Low
2. Detailed Explanation
3. Specific phishing indicators found
4. Why the message could be dangerous
5. Recommended Action for the user

Important rules:
- Do not ask for the user's password.
- Do not say the message is safe if it contains suspicious links or account threats.
- Use bullet points where possible.
- Keep the explanation professional and clear.

Message:
{message_text}
"""

        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.4,
                "max_output_tokens": 500
            }
        )

        ai_text = response.text.strip() if response and response.text else ""

        if not ai_text:
            local_result["advice"] += "\n\nAI explanation was unavailable, so local analysis was used."
            return local_result

        return {
            "label": local_result["label"],
            "score": local_result["score"],
            "reasons": local_result["reasons"],
            "source": "gemini",
            "advice": ai_text
        }

    except Exception as e:
        local_result["advice"] += f"\n\nGemini AI was unavailable, so local analysis was used. Error: {str(e)}"
        return local_result