from flask import current_app

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


SYSTEM_PROMPT = """You are SENTINEL, the built-in AI cybersecurity assistant for CIHE Sentinel AI.

CIHE Sentinel AI is a university capstone project built at the Crown Institute of Higher Education (CIHE).
It is a Flask web application focused on password security, digital identity protection, and AI-powered threat awareness.
The LLM powering this assistant is Google Gemini.

=== TOOLS IN THIS SYSTEM ===

1. Password Strength Checker (/user/strength)
   - Analyses a password using zxcvbn scoring plus a custom AI prediction model.
   - Shows risk label: Very Weak / Weak / Moderate / Strong / Very Strong.
   - Estimates real-world crack time.
   - Checks against a local blacklist of common passwords.
   - Checks the HIBP (Have I Been Pwned) database using SHA-1 k-anonymity — the full password is never sent.
   - Gemini AI provides a natural language security explanation.

2. Password Generator (/user/generator)
   - Random mode: cryptographically secure random characters respecting the admin password policy.
   - Memorable mode: takes a seed word, applies leet-speak and random words to make a human-friendly but strong password.
   - Generated passwords can be saved directly to the encrypted vault.

3. Blacklist & HIBP Checker (/user/checker)
   - Checks if a password appears in a local common-passwords blacklist.
   - Checks the HIBP breach database — only the first 5 hex chars of the SHA-1 hash are sent (k-anonymity).
   - Returns how many times the password has appeared in real breaches.

4. Attack Simulator (/user/attack-simulator)
   - Simulates four real-world attack types: Online (10/sec), Offline (100k/sec), GPU (10B/sec), Dictionary.
   - Also integrates Hashcat — the real password cracking tool — to run a live MD5 dictionary attack demo.
   - Hashcat hashes the test password as MD5 and tries to crack it using common_passwords.txt wordlist.
   - Shows theoretical search space, penalty factors, and realistic estimated crack times.

5. Password Vault — Saved Passwords (/user/saved-passwords)
   - Stores passwords encrypted with Fernet symmetric encryption.
   - Detects and flags reused passwords across vault entries.

6. Cyber Health Score (/user/health-score)
   - Generates a personal security score (0–100) across four pillars:
     a) MFA Status (25 pts) — is MFA enabled?
     b) Login Behaviour Risk (25 pts) — any unusual login activity?
     c) Password Reuse in Vault (25 pts) — reused passwords across accounts?
     d) Security Tool Engagement (25 pts) — frequency of tool usage
   - Returns a grade A–F, plain-language summary, detected issues, and recommendations.

7. SENTINEL AI Chat (this widget)
   - Floating popup on every page, powered by Google Gemini.
   - Falls back to smart local responses if no Gemini API key is set.

=== SYSTEM FEATURES ===
- MFA: mandatory TOTP for all users (Google Authenticator / Authy compatible).
- Behaviour-Based Login Risk: scores each login (new IP +40, unusual hour +20, failed attempts +10–30). Risk = Low/Medium/High.
- Three roles: Admin (user management, policies, audit logs), Analyst (reports, monitoring), User (all personal tools).
- Tech stack: Python Flask, SQLite, Google Gemini, zxcvbn, HIBP API, Fernet encryption, PyOTP, Hashcat.

=== RESPONSE GUIDELINES ===
- You know this software completely — answer specific questions about tools, features, and how they work.
- Be concise and friendly. 3–5 sentences for simple questions; bullet points for feature explanations.
- Never ask for or accept actual passwords.
- Refer to yourself as SENTINEL.
- If asked outside cybersecurity scope, politely redirect.
"""


def _build_gemini_prompt(conversation_history):
    """Builds a single prompt string from conversation history for Gemini."""
    lines = [SYSTEM_PROMPT, "\n=== CONVERSATION ==="]
    for msg in conversation_history:
        role = "User" if msg["role"] == "user" else "SENTINEL"
        lines.append(f"{role}: {msg['content']}")
    lines.append("SENTINEL:")
    return "\n".join(lines)


def get_chat_response(conversation_history):
    """
    Sends conversation history to Gemini and returns SENTINEL's reply.
    Falls back to local keyword responses if Gemini is unavailable.
    """
    api_key = current_app.config.get("GEMINI_API_KEY", "")
    llm_enabled = current_app.config.get("LLM_ENABLED", False)
    model_name = current_app.config.get("LLM_MODEL", "gemini-2.5-flash")

    if llm_enabled and api_key and GENAI_AVAILABLE:
        try:
            client = genai.Client(api_key=api_key)
            prompt = _build_gemini_prompt(conversation_history)
            response = client.models.generate_content(
                model=model_name,
                contents=prompt
            )
            reply = response.text.strip() if response and response.text else ""
            if reply:
                return {"reply": reply, "source": "gemini", "error": None}
        except Exception as e:
            result = _get_local_response(conversation_history)
            result["error"] = f"Gemini unavailable: {str(e)}"
            return result

    return _get_local_response(conversation_history)


def _get_local_response(conversation_history):
    """Smart keyword-based fallback — knows the full software without needing Gemini."""
    msg = ""
    if conversation_history:
        msg = conversation_history[-1].get("content", "").lower()

    # Greetings
    if any(w in msg for w in ["hello", "hi", "hey", "help", "what can you do"]):
        reply = (
            "Hi! I'm **SENTINEL**, your AI cybersecurity assistant powered by Google Gemini. 🔐\n\n"
            "I know this system inside and out. Ask me about:\n"
            "• Any tool (Strength Checker, Attack Simulator, Vault, Health Score…)\n"
            "• Password security, phishing, MFA, or data breaches\n"
            "• How Hashcat or HIBP works in this app"
        )

    # About the software
    elif any(w in msg for w in ["what is this", "about this", "what is cihe", "this project", "what does this app", "capstone"]):
        reply = (
            "**CIHE Sentinel AI** is an AI-powered cybersecurity web app built as a capstone project "
            "at the Crown Institute of Higher Education.\n\n"
            "Key features:\n"
            "• Password strength analysis with Gemini AI explanations\n"
            "• Real Hashcat dictionary attack demo\n"
            "• Breach detection via Have I Been Pwned\n"
            "• Encrypted password vault (Fernet)\n"
            "• Behaviour-based login risk detection\n"
            "• Cyber Health Score (0–100)\n"
            "• Mandatory MFA for all users"
        )

    # All tools
    elif any(w in msg for w in ["what tools", "all tools", "all features", "list", "what pages", "what features"]):
        reply = (
            "Tools available in CIHE Sentinel AI:\n\n"
            "• **Strength Checker** — AI password analysis + HIBP breach check\n"
            "• **Password Generator** — random or memorable mode\n"
            "• **Blacklist & HIBP Checker** — breach exposure check\n"
            "• **Attack Simulator** — simulates 4 attack types + live Hashcat demo\n"
            "• **Password Vault** — Fernet-encrypted saved passwords\n"
            "• **Cyber Health Score** — personal security score 0–100\n"
            "• **SENTINEL AI Chat** — that's me!"
        )

    # Hashcat
    elif any(w in msg for w in ["hashcat", "hash cat", "cracking tool", "md5", "dictionary attack", "real crack"]):
        reply = (
            "**Hashcat** is integrated into the Attack Simulator as a real-world demo.\n\n"
            "Here's how it works:\n"
            "• Your test password is hashed as MD5\n"
            "• Hashcat runs a dictionary attack using the common_passwords.txt wordlist\n"
            "• If the password appears in the wordlist, Hashcat cracks the hash\n"
            "• Result shows whether your password survived a real cracking attempt\n\n"
            "This demonstrates why common or simple passwords are dangerous — real attackers use exactly this method."
        )

    # Attack simulator
    elif any(w in msg for w in ["attack simulator", "simulator", "simulate", "brute force", "gpu attack", "offline", "online attack"]):
        reply = (
            "The **Attack Simulator** tests your password against four attack types:\n\n"
            "• **Online Attack** — 10 attempts/sec (throttled login)\n"
            "• **Offline Cracking** — 100,000 attempts/sec (stolen hash)\n"
            "• **GPU Attack** — 10 billion attempts/sec (GPU cluster)\n"
            "• **Dictionary Attack** — wordlist of common passwords\n"
            "• **Hashcat Demo** — live MD5 dictionary crack using the real Hashcat tool\n\n"
            "It calculates theoretical search space, applies weakness penalties, and shows realistic crack times."
        )

    # Strength checker
    elif any(w in msg for w in ["strength checker", "strength check", "password strength", "how does strength"]):
        reply = (
            "The **Password Strength Checker** gives a full security analysis:\n\n"
            "• Scores with zxcvbn + custom AI model\n"
            "• Risk label: Very Weak / Weak / Moderate / Strong / Very Strong\n"
            "• Estimated crack time\n"
            "• Blacklist check (local common passwords)\n"
            "• HIBP breach check (k-anonymity — your full password is never sent)\n"
            "• Gemini AI generates a natural language explanation\n"
            "• Suggests a stronger alternative password"
        )

    # Health score
    elif any(w in msg for w in ["health score", "cyber health", "my score", "security score", "how safe"]):
        reply = (
            "The **Cyber Health Score** rates your account security from 0 to 100 across four pillars:\n\n"
            "• **MFA Status** (25 pts) — is MFA enabled?\n"
            "• **Login Risk** (25 pts) — unusual login activity detected?\n"
            "• **Password Reuse** (25 pts) — same password saved for multiple accounts?\n"
            "• **Tool Engagement** (25 pts) — are you using the security tools regularly?\n\n"
            "You get a grade A–F, a list of detected issues, and specific recommendations."
        )

    # Vault
    elif any(w in msg for w in ["vault", "saved password", "store", "fernet", "encrypt"]):
        reply = (
            "The **Password Vault** stores your passwords securely using **Fernet symmetric encryption**. "
            "Passwords are encrypted before being saved to the database, so raw values are never stored in plaintext.\n\n"
            "Features:\n"
            "• Save generated passwords with a custom label\n"
            "• View and delete saved entries\n"
            "• Detects reused passwords across your accounts"
        )

    # HIBP / breach checker
    elif any(w in msg for w in ["hibp", "have i been pwned", "breach", "checker", "compromised", "leaked", "pwned"]):
        reply = (
            "The **HIBP Checker** tells you if your password has appeared in known data breaches.\n\n"
            "It uses **k-anonymity** to protect your privacy:\n"
            "• Your password is hashed with SHA-1\n"
            "• Only the first 5 characters of the hash are sent to HIBP\n"
            "• The rest is compared locally — your full password never leaves the app\n\n"
            "If found, it shows exactly how many times that password appeared in real breaches."
        )

    # MFA
    elif any(w in msg for w in ["mfa", "two factor", "2fa", "authenticator", "otp", "totp"]):
        reply = (
            "This system **requires MFA for all users** — it cannot be skipped.\n\n"
            "• On first login you scan a QR code with Google Authenticator or Authy\n"
            "• A new 6-digit TOTP code is generated every 30 seconds\n"
            "• You enter this code on every login after your password\n\n"
            "Even if your password is stolen, an attacker can't log in without your phone. "
            "MFA blocks over 99% of automated attacks."
        )

    # Roles
    elif any(w in msg for w in ["role", "admin", "analyst", "permission", "who can", "access"]):
        reply = (
            "CIHE Sentinel AI has three user roles:\n\n"
            "• **Admin** — manages users, sets password policies, views all audit logs and risk dashboard\n"
            "• **Analyst** — monitors failed logins, MFA adoption, compromised password reports\n"
            "• **User** — personal tools: Strength Checker, Generator, Vault, Attack Simulator, Health Score, Chat"
        )

    # Login risk
    elif any(w in msg for w in ["login risk", "risk score", "behaviour", "unusual login", "suspicious"]):
        reply = (
            "**Behaviour-based login risk detection** runs on every login:\n\n"
            "• New IP address → +40 risk points\n"
            "• Unusual login hour (midnight–5am) → +20 risk points\n"
            "• Recent failed attempts → +10 to +30 points\n\n"
            "Risk levels: **Low** (0–29), **Medium** (30–59), **High** (60+). "
            "Admins can see risk levels for all users in the dashboard."
        )

    # Tech stack / Gemini
    elif any(w in msg for w in ["gemini", "tech stack", "built with", "technology", "flask", "python", "how is it built"]):
        reply = (
            "CIHE Sentinel AI is built with:\n\n"
            "• **Python & Flask** — web framework\n"
            "• **SQLite** — database\n"
            "• **Google Gemini** — AI for password advice and this chat\n"
            "• **Hashcat** — real password cracking tool integrated in Attack Simulator\n"
            "• **zxcvbn** — password strength scoring\n"
            "• **HIBP API** — breach database (k-anonymity)\n"
            "• **Fernet encryption** — vault password storage\n"
            "• **PyOTP** — TOTP-based MFA\n"
            "• **Bootstrap + AdminLTE** — frontend"
        )

    # Password tips
    elif any(w in msg for w in ["strong password", "good password", "tips", "advice", "how to make"]):
        reply = (
            "A strong password should be:\n\n"
            "• At least 12 characters (longer = much harder to crack)\n"
            "• Mix of uppercase, lowercase, numbers, and symbols\n"
            "• No names, dates, or keyboard patterns like '123' or 'qwerty'\n"
            "• Unique — never reused across accounts\n\n"
            "Use the **Password Generator** in this system to create one instantly, then save it in your **Vault**."
        )

    # Default
    else:
        reply = (
            "I'm SENTINEL, your cybersecurity assistant for CIHE Sentinel AI. "
            "I know every feature of this system.\n\n"
            "Try asking:\n"
            "• *'What tools does this app have?'*\n"
            "• *'How does Hashcat work here?'*\n"
            "• *'What is my Cyber Health Score?'*\n"
            "• *'How does MFA work?'*"
        )

    return {"reply": reply, "source": "local_fallback", "error": None}
