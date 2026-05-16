import math
import re
import string
from zxcvbn import zxcvbn


def get_charset_size(password):
    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)

    return max(charset_size, 1)


def calculate_entropy(password, charset_size):
    if not password:
        return 0
    return round(len(password) * math.log2(charset_size), 2)


def format_duration(seconds):
    if seconds <= 1:
        return "Less than 1 second"
    if seconds < 60:
        return f"{int(seconds)} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} days"
    if seconds < 86400 * 365 * 100:
        return f"{seconds / (86400 * 365):.1f} years"

    return f"{seconds / (86400 * 365 * 100):.1f} centuries"


def detect_patterns(password):
    password_lower = password.lower()
    patterns = []
    severe_patterns = []

    common_words = [
        "password", "admin", "welcome", "qwerty", "letmein",
        "abc123", "iloveyou", "guest", "test", "root"
    ]

    keyboard_patterns = [
        "qwerty", "asdf", "zxcv", "1q2w3e", "12345", "6789"
    ]

    if any(word in password_lower for word in common_words):
        patterns.append("Common dictionary word")
        severe_patterns.append("Common dictionary word")

    if any(pattern in password_lower for pattern in keyboard_patterns):
        patterns.append("Keyboard or number sequence")
        severe_patterns.append("Keyboard or number sequence")

    if re.search(r"(.)\1{2,}", password):
        patterns.append("Repeated characters")
        severe_patterns.append("Repeated characters")

    if re.search(r"(19\d{2}|20\d{2})", password):
        patterns.append("Year pattern")
        severe_patterns.append("Year pattern")

    if re.search(r"\d{3,}$", password):
        patterns.append("Long numeric suffix")
        severe_patterns.append("Long numeric suffix")
    elif re.search(r"\d{2}$", password):
        patterns.append("Short numeric suffix")

    if any(char in password for char in "@0$!"):
        patterns.append("Leetspeak or symbol substitution")

    return patterns, severe_patterns


def classify_resistance(password, zxcvbn_score, blacklist_match, hibp_result, severe_patterns):
    if blacklist_match:
        return "Very Weak"

    if hibp_result and hibp_result.get("found"):
        return "Weak"

    if zxcvbn_score <= 1:
        return "Weak"

    if zxcvbn_score == 2:
        return "Moderate"

    if severe_patterns and len(password) < 14:
        return "Moderate"

    if len(password) >= 14 and zxcvbn_score >= 3:
        return "Very Strong"

    if len(password) >= 12 and zxcvbn_score >= 3:
        return "Strong"

    return "Moderate"


def get_resistance_color(resistance):
    if resistance in ["Very Weak", "Weak"]:
        return "danger"
    if resistance == "Moderate":
        return "warning"
    if resistance == "Strong":
        return "primary"
    return "success"


def get_dictionary_result(blacklist_match, hibp_result, severe_patterns):
    if blacklist_match:
        return {
            "risk": "Very High",
            "estimated_time": "Instantly",
            "description": "This password is in the local blacklist, so a dictionary attacker would likely crack it immediately.",
            "severity": "danger"
        }

    if hibp_result and hibp_result.get("found"):
        return {
            "risk": "High",
            "estimated_time": "Seconds to minutes",
            "description": "This password appears in known breach data, making dictionary attacks more effective.",
            "severity": "danger"
        }

    if severe_patterns:
        return {
            "risk": "Moderate",
            "estimated_time": "Minutes to hours",
            "description": "Some predictable patterns exist, so rule-based dictionary attacks may still be effective.",
            "severity": "warning"
        }

    return {
        "risk": "Low",
        "estimated_time": "Low probability",
        "description": "No major dictionary-style weakness was detected.",
        "severity": "success"
    }


def simulate_password_attack(password, blacklist_match=False, hibp_result=None):
    if hibp_result is None:
        hibp_result = {
            "checked": False,
            "found": False,
            "count": 0,
            "error": None
        }

    zxcvbn_result = zxcvbn(password)
    zxcvbn_score = zxcvbn_result.get("score", 0)

    patterns, severe_patterns = detect_patterns(password)

    charset_size = get_charset_size(password)
    password_length = len(password)
    entropy = calculate_entropy(password, charset_size)

    search_space = charset_size ** max(password_length, 1)
    average_attempts = max(search_space / 2, 1)

    online_rate = 10
    offline_rate = 100_000
    gpu_rate = 10_000_000_000

    online_time = average_attempts / online_rate
    offline_time = average_attempts / offline_rate
    gpu_time = average_attempts / gpu_rate

    overall_resistance = classify_resistance(
        password=password,
        zxcvbn_score=zxcvbn_score,
        blacklist_match=blacklist_match,
        hibp_result=hibp_result,
        severe_patterns=severe_patterns
    )

    resistance_color = get_resistance_color(overall_resistance)

    dictionary_result = get_dictionary_result(
        blacklist_match=blacklist_match,
        hibp_result=hibp_result,
        severe_patterns=severe_patterns
    )

    if overall_resistance in ["Very Weak", "Weak"]:
        summary = (
            "This password shows low survivability against realistic attack models. "
            "Known weaknesses or predictable structures make it easier to crack."
        )
    elif overall_resistance == "Moderate":
        summary = (
            "This password has moderate resistance, but some predictable patterns reduce its real-world strength."
        )
    elif overall_resistance == "Strong":
        summary = (
            "This password demonstrates strong resistance. Minor patterns may exist, but length and character diversity improve protection."
        )
    else:
        summary = (
            "This password demonstrates very strong resistance due to good length, diversity, and low predictability."
        )

    if patterns:
        summary += " Detected patterns: " + ", ".join(patterns) + "."

    scenarios = [
        {
            "title": "Online Attack",
            "icon": "fas fa-globe",
            "description": "Simulates a throttled online attacker limited by login rate controls and account lockout behaviour.",
            "rate_label": "10 attempts/sec",
            "estimated_time": format_duration(online_time),
            "severity": "primary"
        },
        {
            "title": "Offline Cracking",
            "icon": "fas fa-database",
            "description": "Simulates an attacker cracking stolen password hashes on a local machine without online rate limits.",
            "rate_label": "100,000 attempts/sec",
            "estimated_time": format_duration(offline_time),
            "severity": "warning"
        },
        {
            "title": "GPU Attack",
            "icon": "fas fa-microchip",
            "description": "Simulates high-speed GPU-assisted cracking where attackers can test massive volumes of guesses in parallel.",
            "rate_label": "10 billion attempts/sec",
            "estimated_time": format_duration(gpu_time),
            "severity": "danger"
        },
        {
            "title": "Dictionary Attack",
            "icon": "fas fa-book-skull",
            "description": dictionary_result["description"],
            "rate_label": dictionary_result["risk"],
            "estimated_time": dictionary_result["estimated_time"],
            "severity": dictionary_result["severity"]
        }
    ]

    return {
        "password_length": password_length,
        "charset_size": charset_size,
        "entropy": entropy,
        "zxcvbn_score": zxcvbn_score,
        "overall_resistance": overall_resistance,
        "resistance_color": resistance_color,
        "summary": summary,
        "blacklist_match": blacklist_match,
        "hibp_found": hibp_result.get("found", False),
        "hibp_count": hibp_result.get("count", 0),
        "scenarios": scenarios,
        "patterns": patterns,
        "severe_patterns": severe_patterns,
        "rule_based_crack": bool(severe_patterns or blacklist_match)
    }