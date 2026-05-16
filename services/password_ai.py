import re
import secrets
import string


COMMON_NAME_PATTERNS = [
    "admin", "user", "test", "guest", "root",
    "nitin", "noshin", "thia", "canberra",
    "password", "welcome", "qwerty"
]

WORD_POOL = [
    "Secure", "Wave", "Falcon", "Ocean", "Tiger",
    "Shield", "Matrix", "Cloud", "Nova", "Stone",
    "Cipher", "Vertex", "Storm", "Rocket", "Orbit"
]

GENERATOR_WORD_POOL = [
    "Wave", "Falcon", "Ocean", "Tiger", "Shield",
    "Matrix", "Cloud", "Nova", "Stone", "Cipher",
    "Storm", "Rocket", "Orbit", "River", "Pixel"
]

LEET_MAP = {
    "a": "@",
    "i": "1",
    "e": "3",
    "o": "0",
    "s": "$",
    "t": "7"
}

def extract_seed_from_input(user_input):
    cleaned = re.sub(r"[^A-Za-z]", "", user_input).strip()

    if not cleaned:
        return secrets.choice(GENERATOR_WORD_POOL)

    cleaned = cleaned[:6]

    chars = list(cleaned.lower())

    for i, ch in enumerate(chars):
        if ch in LEET_MAP and secrets.choice([True, False]):
            chars[i] = LEET_MAP[ch]

    seed = "".join(chars)

    if seed:
        seed = seed[0].upper() + seed[1:]

    return seed


def generate_memorable_password_from_input(user_input, policy=None):
    seed_word = extract_seed_from_input(user_input)

    second_word = secrets.choice(GENERATOR_WORD_POOL)
    while second_word.lower() in seed_word.lower():
        second_word = secrets.choice(GENERATOR_WORD_POOL)

    symbol = secrets.choice("!@#$%^&*")
    digits = "".join(secrets.choice(string.digits) for _ in range(2))

    password_chars = list(f"{seed_word}{second_word}{symbol}{digits}")

    if policy:
        if policy.require_upper and not any(c.isupper() for c in password_chars):
            password_chars.append(secrets.choice(string.ascii_uppercase))
        if policy.require_lower and not any(c.islower() for c in password_chars):
            password_chars.append(secrets.choice(string.ascii_lowercase))
        if policy.require_digit and not any(c.isdigit() for c in password_chars):
            password_chars.append(secrets.choice(string.digits))
        if policy.require_symbol and not any(c in string.punctuation for c in password_chars):
            password_chars.append(secrets.choice("!@#$%^&*"))

        min_length = max(policy.min_length, 12)
    else:
        min_length = 12

    filler = string.ascii_letters + string.digits + "!@#$%^&*"

    while len(password_chars) < min_length:
        password_chars.append(secrets.choice(filler))

    return "".join(password_chars)


def extract_password_features(password):
    password_lower = password.lower()

    length = len(password)
    upper_count = sum(1 for c in password if c.isupper())
    lower_count = sum(1 for c in password if c.islower())
    digit_count = sum(1 for c in password if c.isdigit())
    symbol_count = sum(1 for c in password if c in string.punctuation)
    unique_count = len(set(password))

    has_upper = upper_count > 0
    has_lower = lower_count > 0
    has_digit = digit_count > 0
    has_symbol = symbol_count > 0

    repeated_chars = bool(re.search(r"(.)\1{2,}", password))
    common_name_found = any(name in password_lower for name in COMMON_NAME_PATTERNS)
    sequence_found = contains_sequence(password_lower)
    year_pattern_found = bool(re.search(r"(19\d{2}|20\d{2})", password))
    common_suffix_digits = bool(re.search(r"\d{2,}$", password))

    char_types_used = sum([has_upper, has_lower, has_digit, has_symbol])

    return {
        "length": length,
        "upper_count": upper_count,
        "lower_count": lower_count,
        "digit_count": digit_count,
        "symbol_count": symbol_count,
        "unique_count": unique_count,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "char_types_used": char_types_used,
        "repeated_chars": repeated_chars,
        "common_name_found": common_name_found,
        "sequence_found": sequence_found,
        "year_pattern_found": year_pattern_found,
        "common_suffix_digits": common_suffix_digits
    }


def contains_sequence(password_lower):
    sequences = [
        "0123456789",
        "1234567890",
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]

    for seq in sequences:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in password_lower:
                return True
    return False


def get_base_crack_time(zxcvbn_result):
    crack_times = zxcvbn_result.get("crack_times_display", {})
    return (
        crack_times.get("offline_fast_hashing_1e10_per_second")
        or crack_times.get("offline_slow_hashing_1e4_per_second")
        or "Unknown"
    )


def adjust_crack_time(base_time, blacklist_match, hibp_result, features):
    if blacklist_match:
        return "Instantly"

    if hibp_result and hibp_result.get("found"):
        return "Less than 1 minute"

    lowered = base_time.lower()

    if features["common_name_found"] and features["year_pattern_found"]:
        if "centur" in lowered or "year" in lowered:
            return "Hours to days"

    if features["sequence_found"] and features["common_suffix_digits"]:
        if "centur" in lowered or "year" in lowered or "month" in lowered:
            return "Minutes to hours"

    if features["length"] < 10:
        if "centur" in lowered or "year" in lowered:
            return "Hours to days"

    return base_time


def classify_risk_level(zxcvbn_score, blacklist_match, hibp_result, features):
    if blacklist_match:
        return "Very Weak"

    if hibp_result and hibp_result.get("found"):
        return "Weak"

    if zxcvbn_score == 0:
        return "Very Weak"
    if zxcvbn_score == 1:
        return "Weak"
    if zxcvbn_score == 2:
        return "Moderate"

    if zxcvbn_score >= 3:
        if features["common_name_found"] or features["year_pattern_found"] or features["sequence_found"]:
            return "Moderate"
        if features["length"] >= 14 and features["char_types_used"] == 4:
            return "Very Strong"
        return "Strong"

    return "Moderate"


def build_risk_reasons(features, policy_errors, blacklist_match, hibp_result, zxcvbn_result):
    reasons = []

    if blacklist_match:
        reasons.append("This password appears in the local blacklist of common passwords.")

    if hibp_result and hibp_result.get("found"):
        reasons.append(
            f"This password appears in known data breaches ({hibp_result.get('count', 0)} exposures)."
        )

    warning = zxcvbn_result.get("feedback", {}).get("warning")
    suggestions = zxcvbn_result.get("feedback", {}).get("suggestions", [])

    if warning:
        reasons.append(warning)

    for item in suggestions:
        if item not in reasons:
            reasons.append(item)

    if features["common_name_found"]:
        reasons.append("The password contains a common name or word pattern.")

    if features["sequence_found"]:
        reasons.append("The password contains a predictable keyboard or number sequence.")

    if features["common_suffix_digits"]:
        reasons.append("The password ends with predictable numeric digits.")

    if features["year_pattern_found"]:
        reasons.append("The password includes a common year pattern.")

    if features["repeated_chars"]:
        reasons.append("The password contains repeated characters, which reduces unpredictability.")

    if features["length"] < 10:
        reasons.append("The password is relatively short and easier to guess or brute-force.")

    if not features["has_symbol"]:
        reasons.append("Adding a symbol would improve password complexity.")

    if not features["has_upper"]:
        reasons.append("Adding an uppercase letter would improve password complexity.")

    if not features["has_digit"]:
        reasons.append("Adding a digit would improve password complexity.")

    for error in policy_errors:
        if error not in reasons:
            reasons.append(error)

    deduped = []
    for reason in reasons:
        if reason and reason not in deduped:
            deduped.append(reason)

    if not deduped:
        deduped.append("No major weakness patterns were detected.")

    return deduped


def generate_suggested_password(policy=None):
    first_word = secrets.choice(WORD_POOL)
    second_word = secrets.choice([word for word in WORD_POOL if word != first_word])

    digit_part = "".join(secrets.choice(string.digits) for _ in range(2))
    symbol_part = secrets.choice("!@#$%^&*")
    extra_symbol = secrets.choice("!@#$%^&*")
    extra_upper = secrets.choice(string.ascii_uppercase)
    extra_lower = secrets.choice(string.ascii_lowercase)

    password_chars = list(
        f"{first_word}{symbol_part}{second_word}{extra_symbol}{digit_part}{extra_upper}{extra_lower}"
    )

    if policy:
        if policy.require_upper and not any(c.isupper() for c in password_chars):
            password_chars.append(secrets.choice(string.ascii_uppercase))
        if policy.require_lower and not any(c.islower() for c in password_chars):
            password_chars.append(secrets.choice(string.ascii_lowercase))
        if policy.require_digit and not any(c.isdigit() for c in password_chars):
            password_chars.append(secrets.choice(string.digits))
        if policy.require_symbol and not any(c in string.punctuation for c in password_chars):
            password_chars.append(secrets.choice("!@#$%^&*"))

        min_length = max(policy.min_length, 14)
    else:
        min_length = 14

    all_chars = string.ascii_letters + string.digits + "!@#$%^&*"

    while len(password_chars) < min_length:
        password_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def estimate_suggested_crack_time(suggested_password):
    length = len(suggested_password)
    has_upper = any(c.isupper() for c in suggested_password)
    has_lower = any(c.islower() for c in suggested_password)
    has_digit = any(c.isdigit() for c in suggested_password)
    has_symbol = any(c in string.punctuation for c in suggested_password)

    if length >= 16 and has_upper and has_lower and has_digit and has_symbol:
        return "Centuries"
    if length >= 14 and has_upper and has_lower and has_digit and has_symbol:
        return "Decades to centuries"
    if length >= 12 and has_upper and has_lower and has_digit:
        return "Years to decades"
    return "Months to years"


def predict_password_strength(password, zxcvbn_result, policy_errors=None, hibp_result=None, blacklist_match=False, policy=None):
    if policy_errors is None:
        policy_errors = []

    if hibp_result is None:
        hibp_result = {
            "checked": False,
            "found": False,
            "count": 0,
            "error": None
        }

    features = extract_password_features(password)
    base_crack_time = get_base_crack_time(zxcvbn_result)
    adjusted_crack_time = adjust_crack_time(
        base_time=base_crack_time,
        blacklist_match=blacklist_match,
        hibp_result=hibp_result,
        features=features
    )

    risk_label = classify_risk_level(
        zxcvbn_score=zxcvbn_result.get("score", 0),
        blacklist_match=blacklist_match,
        hibp_result=hibp_result,
        features=features
    )

    reasons = build_risk_reasons(
        features=features,
        policy_errors=policy_errors,
        blacklist_match=blacklist_match,
        hibp_result=hibp_result,
        zxcvbn_result=zxcvbn_result
    )

    suggested_password = generate_suggested_password(policy=policy)
    suggested_crack_time = estimate_suggested_crack_time(suggested_password)

    return {
        "risk_label": risk_label,
        "estimated_crack_time": adjusted_crack_time,
        "reasons": reasons,
        "suggested_password": suggested_password,
        "suggested_crack_time": suggested_crack_time,
        "features": features
    }