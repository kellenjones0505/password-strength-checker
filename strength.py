"""Password strength scoring.

Passwords are only ever held in memory while being scored. Nothing in this
module writes a password to disk, a log, or the screen.
"""

import string
from pathlib import Path

COMMON_PASSWORDS_FILE = Path(__file__).with_name("common_passwords.txt")

# Length is the single biggest factor in password strength: every extra
# character multiplies the number of guesses an attacker has to make.
LENGTH_THRESHOLDS = [
    (20, 4, "Fantastic length (20+ characters)."),
    (16, 3, "Great length (16-19 characters)."),
    (12, 2, "Good length (12-15 characters)."),
    (8, 1, "Okay length, but 12+ characters is much stronger."),
]

# Each character class an attacker has to account for enlarges the search space.
CHARACTER_CLASSES = {
    "lowercase letters": set(string.ascii_lowercase),
    "uppercase letters": set(string.ascii_uppercase),
    "digits": set(string.digits),
    "symbols": set(string.punctuation + " "),
}

# The top length tier is worth the most points.
MAX_SCORE = LENGTH_THRESHOLDS[0][1] + len(CHARACTER_CLASSES)

LABELS = [
    (8, "Super strong"),
    (6, "Strong"),
    (4, "Moderate"),
    (2, "Weak"),
    (0, "Very weak"),
]


def load_common_passwords(path=COMMON_PASSWORDS_FILE):
    """Load the wordlist into a set for fast lookups, skipping comments and blanks."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return {line.strip().lower() for line in lines if line.strip() and not line.startswith("#")}


COMMON_PASSWORDS = load_common_passwords()


def base_word(password):
    """Strip the trailing digits/symbols people tack on, e.g. 'Summer2024!' -> 'summer'."""
    return password.lower().rstrip(string.digits + string.punctuation + " ")


def is_common(password):
    """True if the password, or its base word, appears in the common-password list."""
    lowered = password.lower()
    return lowered in COMMON_PASSWORDS or base_word(password) in COMMON_PASSWORDS


def score_length(password):
    """Return (points, feedback) based on password length."""
    for minimum, points, message in LENGTH_THRESHOLDS:
        if len(password) >= minimum:
            return points, message
    return 0, "Too short: use at least 8 characters (12+ recommended)."


def score_variety(password):
    """Return (points, feedback) based on which character classes are present."""
    chars = set(password)
    present = [name for name, members in CHARACTER_CLASSES.items() if chars & members]
    missing = [name for name in CHARACTER_CLASSES if name not in present]

    if missing:
        message = "Consider adding: " + ", ".join(missing) + "."
    else:
        message = "Uses all character types."
    return len(present), message


def label_for(score):
    """Turn a numeric score into a human-readable rating."""
    for minimum, label in LABELS:
        if score >= minimum:
            return label
    return LABELS[-1][1]


def evaluate(password):
    """Score a password and return a summary dict (never includes the password)."""
    # A known password is cracked instantly by a wordlist attack, so nothing
    # else about it matters.
    if is_common(password):
        return {
            "score": 0,
            "max_score": MAX_SCORE,
            "rating": "Very weak",
            "feedback": [
                "This password (or its base word) is on a common-password list. "
                "Attackers try these first, so it would be cracked almost instantly."
            ],
        }

    length_points, length_msg = score_length(password)
    variety_points, variety_msg = score_variety(password)
    score = length_points + variety_points

    return {
        "score": score,
        "max_score": MAX_SCORE,
        "rating": label_for(score),
        "feedback": [length_msg, variety_msg],
    }
