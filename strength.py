"""Password strength scoring.

Passwords are only ever held in memory while being scored. Nothing in this
module writes a password to disk, a log, or the screen.
"""

import string

# Length is the single biggest factor in password strength: every extra
# character multiplies the number of guesses an attacker has to make.
LENGTH_THRESHOLDS = [
    (16, 3, "Great length (16+ characters)."),
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

MAX_SCORE = 3 + len(CHARACTER_CLASSES)

LABELS = [
    (6, "Strong"),
    (4, "Moderate"),
    (2, "Weak"),
    (0, "Very weak"),
]


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
    length_points, length_msg = score_length(password)
    variety_points, variety_msg = score_variety(password)
    score = length_points + variety_points

    return {
        "score": score,
        "max_score": MAX_SCORE,
        "rating": label_for(score),
        "feedback": [length_msg, variety_msg],
    }
