"""Interactive password strength checker.

Run with:  python main.py

Passwords are read with getpass, so they are never shown on screen, never
passed on the command line (where they'd land in shell history), and never
written to disk or logged.
"""

from getpass import getpass

from hashing import BCRYPT_MAX_BYTES, BCRYPT_ROUNDS, compare
from strength import evaluate


def format_report(result):
    """Build the strength section of the report from an evaluate() result."""
    filled = "#" * result["score"]
    empty = "-" * (result["max_score"] - result["score"])
    lines = [
        f"Strength: {result['rating']}  [{filled}{empty}] {result['score']}/{result['max_score']}",
    ]
    lines += [f"  - {tip}" for tip in result["feedback"]]
    return "\n".join(lines)


def format_hashing(result):
    """Build the hashing-comparison section of the report from a compare() result."""
    sha_first, sha_second = result["sha256"]
    bcrypt_first, bcrypt_second = result["bcrypt"]
    slowdown = result["sha256_per_second"] / result["bcrypt_per_second"]

    return "\n".join([
        "How this password would be stored:",
        "",
        "  SHA-256 (fast, unsalted -- NOT suitable for passwords)",
        f"    hash #1: {sha_first}",
        f"    hash #2: {sha_second}",
        "    Same password -> same hash, so precomputed lookup tables work against it.",
        "",
        f"  bcrypt (slow, salted, cost factor {BCRYPT_ROUNDS})",
        f"    hash #1: {bcrypt_first}",
        f"    hash #2: {bcrypt_second}",
        "    A new random salt each time -> different hashes, yet both verify: "
        f"{result['bcrypt_verifies']}",
        "",
        "  Guessing speed on this computer:",
        f"    SHA-256: ~{result['sha256_per_second']:,.0f} guesses/second",
        f"    bcrypt:  ~{result['bcrypt_per_second']:,.1f} guesses/second",
        f"    bcrypt makes a brute-force attack ~{slowdown:,.0f}x slower.",
    ])


def check(password):
    """Return the full report for one password."""
    sections = [format_report(evaluate(password))]
    try:
        sections.append(format_hashing(compare(password)))
    except ValueError:
        sections.append(
            f"(Hash demo skipped: bcrypt only supports passwords up to {BCRYPT_MAX_BYTES} bytes.)"
        )
    return "\n\n".join(sections)


def main():
    print("Password Strength Checker")
    print("Your typing is hidden and nothing you enter is saved.")
    print("Press Enter on an empty line to quit.\n")

    while True:
        password = getpass("Password to check: ")
        if not password:
            print("Goodbye.")
            break
        print()
        print(check(password))
        print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye.")
