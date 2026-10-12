# Password Strength Checker

A command-line tool that rates how strong a password is and shows, side by side,
how that password would be stored using **SHA-256** versus **bcrypt**, with a
live speed test that shows why bcrypt is the right choice for passwords.

Built as a cybersecurity portfolio project to demonstrate secure password
handling, attacker-informed strength checks, and password-hashing best practices.

## Features

- **Strength scoring** (0–7) based on length and character variety, with
  specific tips for improvement
- **Common-password detection** against a wordlist, including variations like
  `Summer2024!` (base word `summer` plus a predictable suffix)
- **Hashing comparison**: shows SHA-256 and bcrypt hashes of the same password,
  shows why salting matters, and measures how many guesses per second
  each algorithm allows on your own machine
- **Privacy by design**: passwords are typed with hidden input and are never
  displayed, saved, logged, or passed on the command line

## Getting started

Requires Python 3.9+.

```bash
git clone https://github.com/kellenjones0505/password-strength-checker.git
cd password-strength-checker

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

Type a password (your typing stays hidden) and press Enter. Press Enter on an
empty line to quit. **Use made-up passwords. Don't type real credentials into tools you're testing.**

### Example output

```
Strength: Strong  [#######] 7/7
  - Great length (16+ characters).
  - Uses all character types.

How this password would be stored:

  SHA-256 (fast, unsalted -- NOT suitable for passwords)
    hash #1: c707e34f3723a4c7c554d8c3d4a72c841142f2b5afd1e72178c1c099d67dd4d1
    hash #2: c707e34f3723a4c7c554d8c3d4a72c841142f2b5afd1e72178c1c099d67dd4d1
    Same password -> same hash, so precomputed lookup tables work against it.

  bcrypt (slow, salted, cost factor 12)
    hash #1: $2b$12$ZKwEqm4kl90CuTF/Gf8rauhLyr3jfKUlA/Tbi.S41hMLKYe0Z.AKu
    hash #2: $2b$12$vZ2PS8fxnsV9OrvKkfpbuOsN86ljXJdZwZkpgGx5M3LgF7oMGJOeG
    A new random salt each time -> different hashes, yet both verify: True

  Guessing speed on this computer:
    SHA-256: ~1,498,954 guesses/second
    bcrypt:  ~5.3 guesses/second
    bcrypt makes a brute-force attack ~283,539x slower.
```

### Running the tests

```bash
python -m unittest -v
```

## Security concepts demonstrated

### 1. Why length and variety matter
The number of possible passwords an attacker must try grows exponentially with
length, and multiplies with each character type (lowercase, uppercase, digits,
symbols) that might appear. Length is the bigger factor: adding characters helps
more than adding complexity.

### 2. Dictionary attacks beat complexity
Attackers don't guess randomly. They start with **wordlists** of real passwords
from data breaches, plus rules that add common variations (capitalising the
first letter, swapping `a`→`@`, appending a year or `!`). A password like
`P@ssw0rd` or `Summer2024!` looks complex but falls almost instantly, so this tool
scores any password on the list as **Very weak**, no matter its length or symbols.

### 3. Hashing, not encryption
Systems should never store passwords in a form that can be reversed. They store a
**hash**, a one-way fingerprint. At login, the system hashes what you typed and
compares. If the database leaks, attackers get hashes and must guess passwords one
at a time.

### 4. Why SHA-256 is the wrong tool for passwords
- **It's too fast.** SHA-256 is designed for checking files and data quickly.
  GPUs compute billions of SHA-256 hashes per second, so a leaked database can be
  attacked with huge wordlists in minutes.
- **It's unsalted.** The same password always produces the same hash, so attackers
  can use precomputed **rainbow tables**, and users with the same password are
  easy to spot.

### 5. Why bcrypt is better
- **Deliberately slow:** in this demo, roughly 280,000× fewer guesses per second
  than SHA-256 on the same machine.
- **Tunable cost factor:** each +1 doubles the work, so it can be raised as
  hardware gets faster.
- **Built-in random salt:** stored inside the hash itself
  (`$2b$<cost>$<22-char salt><hash>`), so identical passwords produce different
  hashes and rainbow tables don't work.

### 6. Secure handling of sensitive input
- Input is read with `getpass`, so it's never shown on screen.
- Passwords are never accepted as command-line arguments, which would end up in
  shell history and process listings.
- Nothing is written to disk or logged, and tests check that the
  password never appears in the program's output.

## Limitations

- Rule-based scoring underrates long passphrases such as
  `correct horse battery staple`, which are strong in practice. Estimators like
  [zxcvbn](https://github.com/dropbox/zxcvbn) model this better.
- The bundled wordlist is a small sample. Real-world use would check against
  larger lists (e.g. [SecLists](https://github.com/danielmiessler/SecLists)) or
  the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) k-anonymity API.
- bcrypt only uses the first 72 bytes of a password. Longer passwords are
  rejected for the hash demo rather than silently truncated.
- Python strings can't be securely wiped from memory, so the password stays
  in RAM until Python's garbage collector frees it.
- Modern systems often prefer **Argon2id**, the winner of the Password Hashing
  Competition, which is also memory-hard. bcrypt is used here because it's still
  widely deployed and easy to understand.

## Project structure

```
main.py                  Interactive CLI (hidden input, report formatting)
strength.py              Length, variety, and common-password scoring
hashing.py               SHA-256 vs bcrypt hashing and speed comparison
common_passwords.txt     Sample wordlist of common passwords
tests/                   Unit tests (unittest)
requirements.txt         Python dependencies
```
