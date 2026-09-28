"""Checksum validators. They cut false positives: a random 12-digit number is
very unlikely to pass the Aadhaar Verhoeff check."""
from __future__ import annotations

# --- Luhn (credit cards, NPI) ----------------------------------------------

def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def npi_valid(npi: str) -> bool:
    """US National Provider Identifier: Luhn over '80840' + the 10 digits."""
    digits = "".join(c for c in npi if c.isdigit())
    return len(digits) == 10 and luhn_valid("80840" + digits)


# --- Verhoeff (Aadhaar) ----------------------------------------------------
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed([d for d in number if d.isdigit()])):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    """Compute the check digit to append (used to build valid test data)."""
    c = 0
    for i, ch in enumerate(reversed([d for d in number if d.isdigit()])):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def aadhaar_valid(number: str) -> bool:
    digits = "".join(c for c in number if c.isdigit())
    return len(digits) == 12 and digits[0] not in "01" and verhoeff_valid(digits)


# --- US SSN ----------------------------------------------------------------

def ssn_valid(ssn: str) -> bool:
    digits = "".join(c for c in ssn if c.isdigit())
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


# --- Indian PAN ------------------------------------------------------------
PAN_HOLDER_TYPES = set("ABCFGHLJPT")  # 4th character: P = person, C = company, ...


def pan_valid(pan: str) -> bool:
    return len(pan) == 10 and pan[3].upper() in PAN_HOLDER_TYPES
