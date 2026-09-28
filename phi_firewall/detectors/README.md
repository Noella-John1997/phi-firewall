# `detectors/` — finding sensitive data

## How detection works

1. **Regex finds candidates** (`patterns.py`). Example: any 12 digits that look like `2345 6789 0124`.
2. **A validator confirms them** (`validators.py`). Example: the Aadhaar number must pass the
   **Verhoeff checksum**. A random 12-digit number passes only ~10% of the time, so false positives drop sharply.
3. **Overlaps are resolved** (`engine.py`). If two detectors match the same characters we keep the
   higher score, then the longer match. That's how `DOB: 04/12/1987` becomes a `DOB` and not a plain `DATE`.

## Checksums in simple words

| Checksum | Used for | Idea |
| --- | --- | --- |
| Luhn | Credit cards, NPI | Double every second digit from the right, add everything, must end in 0 |
| Verhoeff | Aadhaar | Uses a small multiplication table (dihedral group D5) that catches every single-digit typo and every swap of neighbours |
| SSN rules | US SSN | Area can't be 000, 666 or 9xx; group can't be 00; serial can't be 0000 |
| PAN rule | Indian PAN | 4th letter is the holder type (P = person, C = company, …) |

## Adding a detector

Add a `Detector(entity, regex, validator, score, group)` to `DETECTORS` in `patterns.py`, add a
default action for it in `policy/default_policy.yaml`, and write a test.

## Optional: Presidio

`DetectionEngine(use_presidio=True)` adds Microsoft Presidio's NER for names and locations
(`pip install -e ".[presidio]"` and a spaCy model).
