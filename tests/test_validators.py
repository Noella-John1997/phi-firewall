from phi_firewall.detectors.validators import (aadhaar_valid, luhn_valid, npi_valid, pan_valid,
                                               ssn_valid, verhoeff_check_digit)


def test_luhn():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")


def test_aadhaar_verhoeff():
    base = "23456789012"
    good = base + verhoeff_check_digit(base)
    assert aadhaar_valid(good)
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert not aadhaar_valid(bad)
    assert not aadhaar_valid("1" + good[1:])  # can't start with 0 or 1


def test_ssn_rules():
    assert ssn_valid("123-45-6789")
    assert not ssn_valid("000-45-6789")
    assert not ssn_valid("666-45-6789")
    assert not ssn_valid("900-45-6789")
    assert not ssn_valid("123-00-6789")


def test_pan_and_npi():
    assert pan_valid("ABCPE1234F")
    assert not pan_valid("ABCZE1234F")  # Z is not a valid holder type
    assert npi_valid("1234567893")
    assert not npi_valid("1234567890")
