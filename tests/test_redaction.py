import pytest

from phi_firewall.detectors import DetectionEngine
from phi_firewall.policy import Action, Policy, load_policy
from phi_firewall.redaction import BlockedContent, Redactor, rehydrate

from conftest import NOTE


@pytest.fixture
def redactor():
    return Redactor(DetectionEngine(), load_policy())


def test_detects_all_entities():
    found = {s.entity for s in DetectionEngine().detect(NOTE)}
    assert {"PERSON", "DOB", "MRN", "EMAIL", "PHONE", "AADHAAR", "PAN"} <= found


def test_no_false_positive_on_plain_text():
    assert DetectionEngine().detect("The patient reports mild headache for three days.") == []


def test_dob_wins_over_plain_date():
    spans = DetectionEngine().detect("DOB: 04/12/1987")
    assert [s.entity for s in spans] == ["DOB"]


def test_redact_and_rehydrate_round_trip(redactor):
    res = redactor.redact(NOTE)
    for secret in ["Jane Doe", "jane.doe@gmail.com", "AB123456", "ABCPE1234F"]:
        assert secret not in res.text
    assert "[AADHAAR]" in res.text  # masked, not reversible
    restored = rehydrate(res.text, res.mapping)
    assert "Jane Doe" in restored and "jane.doe@gmail.com" in restored
    assert "2345 6789 0124" not in restored


def test_same_value_same_token_across_messages(redactor):
    mapping, counts = {}, None
    a = redactor.redact("Patient: Jane Doe has asthma.", mapping)
    b = redactor.redact("Patient: Jane Doe needs a refill.", mapping)
    assert "[[PERSON_1]]" in a.text and "[[PERSON_1]]" in b.text
    assert len(mapping) == 1


def test_block_policy_raises(redactor):
    with pytest.raises(BlockedContent):
        redactor.redact("Card 4111 1111 1111 1111 please")


def test_allow_policy_keeps_value():
    r = Redactor(DetectionEngine(), Policy(default=Action.TOKENIZE, entities={"EMAIL": Action.ALLOW}))
    assert "a@b.com" in r.redact("mail a@b.com").text


def test_unknown_tokens_left_alone():
    assert rehydrate("hi [[PERSON_9]]", {"PERSON_1": "Jane"}) == "hi [[PERSON_9]]"
