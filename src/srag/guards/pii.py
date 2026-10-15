"""Detect and mask personal and sensitive data before anything leaves the machine.

Masking is reversible inside the process: each value is replaced by a placeholder such as
<EMAIL_1>, and the mapping is kept locally so the answer can be shown with the real values.
The mapping itself is never sent anywhere.
"""

import ipaddress
import re
from dataclasses import dataclass, field

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_PHONE = re.compile(r"(?<![\w.+])(?:\(?\+\d{1,3}\)?[ .-]?)?(?:\(?\d{1,3}\)?[ .-]?){2,5}\d{2,4}(?!\w)(?!\.\d)")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_ok(value: str) -> bool:
    s = value.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    number = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(number) % 97 == 1


def _ip_ok(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _phone_ok(value: str) -> bool:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}|\d{2}[/-]\d{2}[/-]\d{4}", value.strip()):
        return False  # a date, not a phone number
    digits = re.sub(r"\D", "", value)
    return 8 <= len(digits) <= 15


# Order matters: the most specific patterns run first so a card number is not taken for a phone.
_DETECTORS = [
    ("EMAIL", _EMAIL, None),
    ("IBAN", _IBAN, _iban_ok),
    ("CARD", _CARD, lambda v: _luhn_ok(re.sub(r"\D", "", v))),
    ("IP", _IPV4, _ip_ok),
    ("PHONE", _PHONE, _phone_ok),
]


@dataclass
class MaskResult:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)  # placeholder -> original value

    @property
    def count(self) -> int:
        return len(self.mapping)

    def types(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for placeholder in self.mapping:
            kind = placeholder.strip("<>").rsplit("_", 1)[0]
            out[kind] = out.get(kind, 0) + 1
        return out


class PiiMasker:
    """Masks values consistently across several texts (question and sources share one mapping)."""

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def mask(self, text: str) -> str:
        for kind, pattern, validator in _DETECTORS:

            def replace(match: re.Match, kind=kind, validator=validator) -> str:
                value = match.group(0)
                if value.startswith("<") or (validator and not validator(value)):
                    return value
                return self._placeholder(kind, value)

            text = pattern.sub(replace, text)
        return text

    def _placeholder(self, kind: str, value: str) -> str:
        key = value.strip()
        if key in self._reverse:
            return self._reverse[key]
        self._counters[kind] = self._counters.get(kind, 0) + 1
        placeholder = f"<{kind}_{self._counters[kind]}>"
        self.mapping[placeholder] = key
        self._reverse[key] = placeholder
        return placeholder

    def unmask(self, text: str) -> str:
        for placeholder, value in self.mapping.items():
            text = text.replace(placeholder, value)
        return text

    def result(self, text: str) -> MaskResult:
        return MaskResult(text=text, mapping=dict(self.mapping))


def mask(text: str) -> MaskResult:
    masker = PiiMasker()
    return masker.result(masker.mask(text))
