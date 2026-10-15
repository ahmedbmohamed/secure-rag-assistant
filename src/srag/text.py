"""Tokenizer shared by the keyword search and the hashing embedder."""

import re

_WORD = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_STOP = set(
    "a an and are as at be by can do does for from how i in is it of on or should the this to what when "
    "which who why with according our we must my me".split()
)


def keywords(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _STOP and len(w) > 1]
