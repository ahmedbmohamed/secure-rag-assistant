"""Time-based one-time passwords (RFC 6238), the 6-digit codes of Google or Microsoft Authenticator."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def verify(secret: str, code: str, last_used_step: int = -1, now: float | None = None) -> int | None:
    """Return the matched time step, or None.

    One step of clock drift is tolerated either way. A code whose step is not newer than
    `last_used_step` is refused, so a code seen by someone else cannot be replayed.
    """
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == DIGITS):
        return None
    step = current_step(now)
    for candidate in (step - 1, step, step + 1):
        if candidate > last_used_step and hmac.compare_digest(code_at(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret: str, account: str, issuer: str = "Secure RAG") -> str:
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP_SECONDS}"


def qr_svg(uri: str) -> bytes:
    import qrcode
    import qrcode.image.svg

    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return image.to_string()
