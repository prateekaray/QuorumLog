"""
QuorumLog — crypto.py

Canonical JSON hashing, Ed25519 signing (PyNaCl), Hashcash-style proof-of-work,
and fully-offline verification of Entries, Receipts, Bundles and FraudProofs.

Conventions (all deterministic, zero network calls needed to verify):

  entry_hash   = SHA256(canonical_json(entry minus "sig"))       # covers pow_nonce
  PoW          = SHA256((pow_anchor + str(pow_nonce)).encode())  # >= D leading zero bits
                 where pow_anchor = entry_hash, EXCEPT for KEY_ROTATE entries where
                 it is the recovery-unsigned hash (the recovery_sig lives inside the
                 payload and can only be added after grinding — this breaks the
                 circular dependency; the anchor is still a full-content hash).
  entry.sig    = Ed25519_sign(author_sk,  bytes.fromhex(entry_hash))
  KEY_ROTATE   = dual-signed: payload["recovery_sig"] = Ed25519_sign(recovery_sk,
                   bytes.fromhex(SHA256(canonical(entry minus "sig",
                                                    payload.recovery_sig = ""))))
                 plus the normal author signature over the final entry_hash.
  receipt_hash = SHA256(canonical_json(receipt minus "sig"))
  receipt.sig  = Ed25519_sign(witness_sk, bytes.fromhex(receipt_hash))

No custom crypto: only PyNaCl (Ed25519) and stdlib hashlib (SHA-256).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

ZERO_HASH = "0" * 64
DEFAULT_DIFFICULTY = 14          # leading zero bits required by PoW
DEFAULT_K = 5                    # quorum threshold
ENTRY_TYPES = ("GENESIS", "TRANSFER", "ACCEPT", "ATTEST", "KEY_ROTATE")
SIG_HEX_LEN = 128                # Ed25519 signature = 64 bytes
MAX_TERMS_LEN = 4096
MAX_NAME_LEN = 64
MAX_NOTE_LEN = 256
MAX_CLAIM_LEN = 1024
MAX_ASSET_LEN = 128
FUTURE_SKEW_S = 300.0
HEX_DIGITS = set("0123456789abcdef")


class CryptoError(ValueError):
    """Canonicalization failure or unusable key material."""


# --------------------------------------------------------------------------
# Hashing / serialization
# --------------------------------------------------------------------------

def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, tight separators, UTF-8, NaN/Inf rejected."""
    try:
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise CryptoError(f"object is not canonically serializable: {exc}") from exc
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX_DIGITS


def is_sig_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) == SIG_HEX_LEN and set(value) <= HEX_DIGITS


def leading_zero_bits(digest: bytes) -> int:
    value = int.from_bytes(digest, "big")
    return len(digest) * 8 - value.bit_length() if value else len(digest) * 8


def pubkey_to_node_id(pubkey_hex: str) -> str:
    """256-bit Kademlia node id = SHA256(32-byte Ed25519 public key)."""
    return sha256_hex(bytes.fromhex(pubkey_hex))


# --------------------------------------------------------------------------
# Keys and identity files (0600 permissions)
# --------------------------------------------------------------------------

def create_keypair() -> tuple[SigningKey, str]:
    sk = SigningKey.generate()
    return sk, sk.verify_key.encode().hex()


def sign_digest(sk: SigningKey, digest_hex: str) -> str:
    return sk.sign(bytes.fromhex(digest_hex)).signature.hex()


def verify_digest(pubkey_hex: str, digest_hex: str, sig_hex: str) -> bool:
    try:
        VerifyKey(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(digest_hex), bytes.fromhex(sig_hex))
        return True
    except (BadSignatureError, ValueError):
        return False


@dataclass
class Identity:
    sk: SigningKey
    pubkey: str
    recovery_sk: SigningKey
    recovery_pubkey: str

    @property
    def node_id(self) -> str:
        return pubkey_to_node_id(self.pubkey)


def create_identity() -> Identity:
    sk, pub = create_keypair()
    rsk, rpub = create_keypair()
    return Identity(sk=sk, pubkey=pub, recovery_sk=rsk, recovery_pubkey=rpub)


def save_key_file(path: str, data: dict) -> None:
    """Atomic JSON write with 0600 permissions (key material)."""
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def load_key_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise CryptoError(f"key file {path} is not a JSON object")
    return data


def save_identity(dir_path: str, identity: Identity) -> None:
    os.makedirs(dir_path, exist_ok=True)
    save_key_file(os.path.join(dir_path, "identity.json"),
                  {"pubkey": identity.pubkey, "seed": identity.sk.encode().hex()})
    save_key_file(os.path.join(dir_path, "recovery_key.json"),
                  {"pubkey": identity.recovery_pubkey, "seed": identity.recovery_sk.encode().hex()})


def load_identity(dir_path: str) -> Identity:
    main = load_key_file(os.path.join(dir_path, "identity.json"))
    rec = load_key_file(os.path.join(dir_path, "recovery_key.json"))
    sk = SigningKey(bytes.fromhex(main["seed"]))
    rsk = SigningKey(bytes.fromhex(rec["seed"]))
    identity = Identity(sk=sk, pubkey=sk.verify_key.encode().hex(),
                        recovery_sk=rsk, recovery_pubkey=rsk.verify_key.encode().hex())
    if main.get("pubkey") != identity.pubkey or rec.get("pubkey") != identity.recovery_pubkey:
        raise CryptoError("key files do not match their recorded public keys")
    return identity


def identity_exists(dir_path: str) -> bool:
    return os.path.exists(os.path.join(dir_path, "identity.json"))


# --------------------------------------------------------------------------
# Entry
# --------------------------------------------------------------------------

@dataclass
class Entry:
    author: str                # 64-hex Ed25519 public key of the chain owner
    seq: int                   # monotonically increasing per author, >= 0
    prev_hash: str             # hash of the author's previous entry (ZERO_HASH for fresh genesis)
    timestamp: float           # unix seconds
    type: str                  # GENESIS | TRANSFER | ACCEPT | ATTEST | KEY_ROTATE
    payload: dict
    pow_nonce: int = 0
    sig: str = ""              # Ed25519 by author (or recovery key semantics, see above)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Any) -> "Entry":
        if not isinstance(data, dict):
            raise CryptoError("entry must be a JSON object")
        fields = {"author", "seq", "prev_hash", "timestamp", "type",
                  "payload", "pow_nonce", "sig"}
        if set(data) != fields:
            raise CryptoError("entry field set mismatch")
        entry = cls(author=data["author"], seq=data["seq"], prev_hash=data["prev_hash"],
                    timestamp=data["timestamp"], type=data["type"], payload=data["payload"],
                    pow_nonce=data["pow_nonce"], sig=data["sig"])
        _validate_entry_shape(entry)
        return entry

    def signing_dict(self) -> dict:
        data = self.to_dict()
        data.pop("sig")
        return data

    @property
    def entry_hash(self) -> str:
        return sha256_hex(canonical_json(self.signing_dict()))


def _validate_entry_shape(entry: Entry) -> None:
    if not is_hex64(entry.author):
        raise CryptoError("author must be a 64-hex public key")
    if isinstance(entry.seq, bool) or not isinstance(entry.seq, int) or entry.seq < 0:
        raise CryptoError("seq must be an int >= 0")
    if not is_hex64(entry.prev_hash):
        raise CryptoError("prev_hash must be 64-hex")
    if (isinstance(entry.timestamp, bool) or not isinstance(entry.timestamp, (int, float))
            or not math.isfinite(entry.timestamp) or entry.timestamp <= 0):
        raise CryptoError("timestamp must be a finite positive unix timestamp")
    if entry.type not in ENTRY_TYPES:
        raise CryptoError(f"unknown entry type: {entry.type!r}")
    if not isinstance(entry.payload, dict):
        raise CryptoError("payload must be a JSON object")
    if isinstance(entry.pow_nonce, bool) or not isinstance(entry.pow_nonce, int) or entry.pow_nonce < 0:
        raise CryptoError("pow_nonce must be an int >= 0")
    if not is_sig_hex(entry.sig):
        raise CryptoError("sig must be a 128-hex Ed25519 signature")


def _check_payload(entry_type: str, payload: dict) -> Optional[str]:
    keys = set(payload)
    if entry_type == "GENESIS":
        allowed = {"recovery_pubkey", "name", "rotated_from"}
        if "recovery_pubkey" not in keys or not keys <= allowed:
            return "genesis payload needs recovery_pubkey (name/rotated_from optional)"
        if not is_hex64(payload["recovery_pubkey"]):
            return "genesis recovery_pubkey must be 64-hex"
        name = payload.get("name")
        if name is not None and (not isinstance(name, str) or not (1 <= len(name) <= MAX_NAME_LEN)):
            return "genesis name must be a string of 1..64 chars"
        rot = payload.get("rotated_from")
        if rot is not None and not is_hex64(rot):
            return "genesis rotated_from must be 64-hex"
    elif entry_type == "TRANSFER":
        if keys != {"asset", "to", "terms"}:
            return "transfer payload must be exactly {asset, to, terms}"
        asset = payload["asset"]
        if not isinstance(asset, str) or not (1 <= len(asset) <= MAX_ASSET_LEN):
            return f"asset must be a string of 1..{MAX_ASSET_LEN} chars"
        if not is_hex64(payload["to"]):
            return "transfer recipient must be a 64-hex public key"
        terms = payload["terms"]
        if not isinstance(terms, str) or not (1 <= len(terms) <= MAX_TERMS_LEN):
            return f"terms must be a string of 1..{MAX_TERMS_LEN} chars"
    elif entry_type == "ACCEPT":
        if keys not in ({"entry_hash"}, {"entry_hash", "note"}):
            return "accept payload must be {entry_hash} with optional note"
        if not is_hex64(payload["entry_hash"]):
            return "accept entry_hash must be 64-hex"
        note = payload.get("note")
        if note is not None and (not isinstance(note, str) or len(note) > MAX_NOTE_LEN):
            return f"accept note must be at most {MAX_NOTE_LEN} chars"
    elif entry_type == "ATTEST":
        if keys != {"subject", "claim"}:
            return "attest payload must be exactly {subject, claim}"
        if not is_hex64(payload["subject"]):
            return "attest subject must be a 64-hex public key"
        claim = payload["claim"]
        if not isinstance(claim, str) or not (1 <= len(claim) <= MAX_CLAIM_LEN):
            return f"claim must be a string of 1..{MAX_CLAIM_LEN} chars"
    else:  # KEY_ROTATE
        if keys != {"new_pubkey", "recovery_pubkey", "recovery_sig"}:
            return "key-rotate payload must be exactly {new_pubkey, recovery_pubkey, recovery_sig}"
        if not is_hex64(payload["new_pubkey"]) or not is_hex64(payload["recovery_pubkey"]):
            return "rotation keys must be 64-hex"
        if not is_sig_hex(payload["recovery_sig"]):
            return "recovery_sig must be a 128-hex signature"
    return None


# --------------------------------------------------------------------------
# Proof of work (Hashcash-style, anti-spam only — not a blockchain)
# --------------------------------------------------------------------------

def pow_target_ok(entry_hash_hex: str, nonce: int, difficulty: int) -> bool:
    digest = hashlib.sha256(f"{entry_hash_hex}{nonce}".encode("ascii")).digest()
    return leading_zero_bits(digest) >= difficulty


def mine_pow(entry: Entry, difficulty: int, max_nonce: int = 1 << 32) -> int:
    """Grind pow_nonce in place until SHA256(pow_anchor + nonce) has D leading
    zero bits. For KEY_ROTATE the anchor is the recovery-unsigned hash."""
    data = entry.signing_dict()
    if entry.type == "KEY_ROTATE":
        payload = dict(entry.payload)
        payload["recovery_sig"] = ""
        data["payload"] = payload
    for nonce in range(max_nonce):
        data["pow_nonce"] = nonce
        if pow_target_ok(sha256_hex(canonical_json(data)), nonce, difficulty):
            entry.pow_nonce = nonce
            return nonce
    raise CryptoError("proof-of-work space exhausted")


# --------------------------------------------------------------------------
# Signing / verification
# --------------------------------------------------------------------------

def sign_entry(entry: Entry, sk: SigningKey) -> str:
    entry.sig = ""
    entry.sig = sign_digest(sk, entry.entry_hash)
    return entry.sig


def _recovery_unsigned_hash(entry: Entry) -> str:
    """entry_hash of the entry with payload.recovery_sig cleared (for KEY_ROTATE)."""
    data = entry.signing_dict()
    payload = dict(entry.payload)
    payload["recovery_sig"] = ""
    data["payload"] = payload
    return sha256_hex(canonical_json(data))


def verify_entry(entry: Entry, difficulty: int = DEFAULT_DIFFICULTY,
                 now: Optional[float] = None) -> tuple[bool, str]:
    """Full offline validation: shape -> payload schema -> recovery sig -> PoW -> author sig."""
    try:
        _validate_entry_shape(entry)
    except CryptoError as exc:
        return False, str(exc)
    if now is not None and entry.timestamp > now + FUTURE_SKEW_S:
        return False, "timestamp too far in the future"
    reason = _check_payload(entry.type, entry.payload)
    if reason:
        return False, reason
    if entry.type == "GENESIS":
        if entry.seq != 0:
            return False, "genesis must have seq 0"
        rotated = "rotated_from" in entry.payload
        if rotated and entry.prev_hash == ZERO_HASH:
            return False, "rotated genesis needs a real prev_hash"
        if not rotated and entry.prev_hash != ZERO_HASH:
            return False, "genesis prev_hash must be all zeros"
        if entry.payload["recovery_pubkey"] == entry.author:
            return False, "recovery key must differ from author key"
    if entry.type == "KEY_ROTATE":
        if entry.payload["new_pubkey"] == entry.author:
            return False, "new key must differ from current key"
        if entry.payload["recovery_pubkey"] == entry.author:
            return False, "recovery key must differ from author key"
        h0 = _recovery_unsigned_hash(entry)
        if not verify_digest(entry.payload["recovery_pubkey"], h0, entry.payload["recovery_sig"]):
            return False, "recovery-key signature invalid"
        if not pow_target_ok(h0, entry.pow_nonce, difficulty):
            return False, "insufficient proof-of-work"
    else:
        entry_hash = entry.entry_hash
        if not pow_target_ok(entry_hash, entry.pow_nonce, difficulty):
            return False, "insufficient proof-of-work"
    if not verify_digest(entry.author, entry.entry_hash, entry.sig):
        return False, "author signature invalid"
    return True, "ok"


# --------------------------------------------------------------------------
# Receipt / Bundle / FraudProof + offline verification
# --------------------------------------------------------------------------

@dataclass
class Receipt:
    entry_hash: str
    author: str
    seq: int
    witness: str               # 64-hex pubkey of the witness that signed
    seen_at: float
    sig: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Any) -> "Receipt":
        if not isinstance(data, dict) or set(data) != {
                "entry_hash", "author", "seq", "witness", "seen_at", "sig"}:
            raise CryptoError("receipt field set mismatch")
        receipt = cls(entry_hash=data["entry_hash"], author=data["author"], seq=data["seq"],
                      witness=data["witness"], seen_at=data["seen_at"], sig=data["sig"])
        if not is_hex64(receipt.entry_hash) or not is_hex64(receipt.author) \
                or not is_hex64(receipt.witness):
            raise CryptoError("receipt hex fields invalid")
        if isinstance(receipt.seq, bool) or not isinstance(receipt.seq, int) or receipt.seq < 0:
            raise CryptoError("receipt seq invalid")
        if (isinstance(receipt.seen_at, bool) or not isinstance(receipt.seen_at, (int, float))
                or not math.isfinite(receipt.seen_at) or receipt.seen_at <= 0):
            raise CryptoError("receipt seen_at invalid")
        if not is_sig_hex(receipt.sig):
            raise CryptoError("receipt sig invalid")
        return receipt

    def signing_dict(self) -> dict:
        data = self.to_dict()
        data.pop("sig")
        return data

    @property
    def receipt_hash(self) -> str:
        return sha256_hex(canonical_json(self.signing_dict()))


def sign_receipt(receipt: Receipt, sk: SigningKey) -> str:
    receipt.sig = ""
    receipt.sig = sign_digest(sk, receipt.receipt_hash)
    return receipt.sig


def verify_receipt(receipt: Receipt) -> tuple[bool, str]:
    if not verify_digest(receipt.witness, receipt.receipt_hash, receipt.sig):
        return False, "witness signature invalid"
    return True, "ok"


@dataclass
class Bundle:
    """Portable unit of finality: one entry + K valid witness receipts."""
    entry: Entry
    receipts: list

    def to_dict(self) -> dict:
        return {"entry": self.entry.to_dict(),
                "receipts": [r.to_dict() for r in self.receipts]}

    @classmethod
    def from_dict(cls, data: Any) -> "Bundle":
        if not isinstance(data, dict) or set(data) != {"entry", "receipts"}:
            raise CryptoError("bundle field set mismatch")
        if not isinstance(data["receipts"], list):
            raise CryptoError("bundle receipts must be a list")
        return cls(entry=Entry.from_dict(data["entry"]),
                   receipts=[Receipt.from_dict(r) for r in data["receipts"]])


def verify_bundle(bundle: Bundle, k: int = DEFAULT_K,
                  difficulty: int = DEFAULT_DIFFICULTY,
                  now: Optional[float] = None) -> tuple[bool, str]:
    """Fully offline: entry validity + K distinct valid witness receipts. Zero network calls."""
    ok, reason = verify_entry(bundle.entry, difficulty, now=now)
    if not ok:
        return False, f"entry invalid: {reason}"
    if len(bundle.receipts) < k:
        return False, f"insufficient receipts: {len(bundle.receipts)} < {k}"
    seen: set[str] = set()
    for r in bundle.receipts:
        if r.entry_hash != bundle.entry.entry_hash:
            return False, "receipt references a different entry"
        if r.author != bundle.entry.author or r.seq != bundle.entry.seq:
            return False, "receipt author/seq mismatch"
        if r.witness == bundle.entry.author:
            return False, "author cannot witness own entry"
        if r.witness in seen:
            return False, "duplicate witness in bundle"
        seen.add(r.witness)
        ok, reason = verify_receipt(r)
        if not ok:
            return False, f"receipt invalid: {reason}"
    return True, "ok"


@dataclass
class FraudProof:
    """Two validly-signed entries by the same author claiming the same seq with different hashes."""
    entry_a: Entry
    entry_b: Entry

    def to_dict(self) -> dict:
        return {"entry_a": self.entry