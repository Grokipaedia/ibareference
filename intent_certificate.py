"""
IBA Intent Certificate
Patent Application GB2603013.0 (pending)
intentbound.com
"""

import json
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, generate_private_key, EllipticCurvePrivateKey
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


@dataclass
class IntentCertificate:
    """
    A cryptographically signed declaration of authorized intent.
    
    The principal signs the intent BEFORE the agent acts.
    The agent carries this certificate and presents it at the enforcement boundary.
    """
    principal_id: str          # Identity of the authorizing human principal
    agent_id: str              # Identity of the acting agent
    declared_intent: str       # What the agent is authorized to do
    scope: list                # Explicit list of permitted action types
    issued_at: float           # Unix timestamp of issuance
    expires_at: float          # Unix timestamp of expiry (temporal decay)
    certificate_id: str        # Unique identifier for this certificate
    principal_signature: Optional[str] = None  # Principal's ECDSA-P384 signature
    agent_signature: Optional[str] = None      # Agent's ECDSA-P384 countersignature

    def to_signable_bytes(self) -> bytes:
        """Canonical serialisation for signing — excludes signature fields."""
        payload = {
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "declared_intent": self.declared_intent,
            "scope": sorted(self.scope),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "certificate_id": self.certificate_id,
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the signable payload."""
        return hashlib.sha256(self.to_signable_bytes()).hexdigest()

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def is_valid_scope(self, action_type: str) -> bool:
        return action_type in self.scope


def generate_keypair() -> tuple:
    """Generate an ECDSA P-384 keypair."""
    private_key = generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign_certificate(cert: IntentCertificate, private_key: EllipticCurvePrivateKey) -> str:
    """Sign the certificate payload. Returns hex-encoded DER signature."""
    signature = private_key.sign(cert.to_signable_bytes(), ECDSA(hashes.SHA384()))
    return signature.hex()


def verify_signature(cert: IntentCertificate, signature_hex: str,
                     public_key) -> bool:
    """Verify a signature against the certificate payload."""
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            cert.to_signable_bytes(),
            ECDSA(hashes.SHA384())
        )
        return True
    except InvalidSignature:
        return False


def create_certificate(
    principal_id: str,
    agent_id: str,
    declared_intent: str,
    scope: list,
    ttl_seconds: int,
    principal_private_key: EllipticCurvePrivateKey
) -> IntentCertificate:
    """
    Issue a new Intent Certificate signed by the principal.
    
    TTL (time-to-live) enforces temporal decay —
    certificates expire and cannot be reused indefinitely.
    """
    now = time.time()
    cert_id = hashlib.sha256(
        f"{principal_id}{agent_id}{now}".encode()
    ).hexdigest()[:16]

    cert = IntentCertificate(
        principal_id=principal_id,
        agent_id=agent_id,
        declared_intent=declared_intent,
        scope=scope,
        issued_at=now,
        expires_at=now + ttl_seconds,
        certificate_id=cert_id,
    )
    cert.principal_signature = sign_certificate(cert, principal_private_key)
    return cert
