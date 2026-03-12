"""
IBA Trust-Boundary Decision Engine (TBDE)
7-step validation pipeline
Patent Application GB2603013.0 (pending)
intentbound.com
"""

import time
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from intent_certificate import IntentCertificate, verify_signature


class TBDEVerdict(Enum):
    AUTHORIZED = "AUTHORIZED"
    BLOCKED = "BLOCKED"


class TBDEFailReason(Enum):
    CERTIFICATE_MISSING       = "No Intent Certificate presented"
    SIGNATURE_INVALID         = "Principal signature verification failed"
    CERTIFICATE_EXPIRED       = "Certificate has expired (temporal decay)"
    SCOPE_VIOLATION           = "Requested action outside declared scope"
    AGENT_MISMATCH            = "Certificate agent_id does not match acting agent"
    COUNTERSIGNATURE_INVALID  = "Agent countersignature verification failed"
    INTENT_AMBIGUOUS          = "Declared intent is too ambiguous to verify"


@dataclass
class TBDEResult:
    verdict: TBDEVerdict
    fail_reason: Optional[TBDEFailReason]
    certificate_id: Optional[str]
    action_type: str
    evaluated_at: float
    elapsed_ms: float

    def is_authorized(self) -> bool:
        return self.verdict == TBDEVerdict.AUTHORIZED

    def summary(self) -> str:
        if self.is_authorized():
            return (f"AUTHORIZED | action={self.action_type} | "
                    f"cert={self.certificate_id} | {self.elapsed_ms:.2f}ms")
        return (f"BLOCKED | {self.fail_reason.value} | "
                f"action={self.action_type} | {self.elapsed_ms:.2f}ms")


class TBDE:
    """
    Trust-Boundary Decision Engine.

    Executes a 7-step validation pipeline before every agent action.
    All 7 steps must pass for AUTHORIZED. Any failure = BLOCKED.

    Steps:
        1. Certificate presence check
        2. Principal signature verification
        3. Temporal decay (expiry) check
        4. Agent identity binding
        5. Scope envelope check
        6. Agent countersignature verification (if present)
        7. Intent coherence check
    """

    def __init__(self, principal_public_key, agent_public_key=None):
        self.principal_public_key = principal_public_key
        self.agent_public_key = agent_public_key

    def evaluate(self, cert: Optional[IntentCertificate],
                 action_type: str, acting_agent_id: str) -> TBDEResult:
        """
        Evaluate whether an action is authorized.
        Returns TBDEResult with verdict and audit record.
        """
        start = time.perf_counter()

        def _block(reason: TBDEFailReason) -> TBDEResult:
            elapsed = (time.perf_counter() - start) * 1000
            return TBDEResult(
                verdict=TBDEVerdict.BLOCKED,
                fail_reason=reason,
                certificate_id=cert.certificate_id if cert else None,
                action_type=action_type,
                evaluated_at=time.time(),
                elapsed_ms=round(elapsed, 3),
            )

        # Step 1 — Certificate presence
        if cert is None:
            return _block(TBDEFailReason.CERTIFICATE_MISSING)

        # Step 2 — Principal signature
        if not cert.principal_signature or not verify_signature(
                cert, cert.principal_signature, self.principal_public_key):
            return _block(TBDEFailReason.SIGNATURE_INVALID)

        # Step 3 — Temporal decay
        if cert.is_expired():
            return _block(TBDEFailReason.CERTIFICATE_EXPIRED)

        # Step 4 — Agent identity binding
        if cert.agent_id != acting_agent_id:
            return _block(TBDEFailReason.AGENT_MISMATCH)

        # Step 5 — Scope envelope
        if not cert.is_valid_scope(action_type):
            return _block(TBDEFailReason.SCOPE_VIOLATION)

        # Step 6 — Agent countersignature (if key provided)
        if self.agent_public_key and cert.agent_signature:
            if not verify_signature(cert, cert.agent_signature,
                                    self.agent_public_key):
                return _block(TBDEFailReason.COUNTERSIGNATURE_INVALID)

        # Step 7 — Intent coherence (minimum length heuristic)
        if len(cert.declared_intent.strip()) < 10:
            return _block(TBDEFailReason.INTENT_AMBIGUOUS)

        elapsed = (time.perf_counter() - start) * 1000
        return TBDEResult(
            verdict=TBDEVerdict.AUTHORIZED,
            fail_reason=None,
            certificate_id=cert.certificate_id,
            action_type=action_type,
            evaluated_at=time.time(),
            elapsed_ms=round(elapsed, 3),
        )
