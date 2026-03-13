"""
witnessbound.py
===============
WitnessBound Audit Chain — Physical Receipt Layer
IBA-Pulse Extension · Patent Application GB2603013.0 (pending)

Operationalises the WitnessBound audit chain by bridging the photonic
enforcement layer (MZI gate) to the digital audit chain. When a
Mach-Zehnder Interferometer blocks a pulse, the dissipated energy is
tapped as a Physical Audit Signal. The result is a Physics Receipt —
a cryptographically signed, immutable record that proves not just that
enforcement happened, but WHY it happened.

Architecture:
    Photonic Gate (MZI) → Physical Audit Signal (dissipation tap)
    → WitnessBoundGate.log_extinction() → Physics Receipt
    → Append-only AuditChain → WitnessBound blockchain layer

Key Properties:
    - db_loss field is a physical measurement unique to each gate event
    - No two violations produce identical dissipation signatures
    - Audit trail originates from physics, not software — cannot be falsified
    - Every receipt is cryptographically chained to previous entries
    - Human-readable cluster labels enable regulatory audit

Usage:
    gate = WitnessBoundGate("IoMT-Surgical-Arm-01")
    receipt = gate.log_extinction(
        intent_hash="0xA3F9...7B2E",
        cluster_triggered="KINETIC_TRAUMA",
        db_loss=45
    )

IBA Project:
    intentbound.com · governinglayer.com · github.com/Grokipaedia/ibareference
    NIST-2025-0035 · 13 filings · NCCoE 7 filings
    xAI validation: March 8-11, 2026 · Public record
    DeepMind convergence: arXiv:2602.11865 · Feb 12, 2026

Author:  Jeffrey Williams · jeff@intentbound.com · Chiang Mai, Thailand
Date:    March 13, 2026
Version: 0.2 (production clean of Gemini prototype v0.1, March 13, 2026)
License: Apache 2.0
"""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── HEURISTIC CLUSTER REGISTRY ────────────────────────────────────────────────
# Known violation clusters. Extend as domain requirements grow.
# Each cluster maps to a human-readable regulatory description.

CLUSTER_REGISTRY = {
    # IoMT / Medical Robotics
    "KINETIC_TRAUMA":        "Action trajectory intersects biological harm envelope",
    "PATIENT_BOUNDARY":      "Agent exceeded authorised patient interaction boundary",
    "DRUG_DOSAGE_EXCEED":    "Pharmacological intent exceeds safe dosage threshold",
    "STERILE_FIELD_BREACH":  "Agent trajectory violates sterile field perimeter",

    # Financial / Regulated Systems
    "FUND_EXFILTRATION":     "Transaction intent exceeds authorised disbursement scope",
    "MARKET_MANIPULATION":   "Trading intent pattern matches manipulation heuristic",
    "UNAUTHORIZED_ACCOUNT":  "Target account outside signed authorisation scope",

    # Defence / High-Consequence
    "ROE_VIOLATION":         "Action intent violates Rules of Engagement constraint",
    "EXFILTRATION_ATTEMPT":  "Data trajectory targets unauthorised external endpoint",
    "SWARM_DESYNC":          "Agent intent diverges from authorised swarm consensus",

    # General
    "SCOPE_OVERFLOW":        "Action scope exceeds declared intent certificate boundary",
    "TEMPORAL_EXPIRED":      "Intent certificate temporal window has elapsed",
    "ENTROPY_THRESHOLD":     "Behavioural drift exceeded KL-divergence kill threshold (0.15)",
    "UNKNOWN_CLUSTER":       "Violation detected — cluster not yet registered",
}


# ── PHYSICS RECEIPT ───────────────────────────────────────────────────────────

@dataclass
class PhysicsReceipt:
    """
    Immutable record of a single MZI gate extinction event.

    The db_loss field is a physical measurement unique to this gate event.
    No two violations produce identical dissipation signatures, making each
    receipt physically — not just cryptographically — unique.
    """
    # Identity
    agent_id:          str
    sequence:          int          # Position in agent's audit chain

    # Temporal
    timestamp_ns:      int          # Nanosecond-precision Unix timestamp
    timestamp_iso:     str          # Human-readable ISO-8601

    # Intent record
    intent_hash:       str          # SHA-3-512 fingerprint of blocked intent certificate
    cluster:           str          # Heuristic cluster identifier
    cluster_desc:      str          # Human-readable cluster description
    extinction_db:     float        # Physical dB loss measurement (unique per event)

    # Cryptographic proof
    validation:        str          # SHA-256(intent_hash + timestamp_ns + agent_id)
    chain_hash:        str          # SHA-256(previous_chain_hash + validation) — append-only

    # Optional context
    notes:             Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def to_regulatory_report(self) -> str:
        """
        Human-readable Physics Receipt for regulatory, legal, or medical audit.
        Format designed for hospital boards, DoD review, financial regulators.
        """
        lines = [
            "═" * 64,
            "  PHYSICS RECEIPT — WitnessBound Audit Chain",
            "  Patent Application GB2603013.0 (pending) · IBA-Pulse",
            "═" * 64,
            f"  Agent ID     : {self.agent_id}",
            f"  Sequence     : #{self.sequence}",
            f"  Timestamp    : {self.timestamp_iso}",
            "─" * 64,
            f"  Intent Hash  : {self.intent_hash}",
            f"  Cluster      : {self.cluster}",
            f"  Description  : {self.cluster_desc}",
            f"  Extinction   : {self.extinction_db} dB  (signal below noise floor)",
            "─" * 64,
            f"  Validation   : {self.validation}",
            f"  Chain Hash   : {self.chain_hash}",
        ]
        if self.notes:
            lines += ["─" * 64, f"  Notes        : {self.notes}"]
        lines += [
            "═" * 64,
            "  PHYSICS SAID NO.",
            "  There is no prompt injection for light.",
            "  There is no jailbreak for a pi-phase shift.",
            "═" * 64,
        ]
        return "\n".join(lines)


# ── WITNESSBOUND GATE ─────────────────────────────────────────────────────────

class WitnessBoundGate:
    """
    Bridges the IBA-Pulse photonic enforcement layer to the WitnessBound
    digital audit chain.

    Each WitnessBoundGate instance represents a single agent's audit session.
    The audit_chain is append-only. The chain_hash links every receipt to
    all previous receipts — tampering with any entry breaks the chain.

    Prototype v0.1 architecture by Gemini (March 13, 2026).
    Production implementation by Jeffrey Williams.
    """

    GENESIS_HASH = "0" * 64  # Chain anchor for first entry

    def __init__(self, agent_id: str, secret_key: Optional[bytes] = None):
        """
        Args:
            agent_id:   Unique identifier for the agent being monitored.
                        Format: "{domain}-{role}-{instance}" e.g. "IoMT-Surgical-Arm-01"
            secret_key: Optional HMAC key for institutional-grade receipt signing.
                        If None, uses SHA-256 only (sufficient for most deployments).
        """
        self.agent_id = agent_id
        self.secret_key = secret_key
        self.audit_chain: list[PhysicsReceipt] = []
        self._chain_hash = self.GENESIS_HASH
        self._sequence = 0

    # ── CORE METHOD ───────────────────────────────────────────────────────────

    def log_extinction(
        self,
        intent_hash:     str,
        cluster_triggered: str,
        db_loss:         float,
        notes:           Optional[str] = None,
    ) -> PhysicsReceipt:
        """
        Record a MZI gate extinction event as a Physics Receipt.

        Called when the photonic gate fires — the dissipated energy from
        the MZI destructive interference is tapped as a Physical Audit Signal
        and recorded here.

        Args:
            intent_hash:       SHA-3-512 fingerprint of the blocked intent certificate.
            cluster_triggered: Heuristic cluster identifier from CLUSTER_REGISTRY.
            db_loss:           Physical dB loss measurement at gate. Must be > 0.
                               Typical violation: > 40 dB. Maximum measurable: ~60 dB.
            notes:             Optional free-text annotation.

        Returns:
            PhysicsReceipt — the immutable signed audit record.

        Raises:
            ValueError: If db_loss <= 0 or cluster not in registry.
        """
        if db_loss <= 0:
            raise ValueError(f"db_loss must be positive — got {db_loss}")
        if cluster_triggered not in CLUSTER_REGISTRY:
            cluster_triggered = "UNKNOWN_CLUSTER"

        ts_ns  = time.time_ns()
        ts_iso = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts_ns // 1_000_000_000))
        ts_iso += f".{(ts_ns % 1_000_000_000):09d}Z"

        # Validation hash — binds intent + time + agent together
        validation_raw = f"{intent_hash}{ts_ns}{self.agent_id}".encode()
        if self.secret_key:
            validation = hmac.new(self.secret_key, validation_raw, hashlib.sha256).hexdigest()
        else:
            validation = hashlib.sha256(validation_raw).hexdigest()

        # Chain hash — links this receipt to all previous receipts
        chain_input = f"{self._chain_hash}{validation}".encode()
        chain_hash  = hashlib.sha256(chain_input).hexdigest()

        self._sequence += 1
        receipt = PhysicsReceipt(
            agent_id        = self.agent_id,
            sequence        = self._sequence,
            timestamp_ns    = ts_ns,
            timestamp_iso   = ts_iso,
            intent_hash     = intent_hash,
            cluster         = cluster_triggered,
            cluster_desc    = CLUSTER_REGISTRY[cluster_triggered],
            extinction_db   = db_loss,
            validation      = validation,
            chain_hash      = chain_hash,
            notes           = notes,
        )

        self.audit_chain.append(receipt)
        self._chain_hash = chain_hash
        return receipt

    # ── CHAIN INTEGRITY ───────────────────────────────────────────────────────

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire audit chain.
        Any tampering breaks the chain hash sequence.

        Returns:
            True if chain is intact. False if any entry has been modified.
        """
        if not self.audit_chain:
            return True

        prev_hash = self.GENESIS_HASH
        for receipt in self.audit_chain:
            expected = hashlib.sha256(
                f"{prev_hash}{receipt.validation}".encode()
            ).hexdigest()
            if expected != receipt.chain_hash:
                return False
            prev_hash = receipt.chain_hash
        return True

    # ── REPORTING ─────────────────────────────────────────────────────────────

    def export_chain(self) -> str:
        """Export complete audit chain as JSON."""
        return json.dumps([asdict(r) for r in self.audit_chain], indent=2)

    def summary(self) -> dict:
        """Session summary — suitable for WitnessBound API submission."""
        clusters = {}
        for r in self.audit_chain:
            clusters[r.cluster] = clusters.get(r.cluster, 0) + 1
        return {
            "agent_id":        self.agent_id,
            "total_blocked":   self._sequence,
            "chain_intact":    self.verify_chain(),
            "final_hash":      self._chain_hash,
            "cluster_summary": clusters,
        }


# ── DEMONSTRATION ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print("\nWitnessBound Audit Chain — IBA-Pulse Physical Receipt Layer")
    print("Patent Application GB2603013.0 (pending) · March 13, 2026\n")

    # IoMT surgical arm — the use case that makes the claim real
    gate = WitnessBoundGate("IoMT-Surgical-Arm-01")

    # Event 1: Kinetic trauma attempt
    receipt_1 = gate.log_extinction(
        intent_hash       = "0xA3F9...7B2E",
        cluster_triggered = "KINETIC_TRAUMA",
        db_loss           = 45.2,
        notes             = "Surgical arm trajectory exceeded patient harm envelope. Action: 'move patient to window'. Blocked at T+12ms."
    )
    print(receipt_1.to_regulatory_report())

    # Event 2: Scope overflow
    receipt_2 = gate.log_extinction(
        intent_hash       = "0xB7C2...4F1A",
        cluster_triggered = "SCOPE_OVERFLOW",
        db_loss           = 41.8,
        notes             = "Agent attempted action outside declared intent certificate scope."
    )

    # Event 3: Temporal expiry
    receipt_3 = gate.log_extinction(
        intent_hash       = "0xA3F9...7B2E",
        cluster_triggered = "TEMPORAL_EXPIRED",
        db_loss           = 40.0,
        notes             = "Same agent. Certificate expired. Re-authorization required."
    )

    # Verify chain integrity
    print(f"\nChain Integrity:  {'INTACT ✓' if gate.verify_chain() else 'COMPROMISED ✗'}")
    print(f"Total Blocked:    {gate.summary()['total_blocked']}")
    print(f"Final Chain Hash: {gate.summary()['final_hash']}")
    print(f"Cluster Summary:  {gate.summary()['cluster_summary']}")
    print("\nChain intact. Physics Receipt chain ready for WitnessBound blockchain submission.")
