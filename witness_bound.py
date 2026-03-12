"""
IBA WitnessBound — Pre-Execution Audit Commitment
Immutable audit trail before agent action executes.
Patent Application GB2603013.0 (pending)
intentbound.com
"""

import hashlib
import json
import time
from dataclasses import dataclass
from typing import List, Optional
from tbde import TBDEResult, TBDEVerdict


@dataclass
class WitnessRecord:
    """
    An immutable pre-execution commitment.
    Created BEFORE the action executes — not after.
    This is the key distinction from traditional audit logging.
    """
    record_id: str
    certificate_id: Optional[str]
    action_type: str
    acting_agent_id: str
    tbde_verdict: str
    tbde_elapsed_ms: float
    committed_at: float
    chain_hash: str        # Hash linking to previous record (chain integrity)
    record_hash: str       # Self-hash of this record

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "certificate_id": self.certificate_id,
            "action_type": self.action_type,
            "acting_agent_id": self.acting_agent_id,
            "tbde_verdict": self.tbde_verdict,
            "tbde_elapsed_ms": self.tbde_elapsed_ms,
            "committed_at": self.committed_at,
            "chain_hash": self.chain_hash,
            "record_hash": self.record_hash,
        }


class WitnessBound:
    """
    WitnessBound Audit Layer.

    Commits a tamper-evident record of every TBDE decision
    BEFORE the action is allowed to execute.

    Chain integrity: each record hashes the previous record,
    forming a linked audit chain. Tampering with any record
    invalidates all subsequent records.
    """

    def __init__(self):
        self._chain: List[WitnessRecord] = []
        self._last_hash = "GENESIS"

    def commit(self, tbde_result: TBDEResult, acting_agent_id: str) -> WitnessRecord:
        """
        Commit a TBDE result to the audit chain.
        Called immediately after TBDE evaluation, before action execution.
        """
        now = time.time()
        payload = {
            "certificate_id": tbde_result.certificate_id,
            "action_type": tbde_result.action_type,
            "acting_agent_id": acting_agent_id,
            "tbde_verdict": tbde_result.verdict.value,
            "tbde_elapsed_ms": tbde_result.elapsed_ms,
            "committed_at": now,
            "chain_hash": self._last_hash,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        record_hash = hashlib.sha256(payload_bytes).hexdigest()
        record_id = record_hash[:16]

        record = WitnessRecord(
            record_id=record_id,
            certificate_id=tbde_result.certificate_id,
            action_type=tbde_result.action_type,
            acting_agent_id=acting_agent_id,
            tbde_verdict=tbde_result.verdict.value,
            tbde_elapsed_ms=tbde_result.elapsed_ms,
            committed_at=now,
            chain_hash=self._last_hash,
            record_hash=record_hash,
        )
        self._chain.append(record)
        self._last_hash = record_hash
        return record

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire audit chain.
        Returns False if any record has been tampered with.
        """
        prev_hash = "GENESIS"
        for record in self._chain:
            payload = {
                "certificate_id": record.certificate_id,
                "action_type": record.action_type,
                "acting_agent_id": record.acting_agent_id,
                "tbde_verdict": record.tbde_verdict,
                "tbde_elapsed_ms": record.tbde_elapsed_ms,
                "committed_at": record.committed_at,
                "chain_hash": prev_hash,
            }
            expected = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode()
            ).hexdigest()
            if expected != record.record_hash:
                return False
            prev_hash = record.record_hash
        return True

    def get_chain(self) -> List[dict]:
        return [r.to_dict() for r in self._chain]

    def blocked_count(self) -> int:
        return sum(1 for r in self._chain if r.tbde_verdict == TBDEVerdict.BLOCKED.value)

    def authorized_count(self) -> int:
        return sum(1 for r in self._chain if r.tbde_verdict == TBDEVerdict.AUTHORIZED.value)
