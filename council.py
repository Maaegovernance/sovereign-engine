"""Human Council Registry & Identity-Bound Multi-Signature Verification.

Binds HMAC signatures to specific authenticated member identities rather than
raw signature counts. Enforces M-of-N distinct active members and supports
role-based status (active / revoked).
"""

import hmac
import hashlib
from typing import Dict, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class CouncilMember:
    member_id: str
    role: str
    public_secret: bytes
    active: bool = True


class CouncilRegistry:
    def __init__(self):
        self.members: Dict[str, CouncilMember] = {}

    def add_member(self, member: CouncilMember) -> None:
        self.members[member.member_id] = member

    def revoke_member(self, member_id: str) -> bool:
        """Mark a member as inactive (revoked). Returns True if member existed."""
        member = self.members.get(member_id)
        if not member:
            return False
        member.active = False
        return True

    def reactivate_member(self, member_id: str) -> bool:
        member = self.members.get(member_id)
        if not member:
            return False
        member.active = True
        return True

    def get_member(self, member_id: str) -> Optional[CouncilMember]:
        return self.members.get(member_id)

    def active_members(self) -> Dict[str, CouncilMember]:
        return {mid: m for mid, m in self.members.items() if m.active}

    def verify_member_signature(
        self,
        member_id: str,
        payload_str: str,
        signature_hex: str,
    ) -> bool:
        """Verify an HMAC signature strictly against a specific member's secret."""
        member = self.members.get(member_id)
        if not member or not member.active:
            return False
        if not signature_hex or not isinstance(signature_hex, str):
            return False

        expected = hmac.new(
            member.public_secret,
            payload_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature_hex)

    def validate_multi_sig(
        self,
        payload_str: str,
        signature_map: Dict[str, str],  # {member_id: signature_hex}
        required_count: int,
    ) -> Tuple[bool, Set[str], str]:
        """Ensure signatures belong to N DISTINCT active council members.

        Returns:
            (success, set_of_valid_signer_ids, reason_string)
        """
        if required_count <= 0:
            return True, set(), "COUNCIL_QUORUM_VERIFIED (no signatures required)"

        valid_signers: Set[str] = set()

        for member_id, sig_hex in signature_map.items():
            if self.verify_member_signature(member_id, payload_str, sig_hex):
                valid_signers.add(member_id)

        if len(valid_signers) < required_count:
            return (
                False,
                valid_signers,
                f"Council Quorum Failed: {len(valid_signers)}/{required_count} "
                f"distinct valid signatures.",
            )

        return True, valid_signers, "COUNCIL_QUORUM_VERIFIED"
