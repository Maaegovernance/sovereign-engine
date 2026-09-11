"""Tests for identity-bound Human Council multi-signature verification."""

import hmac
import hashlib
import unittest
from council import CouncilRegistry, CouncilMember


class TestCouncilRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = CouncilRegistry()
        self.registry.add_member(CouncilMember(
            member_id="member-01",
            role="Sovereign",
            public_secret=b"secret_member_01",
        ))
        self.registry.add_member(CouncilMember(
            member_id="member-02",
            role="SecurityLead",
            public_secret=b"secret_member_02",
        ))
        self.registry.add_member(CouncilMember(
            member_id="member-03",
            role="Architect",
            public_secret=b"secret_member_03",
        ))

    def _sig(self, member_id: str, secret: bytes, payload: str) -> str:
        return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()

    def test_valid_single_member_signature(self):
        payload = "POL-CRIT-001:request-42"
        sig = self._sig("member-01", b"secret_member_01", payload)
        self.assertTrue(
            self.registry.verify_member_signature("member-01", payload, sig)
        )

    def test_wrong_member_secret_rejected(self):
        payload = "POL-CRIT-001:request-42"
        # Sign with member-02 secret but claim to be member-01
        sig = self._sig("member-02", b"secret_member_02", payload)
        self.assertFalse(
            self.registry.verify_member_signature("member-01", payload, sig)
        )

    def test_revoked_member_cannot_sign(self):
        self.registry.revoke_member("member-01")
        payload = "POL-CRIT-001:request-42"
        sig = self._sig("member-01", b"secret_member_01", payload)
        self.assertFalse(
            self.registry.verify_member_signature("member-01", payload, sig)
        )

    def test_multi_sig_requires_distinct_members(self):
        payload = "POL-CRIT-001:request-42"
        sig1 = self._sig("member-01", b"secret_member_01", payload)
        sig2 = self._sig("member-02", b"secret_member_02", payload)

        ok, signers, reason = self.registry.validate_multi_sig(
            payload_str=payload,
            signature_map={
                "member-01": sig1,
                "member-02": sig2,
            },
            required_count=2,
        )
        self.assertTrue(ok)
        self.assertEqual(signers, {"member-01", "member-02"})
        self.assertEqual(reason, "COUNCIL_QUORUM_VERIFIED")

    def test_duplicate_signature_from_same_member_insufficient(self):
        """Replaying the same member twice must not satisfy M-of-N."""
        payload = "POL-CRIT-001:request-42"
        sig1 = self._sig("member-01", b"secret_member_01", payload)

        ok, signers, reason = self.registry.validate_multi_sig(
            payload_str=payload,
            signature_map={
                "member-01": sig1,
                # attacker tries to reuse the same identity
                "member-01-alias": sig1,
            },
            required_count=2,
        )
        self.assertFalse(ok)
        self.assertEqual(len(signers), 1)  # only one distinct valid signer

    def test_insufficient_distinct_signers(self):
        payload = "POL-CRIT-001:request-42"
        sig1 = self._sig("member-01", b"secret_member_01", payload)

        ok, signers, reason = self.registry.validate_multi_sig(
            payload_str=payload,
            signature_map={"member-01": sig1},
            required_count=2,
        )
        self.assertFalse(ok)
        self.assertIn("Council Quorum Failed", reason)


if __name__ == "__main__":
    unittest.main()
