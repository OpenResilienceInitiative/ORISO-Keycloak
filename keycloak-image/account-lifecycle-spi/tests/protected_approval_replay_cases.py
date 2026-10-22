"""Public immutable workflow/revision ownership, independent of approval URL IDs."""

import uuid

from lifecycle_fixture import call, mac


class ProtectedApprovalReplayCases:
    def test_duplicate_workflow_revision_conflicts_without_second_approval(self):
        first_id, duplicate_id = str(uuid.uuid4()), str(uuid.uuid4())
        request = {"scope": self.scope()}
        bearer = self.human(record=False)
        before = self.admin("GET", "/users/count")
        expected_digest = mac(
            "protected-approval-request/v1",
            {
                "request": request,
                "issuerRealm": self.realm_id,
                "issuerSubject": self.human_subject,
            },
        )
        status, first = call(self.base, "PUT", self.endpoint(first_id), request, bearer)
        self.assertEqual(201, status)
        self.assertEqual("AUTHORIZED", first["state"])
        self.assertEqual(expected_digest, first["approvalRequestDigest"])
        receipt = first["approvalReceipt"]
        verified = self.verified_receipt(
            receipt["receipt"],
            "protected-approval-receipt/v1",
            16384,
            {
                "approvalId",
                "scopeDigest",
                "issuerSubject",
                "bindingVersion",
                "profileVersion",
                "validUntil",
                "approvalRequestDigest",
            },
        )
        self.assertEqual({**verified, "receipt": receipt["receipt"]}, receipt)
        self.assertEqual(first_id, receipt["approvalId"])
        self.assertEqual(self.human_subject, receipt["issuerSubject"])
        self.assertEqual(expected_digest, receipt["approvalRequestDigest"])
        status, _ = call(self.base, "PUT", self.endpoint(duplicate_id), request, bearer)
        o = {
            "actualDuplicateStatus": status,
            "expectedDuplicateStatus": 409,
            "sameExactNativeHumanAndOriginalRequest": True,
            "firstApprovalAndRequestMacVerified": True,
            "differentCanonicalApprovalIds": first_id != duplicate_id,
        }
        type(self).duplicate_workflow_observation = o
        query = {
            "scopeDigest": None,
            "workflowId": request["scope"]["workflowId"],
            "inviteId": request["scope"]["inviteId"],
            "authorizationRevision": request["scope"]["authorizationRevision"],
            "attemptId": None,
            "approvalRequestDigest": expected_digest,
        }
        source_status, source = self.protected_machine_request(
            "status", first_id, query
        )
        self.assertEqual(200, source_status)
        self.assertEqual(first, source)
        o["originalApprovalUnchangedAfterCollision"] = True
        absent_status, _ = self.protected_machine_request("status", duplicate_id, query)
        self.assertEqual(404, absent_status)
        o["duplicateApprovalAbsentAfterRollback"] = True
        retry_status, retry = call(
            self.base, "PUT", self.endpoint(first_id), request, bearer
        )
        self.assertEqual(200, retry_status)
        self.assertEqual(first, retry)
        o["originalExactRetryStillImmutable"] = True
        self.assertEqual(before, self.admin("GET", "/users/count"))
        o["noAccountCreated"] = True
        self.assertEqual(409, status)
