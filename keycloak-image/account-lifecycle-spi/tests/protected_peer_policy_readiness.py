"""A finite installed peer-rule change cannot rewrite an already issued approval."""

import base64
import copy
import hashlib
import hmac
import json
import subprocess
import time
import uuid
from urllib.error import URLError
from urllib.request import urlopen

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, IMAGE, REALM, call, canonical, mac
from protected_binding_readiness import BindingReadiness, config_values, inspect_owned
from protected_peer_readiness import PeerFixture, PeerReadiness, PROFILE, REQUIRED, TENANT
from protected_resources import require_active


PRECOMMIT = (*REQUIRED, "exactPeerIssuedReceiptVerified",
    "childDisabledNativeAccountAndCreationMACVerified", "onlyFinitePeerRuleChanged",
    "thirdBootSameJarImageVolumeAndCapsVerified", "sameNativeProfilesAfterRestart",
    "freshParentNativeHumanAfterRestartVerified",
    "installationReadyWithFreshPrimaryApprovalVerified")


def classify(summary):
    o = summary.get("readinessObservation", {})
    images = summary.get("nativeImageIds", [])
    if not (summary.get("executed") == 1 and summary.get("errors") == 0
            and summary.get("skipped") == 0 and o.get("policyChange") in {"removed", "revised"}
            and all(o.get(k) is True for k in PRECOMMIT)
            and len(images) == 3 and len(set(images)) == 1
            and o.get("sourceApproveStatus") == 201 and o.get("sourceCreateStatus") == 201
            and o.get("sourceCommitStatus") == 200 and o.get("sourceConsumedStatus") == 200
            and o.get("peerApproveStatus") == 201 and o.get("childCreateStatus") == 201
            and o.get("changedPolicyPrimaryApproveStatus") == 201):
        return "INPUT_OR_FIXTURE_ERROR"
    if summary.get("failures") == 1 and o.get("changedPolicyParentApproveStatus") == 201:
        return "GENUINE_WITHDRAWN_PEER_RETAINS_NEW_APPROVAL_AUTHORITY_RED"
    if (summary.get("failures") == 1 and o.get("changedPolicyParentApproveStatus") == 403
            and o.get("childCommitStatus") in {403, 409}):
        return "GENUINE_FROZEN_PEER_APPROVAL_COMMIT_AFTER_POLICY_CHANGE_RED"
    if (summary.get("failures") == 0 and o.get("changedPolicyParentApproveStatus") == 403
            and o.get("withdrawnParentNewApprovalDenied") is True
            and o.get("changedPolicyChildApproveStatus") == (403 if o["policyChange"] == "removed" else 201)
            and o.get("childCommitStatus") == 200
            and o.get("childCommitAndConsumedAllMACBindingsVerified") is True
            and o.get("savedParentAndChildTerminalRetriesUnchanged") is True
            and o.get("freshChildNativeHumanAfterRestartVerified") is True
            and o.get("policyChangeChildAuthorityVerified") is True):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


class PeerPolicyReadiness(PeerReadiness):
    def test_removed_policy_preserves_frozen_child_commit_without_role_only_delegation(self):
        self.changed_policy("removed")

    def test_revised_policy_preserves_frozen_child_commit_and_exact_new_policy_binding(self):
        self.changed_policy("revised")

    def changed_policy(self, change):
        self.test_committed_tenant_admin_approves_own_tenant_peer_without_person_config()
        helper, parent, _, child, scope, issued = self.peer_case
        observed = self.observation
        observed["policyChange"] = change
        attempt = str(uuid.uuid4())
        create = self.creation(helper, scope, issued)
        status, opened = helper.protected_machine_request(
            "create", child, create, actor="ACCOUNT_CREATE", attempt=attempt)
        observed["childCreateStatus"] = status
        self.assertEqual(201, status)
        creation = self.verify_creation(helper, child, attempt, parent, scope, create, opened)
        before = helper.admin("GET", "/users/" + opened["accountId"])
        self.assertFalse(before["enabled"])
        self.assertEqual(["/pending-provisioning"],
            [g["path"] for g in helper.admin("GET", "/users/" + opened["accountId"] + "/groups")])
        observed["childDisabledNativeAccountAndCreationMACVerified"] = True
        baseline = inspect_owned(PeerFixture)
        old_config = json.loads(config_values(baseline)["ORISO_PROTECTED_INVITATIONS_CONFIG"])
        changed = copy.deepcopy(old_config)
        if change == "removed":
            changed["peerDelegationPolicies"] = []
        else:
            changed["peerDelegationPolicies"][0]["version"] = 2
        self.assertNotEqual(old_config["peerDelegationPolicies"], changed["peerDelegationPolicies"])
        self.assertEqual({k: v for k, v in old_config.items() if k != "peerDelegationPolicies"},
                         {k: v for k, v in changed.items() if k != "peerDelegationPolicies"})
        observed["onlyFinitePeerRuleChanged"] = True
        self.restart(baseline, changed)
        observed["thirdBootSameJarImageVolumeAndCapsVerified"] = True
        observed["sameNativeProfilesAfterRestart"] = True
        self.assertEqual(before, helper.admin("GET", "/users/" + opened["accountId"]))
        primary = helper.human(record=False)
        status, _ = call(helper.base, "PUT", helper.endpoint(str(uuid.uuid4())),
                         {"scope": helper.scope()}, primary)
        observed["changedPolicyPrimaryApproveStatus"] = status
        self.assertEqual(201, status)
        observed["installationReadyWithFreshPrimaryApprovalVerified"] = True
        original = self.peer_origin
        parent_native = helper.admin("GET", "/users/" + parent)
        parent_bearer = self.peer_human(helper, parent_native, original[2]["account"]["password"])
        observed["freshParentNativeHumanAfterRestartVerified"] = True
        count = helper.admin("GET", "/users/count")
        status, _ = call(helper.base, "PUT", helper.endpoint(str(uuid.uuid4())),
                         {"scope": helper.scope()}, parent_bearer)
        observed["changedPolicyParentApproveStatus"] = status
        self.assertEqual(403, status)
        self.assertEqual(count, helper.admin("GET", "/users/count"))
        observed["withdrawnParentNewApprovalDenied"] = True
        commit = {k: create[k] for k in ("approvalReceipt", "scopeDigest", "authorizationRevision",
                                        "creationFingerprint", "execution")}
        commit.update(accountId=opened["accountId"], creationProof=opened["creationProof"],
            localCommit={"journalVersion": 1, "outboxId": str(uuid.uuid4()), "effectsDigest": "b" * 64})
        PeerFixture.phase = "frozen-child-commit-after-peer-policy-change"
        status, terminal = helper.protected_machine_request(
            "commit", child, commit, actor="ACCOUNT_CREATE", attempt=attempt)
        observed["childCommitStatus"] = status
        self.assertEqual(200, status)
        self.assertEqual("COMMITTED", terminal["state"])
        terminal_value = helper.verified_receipt(terminal["terminalReceipt"], "terminal-receipt", 16000,
            {"realmId", "attemptId", "accountId", "ownerClient", "ownerSubject", "scope",
             "creationFingerprint", "groupId", "roleFingerprint", "state", "generation",
             "executionId", "operation", "commandDigest"})
        expected = {"realmId": PeerFixture.realm_id, "attemptId": attempt, "accountId": opened["accountId"],
            "ownerClient": ACTORS["ACCOUNT_CREATE"][0], "ownerSubject": SUBJECTS["ACCOUNT_CREATE"],
            "scope": canonical(creation["scope"]).decode(), "creationFingerprint": create["creationFingerprint"],
            "groupId": PeerFixture.peer_group_id, "roleFingerprint": creation["initialRoleFingerprint"],
            "state": "COMMITTED", "generation": 0, "executionId": create["execution"]["executionId"],
            "operation": "commit", "commandDigest": mac("protected-invitation-payload/v1", commit)}
        self.assertEqual(expected, terminal_value)
        query = {"scopeDigest": issued["scopeDigest"], "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"], "authorizationRevision": 1, "attemptId": attempt,
            "approvalRequestDigest": issued["approvalRequestDigest"]}
        status, consumed = helper.protected_machine_request("status", child, query)
        self.assertEqual(200, status)
        self.assertEqual("CONSUMED", consumed["state"])
        wrapper = consumed["transitionReceipt"]
        verified = helper.verified_receipt(wrapper["receipt"], "protected-approval-consume/v1", 24000,
            {"operation", "state", "approvalId", "scopeDigest", "boundAttemptId", "accountId", "terminalReceipt"})
        self.assertEqual({"operation": "protected-invitation.consume", "state": "CONSUMED",
            "approvalId": child, "scopeDigest": issued["scopeDigest"], "boundAttemptId": attempt,
            "accountId": opened["accountId"], "terminalReceipt": terminal["terminalReceipt"]}, verified)
        self.assertEqual({**verified, "receipt": wrapper["receipt"]}, wrapper)
        observed["childCommitAndConsumedAllMACBindingsVerified"] = True
        for approval, owned_attempt, body, saved in (
                (original[0], original[1], original[3], original[4]), (child, attempt, commit, terminal)):
            status, retry = helper.protected_machine_request(
                "commit", approval, body, actor="ACCOUNT_CREATE", attempt=owned_attempt)
            self.assertEqual(200, status)
            self.assertEqual(saved, retry)
        observed["savedParentAndChildTerminalRetriesUnchanged"] = True
        child_native = helper.admin("GET", "/users/" + opened["accountId"])
        self.assertTrue(child_native["enabled"])
        self.assertEqual([str(TENANT)], child_native["attributes"]["tenantId"])
        self.assertEqual([PeerFixture.peer_group_id],
            [g["id"] for g in helper.admin("GET", "/users/" + child_native["id"] + "/groups")])
        child_bearer = self.peer_human(helper, child_native, create["account"]["password"])
        observed["freshChildNativeHumanAfterRestartVerified"] = True
        status, result = call(helper.base, "PUT", helper.endpoint(str(uuid.uuid4())),
                              {"scope": helper.scope()}, child_bearer)
        observed["changedPolicyChildApproveStatus"] = status
        self.assertEqual(403 if change == "removed" else 201, status)
        if change == "revised":
            receipt = result["approvalReceipt"]
            verified = helper.verified_receipt(receipt["receipt"], "protected-approval-receipt/v1", 16384,
                {"approvalId", "scopeDigest", "issuerSubject", "bindingVersion", "profileVersion", "validUntil", "approvalRequestDigest"})
            self.assertEqual({**verified, "receipt": receipt["receipt"]}, receipt)
            self.assertEqual(child_native["id"], receipt["issuerSubject"])
            self.assertEqual(2, receipt["bindingVersion"])
        self.assertEqual(count, helper.admin("GET", "/users/count"))
        observed["policyChangeChildAuthorityVerified"] = True

    def restart(self, baseline, changed):
        PeerFixture.phase = "finite-peer-policy-third-boot"
        encoded = json.dumps(changed, separators=(",", ":"))
        subprocess.run(["docker", "stop", "-t", "5", PeerFixture.name], check=True, capture_output=True, timeout=30)
        subprocess.run(["docker", "rm", PeerFixture.name], check=True, capture_output=True, timeout=15)
        command = PeerFixture.command.copy()
        index = command.index(IMAGE)
        command[index:index] = ["-e", "ORISO_PROTECTED_INVITATIONS_ENABLED=true", "-e",
                                "ORISO_PROTECTED_INVITATIONS_CONFIG=" + encoded]
        PeerFixture.memoryStart()
        deadline = time.monotonic() + 180
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        PeerFixture.refresh_endpoint("peer-policy-third-boot")
        while time.monotonic() < deadline:
            require_active("peer-policy-third-boot")
            try:
                with urlopen(PeerFixture.base + "/realms/" + REALM + "/.well-known/openid-configuration",
                             timeout=min(5, max(0.1, deadline - time.monotonic()))) as response:
                    value = json.loads(response.read())
                    if response.status == 200 and value.get("issuer") == PeerFixture.native_issuer:
                        current = BindingReadiness("runTest").runtime(baseline, encoded, PeerFixture)
                        PeerFixture.native_image_ids.append(current["Image"])
                        self.assertEqual(3, len(PeerFixture.native_image_ids))
                        self.assertEqual(1, len(set(PeerFixture.native_image_ids)))
                        return
            except (URLError, OSError, TimeoutError):
                pass
            self.assertTrue(inspect_owned(PeerFixture)["State"]["Running"])
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        self.fail("Finite peer-policy third native boot did not become ready within180s")

    @staticmethod
    def creation(helper, scope, issued):
        account = helper.creation()["account"]
        account["email"] = scope["recipient"]
        account["username"] = "enc." + base64.b32encode(scope["recipient"].encode()).decode().replace("=", ".")
        value = {"approvalReceipt": issued["approvalReceipt"], "scopeDigest": issued["scopeDigest"],
            "authorizationRevision": 1, "acceptanceClaim": {"workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"], "authorizationRevision": 1, "claimId": str(uuid.uuid4()),
            "journalVersion": 1}, "execution": {"executionId": str(uuid.uuid4()), "generation": 0},
            "account": account}
        value["creationFingerprint"] = mac("protected-account-creation/v1", value)
        return value

    def verify_creation(self, helper, approval, attempt, parent, scope, create, opened):
        encoded, signature = opened["creationProof"].split(".")
        self.assertLessEqual(len(opened["creationProof"].encode()), 16384)
        expected = base64.urlsafe_b64encode(hmac.new(CONTEXT_KEY,
            ("creation-proof\n" + encoded).encode(), hashlib.sha256).digest()).decode().rstrip("=")
        self.assertTrue(hmac.compare_digest(expected, signature))
        value = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(encoded, base64.urlsafe_b64encode(canonical(value)).decode().rstrip("="))
        profile = next(p for p in PeerFixture.installed_configuration["profiles"] if p["id"] == PROFILE)
        self.assertEqual({"v": 1, "realmName": REALM, "realmId": PeerFixture.realm_id,
            "attemptId": attempt, "accountId": opened["accountId"], "ownerClient": ACTORS["ACCOUNT_CREATE"][0],
            "ownerSubject": SUBJECTS["ACCOUNT_CREATE"], "initialGroupId": PeerFixture.peer_group_id,
            "initialRoleFingerprint": mac("protected-initial-profile/v1", profile),
            "creationFingerprint": create["creationFingerprint"], "scope": {"tenantId": str(TENANT),
            "registrationKind": "TENANT_ADMIN", "initialGroup": profile["groupPath"],
            "origin": {"kind": "INVITATION", "workflowId": scope["workflowId"],
            "provenance": "protected-approval-v1:" + approval, "humanIssuer": PeerFixture.native_issuer,
            "humanSubject": parent, "humanAuthority": "TENANT_PEER", "agencyIds": []},
            "approvalBinding": {"approvalId": approval, "scopeDigest": create["scopeDigest"],
            "authorizationRevision": 1, "acceptanceClaim": create["acceptanceClaim"]}}}, value)
        return value
