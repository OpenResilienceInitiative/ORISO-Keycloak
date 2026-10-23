"""Offline classification counterexamples for actual peer-policy restart evidence."""

import unittest
from unittest.mock import Mock, patch
import protected_peer_readiness as peer
import protected_peer_policy_readiness as policy


def complete():
    return {"executed": 1, "failures": 1, "errors": 0, "skipped": 0,
        "nativeImageIds": ["synthetic-same-image"] * 3,
        "readinessObservation": {**{name: True for name in policy.PRECOMMIT},
            "policyChange": "removed", "sourceApproveStatus": 201, "sourceCreateStatus": 201,
            "sourceCommitStatus": 200, "sourceConsumedStatus": 200, "peerApproveStatus": 201,
            "childCreateStatus": 201, "changedPolicyPrimaryApproveStatus": 201,
            "changedPolicyParentApproveStatus": 403, "childCommitStatus": 409}}


class PeerPolicyControls(unittest.TestCase):
    def test_only_actual403_or409_frozen_commit_after_all_native_preconditions_is_red(self):
        for code in (403, 409):
            s = complete(); s["readinessObservation"]["childCommitStatus"] = code
            self.assertEqual("GENUINE_FROZEN_PEER_APPROVAL_COMMIT_AFTER_POLICY_CHANGE_RED", policy.classify(s))

    def test_withdrawn_old_peer201_is_a_distinct_authority_failure(self):
        s = complete(); s["readinessObservation"]["changedPolicyParentApproveStatus"] = 201
        self.assertEqual("GENUINE_WITHDRAWN_PEER_RETAINS_NEW_APPROVAL_AUTHORITY_RED", policy.classify(s))

    def test_all_native_profile_and_finite_config_preconditions_are_required(self):
        for name in policy.PRECOMMIT:
            s = complete(); s["readinessObservation"][name] = False
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", policy.classify(s))

    def test_unknown_commit_status_is_never_feature_red(self):
        for code in (0, 400, 401, 404, 405, 500, 503):
            s = complete(); s["readinessObservation"]["childCommitStatus"] = code
            self.assertEqual("BEHAVIOR_FAILURE", policy.classify(s))

    def test_setup_error_skip_or_missing_case_is_not_a_product_counterfactual(self):
        for key, value in (("executed", 0), ("errors", 1), ("skipped", 1)):
            s = complete(); s[key] = value
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", policy.classify(s))

    def test_three_equal_actual_image_ids_are_required(self):
        for images in ([], ["one"] * 2, ["one", "one", "different"], ["one"] * 4):
            s = complete(); s["nativeImageIds"] = images
            self.assertEqual("INPUT_OR_FIXTURE_ERROR", policy.classify(s))

    def test_green_requires_child_macs_saved_retries_and_new_current_human_authority(self):
        for mode, child_status in (("removed", 403), ("revised", 201)):
            s = complete(); s["failures"] = 0
            o = s["readinessObservation"]
            o.update(policyChange=mode, childCommitStatus=200, changedPolicyChildApproveStatus=child_status,
                withdrawnParentNewApprovalDenied=True, childCommitAndConsumedAllMACBindingsVerified=True,
                savedParentAndChildTerminalRetriesUnchanged=True, freshChildNativeHumanAfterRestartVerified=True,
                policyChangeChildAuthorityVerified=True)
            self.assertEqual("GREEN", policy.classify(s))
            for key in ("childCommitAndConsumedAllMACBindingsVerified", "savedParentAndChildTerminalRetriesUnchanged",
                        "freshChildNativeHumanAfterRestartVerified", "policyChangeChildAuthorityVerified"):
                changed = {**s, "readinessObservation": {**o, key: False}}
                self.assertEqual("BEHAVIOR_FAILURE", policy.classify(changed))


class PeerOriginProducerControls(unittest.TestCase):
    def test_actual_producer_retains_original_commands_for_restart_and_saved_retry(self):
        # IO stubs exercise only the producer's transient handoff, never native acceptance.
        account = "00000000-0000-4000-8000-000000000001"
        group = "offline-peer-group"
        scope = {"workflowId": "offline-workflow", "inviteId": "offline-invite"}
        approved = {"scopeDigest": "offline-scope", "approvalRequestDigest": "offline-request"}
        create = {"approvalReceipt": "offline-issued", "scopeDigest": "offline-scope",
            "authorizationRevision": 1, "creationFingerprint": "offline-fingerprint",
            "execution": {"executionId": "offline-execution"},
            "account": {"password": "offline-password-sentinel"}}
        terminal = {"state": "COMMITTED", "terminalReceipt": "offline-terminal"}
        transition = {"accountId": account, "terminalReceipt": terminal["terminalReceipt"]}
        native_receipt = {"realmId": "offline-realm", "attemptId": "offline-attempt",
            "accountId": account, "state": "COMMITTED", "operation": "commit",
            "ownerClient": peer.ACTORS["ACCOUNT_CREATE"][0],
            "ownerSubject": peer.SUBJECTS["ACCOUNT_CREATE"], "groupId": group,
            "creationFingerprint": create["creationFingerprint"],
            "executionId": create["execution"]["executionId"], "generation": 0}
        config = {"peerDelegationPolicies": [{"id": peer.POLICY, "sourceProfileId": peer.PROFILE}],
            "bindings": [{"subject": "offline-other-human"}]}
        helper = Mock()
        helper.approved_creation.return_value = ("offline-approval", "offline-attempt", scope, approved, create)
        helper.protected_machine_request.side_effect = [(201, {"accountId": account, "creationProof": "offline-original-creation"}),
            (200, terminal), (200, {"state": "CONSUMED", "boundAttemptId": "offline-attempt",
                "transitionReceipt": {**transition, "receipt": "offline-consume"}})]
        helper.verified_receipt.side_effect = [transition, native_receipt]
        helper.scope.return_value = scope
        helper.endpoint.side_effect = lambda approval: approval
        client_ids = {actor: "offline-client-" + actor for actor in peer.ACTORS}
        native = {"id": account, "enabled": True, "attributes": {"tenantId": [str(peer.TENANT)]}}
        calls = []
        for actor, (client, _) in peer.ACTORS.items():
            calls.extend([[("GET", "/clients?clientId=" + client), [{"id": client_ids[actor]}]],
                [("GET", "/clients/" + client_ids[actor] + "/service-account-user"), {"id": peer.SUBJECTS[actor]}]])
        calls.extend([
            [("GET", "/groups/" + group + "/role-mappings/realm/composite"), [{"name": "tenant-admin"}]],
            [("GET", "/users/" + account), {"id": account, "enabled": False}],
            [("GET", "/users/" + account + "/groups"), [{"path": "/pending-provisioning"}]],
            [("GET", "/users/" + account), native],
            [("GET", "/users/" + account + "/groups"), [{"id": group}]],
            [("GET", "/users/" + account + "/role-mappings/realm"), []],
            [("GET", "/users/count"), 1], [("GET", "/users/count"), 1]])
        def admin(*args):
            expected, result = calls.pop(0)
            self.assertEqual(expected, args)
            return result
        helper.admin.side_effect = admin
        def approve(base, method, route, body, bearer):
            self.assertEqual(("PUT", {"scope": scope}, "offline-human-sentinel"), (method, body, bearer))
            issued = {"issuerSubject": account, "approvalId": route,
                "scopeDigest": "offline-child-scope"}
            helper.verified_receipt.side_effect = None
            helper.verified_receipt.return_value = issued
            return 201, {"state": "AUTHORIZED", "scopeDigest": "offline-child-scope",
                "approvalReceipt": {**issued, "receipt": "offline-peer-issued"}}
        case = peer.PeerReadiness("runTest")
        case.peer_human = Mock(return_value="offline-human-sentinel")
        case.addCleanup = Mock()
        with patch.object(peer, "PeerFixture") as fixture, patch.object(peer, "inspect_owned", return_value={"Id": "offline-container"}), patch.object(peer, "config_values", return_value={"ORISO_PROTECTED_INVITATIONS_CONFIG": peer.json.dumps(config)}), patch.object(peer, "call", side_effect=approve):
            fixture.return_value = helper
            fixture.configuration_checked = True
            fixture.native_image_ids = ["offline-image"] * 2
            fixture.client_ids = client_ids
            fixture.installed_configuration = config
            fixture.peer_group_id = group
            fixture.realm_id = "offline-realm"
            case.test_committed_tenant_admin_approves_own_tenant_peer_without_person_config()
        self.assertEqual([], calls)
        original = case.peer_origin
        self.assertEqual(("offline-approval", "offline-attempt"), original[:2])
        self.assertIs(create, original[2])
        self.assertIs(helper.protected_machine_request.call_args_list[1].args[2], original[3])
        self.assertIs(terminal, original[4])
        self.assertEqual(account, case.peer_case[1])


if __name__ == "__main__":
    unittest.main()
