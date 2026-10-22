"""A committed native tenant administrator retains finite own-tenant peer authority."""

import base64
import copy
import json
import time
import unittest
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, REALM, call
from protected_binding_readiness import NativeFixture, config_values, inspect_owned
from protected_resources import require_active


PROFILE = "tenant-peer-v1"
OTHER_PROFILE = "tenant-other-v1"
POLICY = "own-tenant-admin-v1"
TENANT = 17


class PeerFixture(NativeFixture):
    @classmethod
    def prepare_installation(cls, helper, configuration):
        parent = helper.group_id("/protected-admins")
        helper.admin("POST", "/groups/" + parent + "/children", {"name": "tenant-peers"})
        cls.peer_group_id = helper.group_id("/protected-admins/tenant-peers")
        role = helper.admin("GET", "/roles/tenant-admin")
        helper.admin(
            "POST", "/groups/" + cls.peer_group_id + "/role-mappings/realm", [role]
        )
        profile = copy.deepcopy(configuration["profiles"][0])
        profile.update(
            id=PROFILE,
            kind="TENANT_ADMIN",
            tenantModes=["EXISTING", "RESERVED_NEW"],
            groupId=cls.peer_group_id,
            groupPath="/protected-admins/tenant-peers",
            realmRoles=["tenant-admin"],
        )
        configuration["profiles"].append(profile)
        other = copy.deepcopy(profile)
        other["id"] = OTHER_PROFILE
        configuration["profiles"].append(other)
        configuration["bindings"][0]["protectedProfileIds"].extend([PROFILE, OTHER_PROFILE])
        configuration["bindings"][0]["protectedProfileIds"].sort()
        configuration["peerDelegationPolicies"] = [
            {
                "id": POLICY,
                "version": 1,
                "sourceProfileId": PROFILE,
                "sourceProfileVersion": 1,
                "humanClientIds": ["protected-human-web"],
                "audienceSets": [["userservice"]],
                "protectedProfileIds": [PROFILE],
                "realmRoles": ["tenant-admin"],
                "clientRoles": {},
            }
        ]
        cls.installed_configuration = copy.deepcopy(configuration)
        return configuration

    def scope(self):
        result = super().scope()
        result.update(
            protectedKind="TENANT_ADMIN",
            targetTenantIds=[TENANT],
            protectedProfileId=PROFILE,
        )
        return result


REQUIRED = (
    "allFiveCurrentNativeClientLinksVerified",
    "installedFinitePeerPolicyAndProfileVerified",
    "originalHumanApprovalAndDisabledCreateVerified",
    "actualNativeCommitAndConsumedApprovalVerified",
    "exactEnabledPeerNativeProfileAndTenantVerified",
    "actualPeerTokenIssuerClientAudienceAndGrantsVerified",
    "actualPeerUserinfoAndCurrentSessionVerified",
    "sameRuntimeWithoutPerPersonBindingOrRestartVerified",
    "peerApprovalAccountCountUnchanged",
)


def classify(summary):
    observed = summary.get("readinessObservation", {})
    images = summary.get("nativeImageIds", [])
    if not (
        summary.get("executed") == 1
        and summary.get("errors") == 0
        and summary.get("skipped") == 0
        and all(observed.get(key) is True for key in REQUIRED)
        and len(images) == 2
        and len(set(images)) == 1
        and observed.get("sourceApproveStatus") == 201
        and observed.get("sourceCreateStatus") == 201
        and observed.get("sourceCommitStatus") == 200
        and observed.get("sourceConsumedStatus") == 200
    ):
        return "INPUT_OR_FIXTURE_ERROR"
    if summary.get("failures") == 1 and observed.get("peerApproveStatus") == 403:
        return "GENUINE_COMMITTED_OWN_TENANT_PEER_APPROVAL_RED"
    if (
        summary.get("failures") == 0
        and observed.get("peerApproveStatus") == 201
        and observed.get("exactPeerIssuedReceiptVerified") is True
    ):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


class PeerReadiness(unittest.TestCase):
    observation = {}

    def clean_native(self):
        PeerFixture.doClassCleanups()
        self.assertEqual([], PeerFixture.tearDown_exceptions)

    def test_committed_tenant_admin_approves_own_tenant_peer_without_person_config(self):
        type(self).observation = {}
        observed = self.observation
        self.addCleanup(self.clean_native)
        PeerFixture.setUpClass()
        helper = PeerFixture("runTest")
        self.assertTrue(PeerFixture.configuration_checked)
        self.assertEqual(2, len(PeerFixture.native_image_ids))
        for actor, (client, _) in ACTORS.items():
            clients = helper.admin("GET", "/clients?clientId=" + client)
            self.assertEqual(1, len(clients))
            self.assertEqual(PeerFixture.client_ids[actor], clients[0]["id"])
            self.assertEqual(
                SUBJECTS[actor],
                helper.admin(
                    "GET", "/clients/" + clients[0]["id"] + "/service-account-user"
                )["id"],
            )
        observed["allFiveCurrentNativeClientLinksVerified"] = True
        before_runtime = inspect_owned(PeerFixture)
        config = json.loads(config_values(before_runtime)["ORISO_PROTECTED_INVITATIONS_CONFIG"])
        self.assertEqual(PeerFixture.installed_configuration, config)
        self.assertEqual(POLICY, config["peerDelegationPolicies"][0]["id"])
        self.assertEqual(PROFILE, config["peerDelegationPolicies"][0]["sourceProfileId"])
        self.assertEqual(
            {"tenant-admin"},
            {role["name"] for role in helper.admin(
                "GET", "/groups/" + PeerFixture.peer_group_id + "/role-mappings/realm/composite"
            )},
        )
        observed["installedFinitePeerPolicyAndProfileVerified"] = True
        approval, attempt, scope, approved, create = helper.approved_creation()
        observed["sourceApproveStatus"] = 201
        status, opened = helper.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        observed["sourceCreateStatus"] = status
        self.assertEqual(201, status)
        account = opened["accountId"]
        self.assertEqual(account, str(uuid.UUID(account)))
        native = helper.admin("GET", "/users/" + account)
        self.assertFalse(native["enabled"])
        self.assertEqual(
            ["/pending-provisioning"],
            [group["path"] for group in helper.admin("GET", "/users/" + account + "/groups")],
        )
        observed["originalHumanApprovalAndDisabledCreateVerified"] = True
        commit = {key: create[key] for key in (
            "approvalReceipt", "scopeDigest", "authorizationRevision", "creationFingerprint", "execution"
        )}
        commit.update(
            accountId=account,
            creationProof=opened["creationProof"],
            localCommit={"journalVersion": 1, "outboxId": str(uuid.uuid4()), "effectsDigest": "a" * 64},
        )
        status, terminal = helper.protected_machine_request(
            "commit", approval, commit, actor="ACCOUNT_CREATE", attempt=attempt
        )
        observed["sourceCommitStatus"] = status
        self.assertEqual(200, status)
        self.assertEqual("COMMITTED", terminal["state"])
        query = {
            "scopeDigest": approved["scopeDigest"],
            "workflowId": scope["workflowId"],
            "inviteId": scope["inviteId"],
            "authorizationRevision": 1,
            "attemptId": attempt,
            "approvalRequestDigest": approved["approvalRequestDigest"],
        }
        status, consumed = helper.protected_machine_request("status", approval, query)
        observed["sourceConsumedStatus"] = status
        self.assertEqual(200, status)
        self.assertEqual("CONSUMED", consumed["state"])
        self.assertEqual(attempt, consumed["boundAttemptId"])
        transition = consumed["transitionReceipt"]
        verified = helper.verified_receipt(
            transition["receipt"], "protected-approval-consume/v1", 24000,
            {"operation", "state", "approvalId", "scopeDigest", "boundAttemptId", "accountId", "terminalReceipt"},
        )
        self.assertEqual({**verified, "receipt": transition["receipt"]}, transition)
        self.assertEqual(account, transition["accountId"])
        self.assertEqual(terminal["terminalReceipt"], transition["terminalReceipt"])
        native_receipt = helper.verified_receipt(
            terminal["terminalReceipt"], "terminal-receipt", 16000,
            {"realmId", "attemptId", "accountId", "ownerClient", "ownerSubject", "scope",
             "creationFingerprint", "groupId", "roleFingerprint", "state", "generation",
             "executionId", "operation", "commandDigest"},
        )
        self.assertEqual(PeerFixture.realm_id, native_receipt["realmId"])
        self.assertEqual(attempt, native_receipt["attemptId"])
        self.assertEqual(account, native_receipt["accountId"])
        self.assertEqual("COMMITTED", native_receipt["state"])
        self.assertEqual("commit", native_receipt["operation"])
        self.assertEqual(ACTORS["ACCOUNT_CREATE"][0], native_receipt["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_CREATE"], native_receipt["ownerSubject"])
        self.assertEqual(PeerFixture.peer_group_id, native_receipt["groupId"])
        self.assertEqual(create["creationFingerprint"], native_receipt["creationFingerprint"])
        self.assertEqual(create["execution"]["executionId"], native_receipt["executionId"])
        self.assertEqual(0, native_receipt["generation"])
        observed["actualNativeCommitAndConsumedApprovalVerified"] = True
        native = helper.admin("GET", "/users/" + account)
        self.assertTrue(native["enabled"])
        self.assertIsNone(native.get("serviceAccountClientLink"))
        self.assertEqual([str(TENANT)], native["attributes"]["tenantId"])
        self.assertEqual(
            [PeerFixture.peer_group_id],
            [group["id"] for group in helper.admin("GET", "/users/" + account + "/groups")],
        )
        self.assertEqual([], helper.admin("GET", "/users/" + account + "/role-mappings/realm"))
        observed["exactEnabledPeerNativeProfileAndTenantVerified"] = True
        bearer = self.peer_human(helper, native, create["account"]["password"])
        observed["actualPeerTokenIssuerClientAudienceAndGrantsVerified"] = True
        observed["actualPeerUserinfoAndCurrentSessionVerified"] = True
        self.assertNotIn(account, {binding["subject"] for binding in config["bindings"]})
        self.assertEqual(before_runtime["Id"], inspect_owned(PeerFixture)["Id"])
        self.assertEqual(
            config, json.loads(config_values(inspect_owned(PeerFixture))["ORISO_PROTECTED_INVITATIONS_CONFIG"])
        )
        observed["sameRuntimeWithoutPerPersonBindingOrRestartVerified"] = True
        count = helper.admin("GET", "/users/count")
        child, child_scope = str(uuid.uuid4()), helper.scope()
        PeerFixture.phase = "committed-own-tenant-peer-approval"
        status, result = call(helper.base, "PUT", helper.endpoint(child), {"scope": child_scope}, bearer)
        observed["peerApproveStatus"] = status
        observed["peerApprovalAccountCountUnchanged"] = count == helper.admin("GET", "/users/count")
        self.assertTrue(observed["peerApprovalAccountCountUnchanged"])
        self.assertEqual(201, status)
        self.assertEqual("AUTHORIZED", result["state"])
        receipt = result["approvalReceipt"]
        verified = helper.verified_receipt(
            receipt["receipt"], "protected-approval-receipt/v1", 16384,
            {"approvalId", "scopeDigest", "issuerSubject", "bindingVersion", "profileVersion", "validUntil", "approvalRequestDigest"},
        )
        self.assertEqual({**verified, "receipt": receipt["receipt"]}, receipt)
        self.assertEqual(account, receipt["issuerSubject"])
        self.assertEqual(child, receipt["approvalId"])
        self.assertEqual(result["scopeDigest"], receipt["scopeDigest"])
        observed["exactPeerIssuedReceiptVerified"] = True
        # Transient test-only context for a distinct public cancellation tracer.
        self.peer_case = (helper, account, bearer, child, child_scope, result)

    def peer_human(self, helper, native, password):
        require_active("peer-human-preconditions")
        status, result = call(
            helper.base, "POST", "/realms/" + REALM + "/protocol/openid-connect/token",
            {"client_id": "protected-human-web", "grant_type": "password",
             "username": native["username"], "password": password, "scope": "openid"},
            form=True,
        )
        self.assertEqual(200, status)
        bearer = result["access_token"]
        payload = bearer.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(native["id"], claims["sub"])
        self.assertEqual(PeerFixture.native_issuer, claims["iss"])
        self.assertEqual("protected-human-web", claims["azp"])
        self.assertEqual(str(TENANT), claims["tenantId"])
        audiences = claims["aud"]
        self.assertEqual({"userservice"}, set([audiences] if isinstance(audiences, str) else audiences))
        self.assertEqual({"tenant-admin"}, set(claims["realm_access"]["roles"]))
        self.assertFalse(claims.get("resource_access"))
        self.assertLess(claims["iat"], claims["exp"])
        self.assertGreater(claims["exp"], time.time())
        current_roles = helper.admin("GET", "/users/" + native["id"] + "/role-mappings/realm/composite")
        self.assertEqual({"tenant-admin"}, {role["name"] for role in current_roles})
        self.assertFalse(helper.admin("GET", "/users/" + native["id"] + "/role-mappings").get("clientMappings"))
        clients = helper.admin("GET", "/clients?clientId=protected-human-web")
        self.assertEqual(1, len(clients))
        client = helper.admin("GET", "/clients/" + clients[0]["id"])
        self.assertTrue(client["enabled"])
        self.assertTrue(client["standardFlowEnabled"])
        self.assertFalse(client["serviceAccountsEnabled"])
        self.assertFalse(client["fullScopeAllowed"])
        status, info = call(helper.base, "GET", "/realms/" + REALM + "/protocol/openid-connect/userinfo", token=bearer)
        self.assertEqual(200, status)
        self.assertEqual(native["id"], info["sub"])
        sessions = helper.admin("GET", "/users/" + native["id"] + "/sessions")
        current = [session for session in sessions if session["id"] == claims["sid"]]
        self.assertEqual(1, len(current))
        self.assertEqual("protected-human-web", current[0]["clients"][client["id"]])
        return bearer
