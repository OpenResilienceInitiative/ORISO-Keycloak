import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile

spec = importlib.util.spec_from_file_location("s1_proof", Path(__file__).parents[1] / "ci/session-exchange-proof.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class SessionProofControls(unittest.TestCase):
    def row(self):
        observed = dict.fromkeys(p.OBSERVATION_FLAGS, True)
        observed["magicStatus"] = 401
        return {"observed": observed,"sessionChecks":dict.fromkeys(p.SESSION_CHECK_FLAGS,True), "counts": {"tests":1,"failures":1,"errors":0,"skipped":0},
                "cases":[{"name":"test_checked_claim_enters_native_session_path", "outcome":"failure"}]}

    def test_only_full_proved_precondition_inventory_earns_assertion_red(self):
        self.assertEqual("ACTUAL_NATIVE_SESSION_ASSERTION_RED", p.native_classification(self.row()))
        good = self.row()
        good["observed"].update(magicStatus=200,nativeRouterSelected=False)
        good["counts"]["failures"] = 0
        good["cases"][0]["outcome"] = "pass"
        self.assertEqual("NATIVE_TRACER_GREEN_INCOMPLETE",p.native_classification(good))
        reached=self.row(); reached["observed"]["nativeRouterSelected"]=False
        self.assertEqual("ACTUAL_NATIVE_SESSION_ASSERTION_FAILURE",p.native_classification(reached))
        reached["observed"]["magicStatus"]=0
        with self.assertRaises(RuntimeError):p.native_classification(reached)

    def test_failed_unknown_and_missing_preconditions_never_count_as_native_red(self):
        for key in p.OBSERVATION_FLAGS:
            for value in (False,None,1,"true"):
                row = self.row()
                row["observed"][key] = value
                if key == "nativeRouterSelected" and value is False:
                    self.assertEqual("ACTUAL_NATIVE_SESSION_ASSERTION_FAILURE",p.native_classification(row))
                else:
                    with self.subTest(key=key,value=value), self.assertRaises(RuntimeError):
                        p.native_classification(row)

    def test_wrong_counts_skips_errors_and_names_never_count_as_native_red(self):
        for key in ("tests","failures","errors","skipped"):
            for value in (True,-1,2):
                row = self.row()
                row["counts"][key] = value
                if key == "nativeRouterSelected" and value is False:
                    self.assertEqual("ACTUAL_NATIVE_SESSION_ASSERTION_FAILURE",p.native_classification(row))
                else:
                    with self.subTest(key=key,value=value), self.assertRaises(RuntimeError):
                        p.native_classification(row)
        row = self.row()
        row["cases"][0]["name"] = "unrelated"
        with self.assertRaises(RuntimeError): p.native_classification(row)

    def test_arbitrary_attributes_and_private_values_are_refused_before_export(self):
        for field,value in (("rawToken","private-do-not-export"),("magicStatus","private"),
                            ("commandMacValid","private")):
            row = self.row()["observed"]
            row[field] = value
            with self.subTest(field=field),self.assertRaises(RuntimeError):
                p.checked_observation(row)

    def test_groups_require_all_distinct_positive_integer_known_absent(self):
        good=[{"processGroup":1,"confirmedAbsent":True},{"processGroup":2,"confirmedAbsent":True}]
        self.assertTrue(p.groups_ok(good,2))
        for mutate in (lambda x:x.pop(),lambda x:x[1].update(processGroup=1),
                       lambda x:x[0].update(processGroup=True),lambda x:x[0].update(processGroup=0),
                       lambda x:x[0].update(confirmedAbsent=False),lambda x:x[0].pop("confirmedAbsent")):
            bad=copy.deepcopy(good);mutate(bad)
            self.assertFalse(p.groups_ok(bad,2))

    def test_formatter_cannot_change_adjacent_untracked_or_empty_sources(self):
        self.assertTrue(p.format_allowed([p.USER_FILES[0]],""))
        self.assertFalse(p.format_allowed([],""))
        self.assertFalse(p.format_allowed([p.USER_FILES[0]],"untracked.java"))
        self.assertFalse(p.format_allowed(["src/main/java/Adjacent.java"],""))

    def test_only_confirmed_formatter_failure_can_trigger_private_proposal(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/"compile.log"
            secret="private-provider-message-never-export"
            log.write_text("spotless-maven-plugin:check "+secret)
            self.assertIs(p.compile_diagnostics(log)["spotlessConfirmed"],False)
            log.write_text("The following files had format violations:\nRun 'mvn spotless:apply'\n/secret/path/MagicLinkAuthority.java:[65,15] "+secret+"\n/secret/path/Unknown.java:[7,8] private")
            result=p.compile_diagnostics(log)
            self.assertIs(result["spotlessConfirmed"],True)
            self.assertNotIn(secret,str(result))
            self.assertEqual({"spotlessConfirmed","ownedFilesMentioned","compilerFailure","ownedSourceFrames"},set(result))
            self.assertEqual([{"file":"MagicLinkAuthority.java","line":65,"column":15}],result["ownedSourceFrames"])
            self.assertNotIn("/secret",str(result))

    def test_formatter_replaces_unstarted_tests_in_exact_three_group_catalogue(self):
        self.assertEqual(["toolchain","user-compile","user-formatter"],p.planned_groups("user",True))
        self.assertEqual(["toolchain","user-compile","user-tests"],p.planned_groups("user",False))
        self.assertEqual(["toolchain","user-compile","lifecycle-compile","otp-compile","native-test"],p.planned_groups("native",False))
        with self.assertRaises(RuntimeError):p.planned_groups("user","true")
        self.assertEqual(p.planned_groups("user",True),p.planned_groups("native",True))
        with self.assertRaises(RuntimeError):p.planned_groups("unknown",False)
        three=[{"processGroup":i,"confirmedAbsent":True} for i in (1,2,3)]
        self.assertTrue(p.groups_ok(three,len(p.planned_groups("user",True))))
        self.assertFalse(p.groups_ok(three[:2],len(p.planned_groups("user",True))))
        self.assertTrue(p.named_groups_ok(three,p.planned_groups("user",True),p.planned_groups("user",True)))
        self.assertFalse(p.named_groups_ok(three,p.planned_groups("user",False),p.planned_groups("user",True)))
        self.assertFalse(p.named_groups_ok(three[:2],p.planned_groups("user",True),p.planned_groups("user",True)))

    def test_failed_worktree_add_can_remove_only_its_exact_owned_empty_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            scratch=Path(tempfile.mkdtemp(prefix="s1-owned-user-format-",dir=root))
            stat=scratch.stat();owner=(stat.st_dev,stat.st_ino,stat.st_uid)
            self.assertTrue(p.empty_owned_scratch(scratch,owner,root))
            self.assertFalse(p.empty_owned_scratch(scratch,(owner[0],owner[1]+1,owner[2]),root))
            self.assertFalse(p.empty_owned_scratch(scratch,owner,root/"other"))
            (scratch/"foreign").write_text("do not remove")
            self.assertFalse(p.empty_owned_scratch(scratch,owner,root))

    def test_python_failure_exports_only_fixed_type_and_allowlisted_source_position(self):
        import sys
        allowed=Path(p.__file__).resolve().parents[2]/"keycloak-image/account-lifecycle-spi/tests/session_exchange_native.py"
        try:
            exec(compile("raise KeyError('private-do-not-export')",str(allowed),"exec"))
        except KeyError:
            result=p.safe_python_failure(sys.exc_info())
        self.assertEqual({"type":"KeyError","sourceFrames":[{"file":allowed.name,"line":1}]},result)
        self.assertNotIn("private",str(result))
        try:
            raise RuntimeError("arbitrary-private-message")
        except RuntimeError:
            self.assertEqual({"type":"OTHER","sourceFrames":[]},p.safe_python_failure(sys.exc_info()))

    def test_green_requires_all_fixed_session_checks_and_never_exports_arbitrary_values(self):
        for flag in p.SESSION_CHECK_FLAGS:
            for value in (False,None,1,"true"):
                row=self.row();row["observed"].update(magicStatus=200,nativeRouterSelected=False)
                row["counts"]["failures"]=0;row["cases"][0]["outcome"]="pass"
                row["sessionChecks"][flag]=value
                with self.subTest(flag=flag,value=value),self.assertRaises(RuntimeError):p.native_classification(row)
        checks=dict.fromkeys(p.SESSION_CHECK_FLAGS,True);checks["private"]="never-export"
        with self.assertRaises(RuntimeError):p.checked_session_checks(checks)
        facts=dict.fromkeys(p.TOKEN_FACT_FLAGS,False)
        self.assertEqual(facts,p.checked_token_facts(facts))
        facts["privateJWT"]="never-export"
        with self.assertRaises(RuntimeError):p.checked_token_facts(facts)
        facts=dict.fromkeys(p.TOKEN_FACT_FLAGS,False);facts["subjectPresent"]=1
        with self.assertRaises(RuntimeError):p.checked_token_facts(facts)

    def test_runtime_requires_both_exact_owned_known_false_oom_integer_zero_restart(self):
        planned=[{"kind":"container","name":"kc"},{"kind":"container","name":"redis"},{"kind":"network","name":"net"}]
        good=[{**row,"confirmedAbsent":True,"runtime":{"oomKilled":False,"restartCount":0} if row["kind"]=="container" else None} for row in planned]
        self.assertTrue(p.runtime_known(good,planned))
        for mutate in (lambda x:x.clear(),lambda x:x.append(copy.deepcopy(x[0])),lambda x:x.pop(),
                       lambda x:x[1].update(name="foreign"),lambda x:x[1].update(name="kc"),
                       lambda x:x[1].update(confirmedAbsent=False),lambda x:x[2].update(confirmedAbsent=False),
                       lambda x:x[0]["runtime"].pop("oomKilled"),lambda x:x[1]["runtime"].update(oomKilled=None),
                       lambda x:x[0]["runtime"].update(oomKilled=True),lambda x:x[1]["runtime"].update(restartCount=False),
                       lambda x:x[0]["runtime"].update(restartCount=1)):
            bad=copy.deepcopy(good);mutate(bad)
            self.assertFalse(p.runtime_known(bad,planned))



    def test_user_inventory_preserves_three_original_and_all_adjacent_cases(self):
        good={name:{"tests":count,"failures":0,"errors":0,"skipped":0} for name,count in p.USER_SUITES.items()}
        self.assertEqual(60,sum(x["tests"] for x in good.values()))
        self.assertEqual(0,p.user_inventory(good))
        red=copy.deepcopy(good);red[p.USER_SUITE]["failures"]=1
        self.assertEqual(1,p.user_inventory(red))
        for mutate in (lambda x:x.pop(p.USER_SUITE),lambda x:x.update(unknown=x[p.USER_SUITE]),
                       lambda x:x[p.USER_SUITE].update(tests=2),lambda x:x[p.USER_SUITE].update(tests=True),
                       lambda x:x[p.USER_SUITE].update(errors=1),lambda x:x[p.USER_SUITE].update(skipped=1)):
            bad=copy.deepcopy(good);mutate(bad)
            with self.assertRaises(RuntimeError):p.user_inventory(bad)

    def test_user_exit_must_agree_with_xml_before_any_green_or_red_credit(self):
        green={name:{"tests":count,"failures":0,"errors":0,"skipped":0} for name,count in p.USER_SUITES.items()}
        red=copy.deepcopy(green);red[p.USER_SUITE]["failures"]=1
        self.assertEqual("USER_FOCUSED_GREEN",p.user_classification(green,0))
        self.assertEqual("USER_ASSERTION_RED",p.user_classification(red,1))
        for counts,status in ((green,1),(red,0),(green,124),(red,124),(green,-9),(red,-9),(green,True),(red,True),(green,None)):
            self.assertEqual("USER_SETUP_OR_INCONCLUSIVE",p.user_classification(counts,status))

    def test_paired_green_requires_exact_private_fixture_exit_inventory_and_booleans(self):
        good={"checks":dict.fromkeys(p.PAIR_FLAGS,True),"exit":0,
              "suites":{p.PAIR_SUITE:{"tests":1,"failures":0,"errors":0,"skipped":0}},"sourceFrames":[]}
        self.assertEqual("PAIRED_PRIVATE_CALLER_GREEN",p.pair_classification(good))
        red=copy.deepcopy(good);red["exit"]=1;red["suites"][p.PAIR_SUITE]["failures"]=1;red["checks"]["javaFixtureGreen"]=False
        self.assertEqual("PAIRED_PRIVATE_CALLER_ASSERTION_RED",p.pair_classification(red))
        for mutate in (lambda x:x.update(exit=124),lambda x:x.update(exit=True),lambda x:x.update(exit=1),
                       lambda x:x["checks"].update(childGroupInherited=False),
                       lambda x:x["checks"].update(firstNative200Dropped=False),
                       lambda x:x["checks"].update(firstNative200Dropped=1),
                       lambda x:x["checks"].update(privateJWT="never-export"),
                       lambda x:x["suites"][p.PAIR_SUITE].update(errors=1),
                       lambda x:x["suites"][p.PAIR_SUITE].update(skipped=1),lambda x:x["suites"].clear(),
                       lambda x:x.update(sourceFrames=[{"file":"private.java","line":1}]),
                       lambda x:x.update(sourceFrames=[{"file":"MagicLinkSessionNativeFixture.java","line":True}]),
                       lambda x:x.update(sourceFrames=[{"file":"MagicLinkSessionNativeFixture.java","line":1,"secret":"never"}])):
            bad=copy.deepcopy(good);mutate(bad)
            with self.assertRaises(RuntimeError):p.pair_classification(bad)

    def test_native_exit_must_agree_with_exact_xml_even_after_a_timeout(self):
        green={"tests":1,"failures":0,"errors":0,"skipped":0}
        red={**green,"failures":1}
        self.assertTrue(p.native_exit_agrees(green,0))
        self.assertTrue(p.native_exit_agrees(red,1))
        for counts,status in ((green,1),(red,0),(green,124),(red,-9),(green,True),(red,None),
                              ({**green,"errors":1},1),({**green,"skipped":1},0)):
            self.assertFalse(p.native_exit_agrees(counts,status))

    def test_only_exact_new_fixture_path_joins_failure_only_formatter_allowlist(self):
        fixture="src/test/java/de/caritas/cob/userservice/api/service/auth/MagicLinkSessionNativeFixture.java"
        self.assertIn(fixture,p.USER_FILES)
        self.assertTrue(p.format_allowed([fixture],""))
        self.assertFalse(p.format_allowed([fixture.replace("Fixture.java","FixtureAdjacent.java")],""))
        self.assertFalse(p.format_allowed([fixture],"untracked.java"))

if __name__ == "__main__": unittest.main()
