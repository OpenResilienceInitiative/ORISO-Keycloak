"""Keep both Keycloak image publish paths behind the same scan."""
from pathlib import Path
import re
import unittest

GITHUB = Path(__file__).resolve().parents[1] / ".github"
SHARED_BUILD = "uses: ./.github/actions/docker-build-push"


class ImagePublish(unittest.TestCase):
    def test_workflows_share_the_gate_and_keep_the_keycloak_context(self):
        for workflow, push in (("ci-main", "true"),
                               ("ci-pull-request", "false"),
                               ("release-image", "true")):
            with self.subTest(workflow=workflow):
                source = (GITHUB / "workflows" / f"{workflow}.yml").read_text()
                self.assertIn(SHARED_BUILD, source)
                self.assertNotIn("uses: docker/build-push-action@", source)
                shared_step = re.split(r"(?m)^ *- name: ", source.split(SHARED_BUILD, 1)[1])[0]
                self.assertIn(f"push_to_ghcr: {push}", shared_step)
                self.assertIn("context: keycloak-image", shared_step)
                if workflow == "release-image":
                    self.assertIn("image_tags: ${{ env.IMAGE }}", shared_step)
                    self.assertLess(source.index(SHARED_BUILD), source.index("git push origin"))

    def test_the_local_build_passes_trivy_before_publishing(self):
        source = (GITHUB / "actions" / "docker-build-push" / "action.yml").read_text()
        steps = re.split(r"(?m)^ *- name: ", source)[1:]
        local = next((step for step in steps if "load: true" in step), "")
        scan = next((step for step in steps if "uses: aquasecurity/trivy-action@" in step), "")
        publish = next(step for step in steps if "push: ${{ inputs.push_to_ghcr }}" in step)
        self.assertTrue(local and scan, "a local image and a scan step are required")
        self.assertLess(steps.index(local), steps.index(scan))
        self.assertLess(steps.index(scan), steps.index(publish))
        for step in local, publish:
            self.assertIn("context: ${{ inputs.context }}", step)
            self.assertIn("platforms: linux/amd64", step)
        self.assertIn("push: false", local)
        self.assertIn("tags: ${{ inputs.image_name }}:ci-scan", local)
        self.assertIn("image-ref: ${{ inputs.image_name }}:ci-scan", scan)
        self.assertIn("exit-code: '1'", scan)
        self.assertIn("ignore-unfixed: true", scan)
        self.assertIn("vuln-type: os,library", scan)
        self.assertIn("severity: CRITICAL,HIGH", scan)
        self.assertNotRegex(scan, r"(?m)^\s*(if|continue-on-error):")
        self.assertNotRegex(publish, r"always\(\)|continue-on-error:")
        self.assertIn("type=raw,value=26.8.2-otp,", source)
