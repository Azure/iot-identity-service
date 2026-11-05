import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(os.environ.get("IIS_REPO_ROOT", Path(__file__).resolve().parents[2]))
BRANCHES = ["main", "release/1.6", "release/1.5"]


def workflow(name):
    return yaml.load(
        (ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader
    )


class PackageWorkflowTests(unittest.TestCase):
    def test_push_pr_and_dispatch_remain_available(self):
        self.assertEqual(
            set(workflow("packages.yaml")["on"]),
            {"push", "pull_request", "workflow_dispatch"},
        )

    def test_package_binary_lock_and_snap_versions_match(self):
        packages = workflow("packages.yaml")
        version = next(
            step["env"]["PACKAGE_VERSION"]
            for step in packages["jobs"]["packages"]["steps"]
            if step.get("name") == "Run"
        )
        for crate in ("aziotctl", "aziotd"):
            manifest = (ROOT / crate / "Cargo.toml").read_text()
            self.assertEqual(
                re.search(r'^version = "([^"]+)"', manifest, re.M)[1], version
            )
            lock = (ROOT / "Cargo.lock").read_text()
            self.assertIn(f'name = "{crate}"\nversion = "{version}"', lock)
        snap = yaml.load(
            (ROOT / "snap/snapcraft.yaml").read_text(), Loader=yaml.BaseLoader
        )
        self.assertEqual(snap["version"], version)


class ReleaseWorkflowTests(unittest.TestCase):
    def test_all_e2e_stages_cover_supported_branches(self):
        jobs = workflow("e2e-tests-scheduled.yaml")["jobs"]
        for job in jobs.values():
            self.assertEqual(job["strategy"]["matrix"]["branch"], BRANCHES)
            self.assertEqual(job["strategy"]["max-parallel"], "10")
            checkout = next(step for step in job["steps"] if "uses" in step)
            self.assertEqual(checkout["with"]["ref"], "${{ matrix.branch }}")
        matrix = jobs["test-run"]["strategy"]["matrix"]
        self.assertEqual(
            len(matrix["branch"]) * len(matrix["os"]) * len(matrix["test_name"]), 48
        )

    def test_weekly_dispatch_uses_each_branch_workflow(self):
        scheduled = workflow("packages-scheduled.yaml")
        self.assertEqual(scheduled["on"]["schedule"], [{"cron": "0 0 * * 0"}])
        self.assertEqual(scheduled["permissions"], {"actions": "write"})
        job = scheduled["jobs"]["packages"]
        self.assertIn("github.repository == 'Azure/iot-identity-service'", job["if"])
        self.assertEqual(job["strategy"]["matrix"]["branch"], BRANCHES)
        self.assertEqual(job["strategy"]["fail-fast"], "false")
        step = job["steps"][0]
        self.assertEqual(step["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertEqual(step["env"]["GH_REPO"], "${{ github.repository }}")
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "dispatch"
            for branch in BRANCHES:
                result = subprocess.run(
                    ["bash", "-euc", 'gh() { printf "%s\\n" "$@" > "$LOG"; }\n'
                     + step["run"]],
                    env=dict(os.environ, BRANCH=branch, LOG=str(log)),
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    log.read_text().splitlines(),
                    ["workflow", "run", "packages.yaml", "--ref", branch],
                )

    def test_prerelease_and_ga_snap_grade(self):
        snap = yaml.load(
            (ROOT / "snap/snapcraft.yaml").read_text(), Loader=yaml.BaseLoader
        )
        script = snap["parts"]["iot-identity-services"]["override-build"]
        grade_script = script.split("contrib/third-party-notices.sh", 1)[0]
        for version, grade in (
            ("1.7.0-rc.1", "devel"),
            ("1.7.0-dev", "devel"),
            ("1.7.0", "stable"),
            ("1.6.1", "stable"),
        ):
            result = subprocess.run(
                ["bash", "-euc",
                 'craftctl() { if [ "$1" = get ]; then printf "%s\\n" "$VERSION"; '
                 'else printf "%s\\n" "$*"; fi; }\n' + grade_script],
                env=dict(os.environ, VERSION=version),
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f"set grade={grade}")

    def test_debian_release_candidate_sorts_before_ga(self):
        script = (ROOT / "ci/package.sh").read_text()
        conversion = script.split(
            "DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get install -y dh-make debhelper",
            1,
        )[1].split("make ARCH=", 1)[0]
        for version, expected in (("1.7.0-rc.1", "1.7.0~rc1"), ("1.7.0", "1.7.0")):
            result = subprocess.run(
                ["bash", "-euc", conversion + '\nprintf "%s" "$PACKAGE_VERSION"'],
                env=dict(os.environ, PACKAGE_VERSION=version),
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
        result = subprocess.run(
            ["dpkg", "--compare-versions", "1.7.0~rc1-1", "lt", "1.7.0-1"],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class ArtifactSelectionTests(unittest.TestCase):
    def run_get_package(self, events, branch="release/1.6", package=""):
        script = (ROOT / "ci/e2e-tests/test-run.sh").read_text()
        # Extract only this function: sourcing the full script provisions Azure resources.
        function = "get_package() {" + script.split("get_package() {", 1)[1].split(
            "\n}\n", 1
        )[0] + "\n}\n"
        runs = [
            {"event": event, "artifacts_url": f"https://fixtures.invalid/{index}"}
            for index, event in enumerate(events)
        ]
        mocks = r'''
curl() {
    local url="${@: -1}"
    printf '%s\n' "$url" >> "$REQUESTS"
    case "$url" in
        *'/runs?'*) printf '%s\n' "$RUNS_JSON" ;;
        https://fixtures.invalid/*)
            printf '%s\n' '{"artifacts":[{"name":"packages_debian-12-slim_amd64","archive_download_url":"https://download.invalid/package"}]}'
            ;;
        https://download.invalid/package) ;;
        *) echo "Unexpected request: $url" >&2; return 1 ;;
    esac
}
sleep() { :; }
unzip() {
    if [ "$1" != '-t' ]; then
        touch aziot-identity-service_fixture_amd64.deb
    fi
}
'''
        with tempfile.TemporaryDirectory() as temp:
            requests = Path(temp) / "requests"
            result = subprocess.run(
                ["bash", "-euc", mocks + function + "\nget_package"],
                cwd=temp, text=True, capture_output=True,
                env=dict(os.environ, BRANCH=branch, OS="debian:12",
                         GITHUB_API_URL="https://api.invalid",
                         GITHUB_REPOSITORY="Azure/iot-identity-service",
                         GITHUB_TOKEN="fixture", GITHUB_PAT="", PACKAGE=package,
                         RUNS_JSON=json.dumps({"workflow_runs": runs}),
                         REQUESTS=str(requests)),
            )
            urls = requests.read_text().splitlines() if requests.exists() else []
        return result, urls

    def test_latest_dispatch_build_is_selected_and_pr_is_excluded(self):
        for branch in BRANCHES:
            result, urls = self.run_get_package(
                ["pull_request", "workflow_dispatch", "push"], branch
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("branch=" + branch.replace("/", "%2f"), urls[0])
            self.assertIn("status=success", urls[0])
            self.assertNotIn("event=push", urls[0])
            self.assertEqual(urls[1], "https://fixtures.invalid/1")

    def test_newer_push_build_remains_preferred(self):
        result, urls = self.run_get_package(["push", "workflow_dispatch"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(urls[1], "https://fixtures.invalid/0")

    def test_no_eligible_run_fails_explicitly(self):
        for events in ([], ["pull_request", "workflow_run"]):
            result, urls = self.run_get_package(events)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No successfully-concluded packages workflow", result.stderr)
            self.assertEqual(len(urls), 4)

    def test_explicit_package_override_does_not_query_github(self):
        result, urls = self.run_get_package([], package="/tmp/fixture.deb")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/tmp/fixture.deb")
        self.assertEqual(urls, [])


if __name__ == "__main__":
    unittest.main()
