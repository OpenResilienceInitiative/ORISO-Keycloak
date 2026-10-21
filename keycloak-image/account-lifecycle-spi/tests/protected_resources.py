"""Explicit resource policies for the protected native proof, never production code."""

import os
from pathlib import Path
import platform
import re
import subprocess
import time

GIB = 1024**3
HOSTED_PROFILE = "github-ubuntu-24-amd64-v1"
_observations = []


class ResourceGateError(RuntimeError):
    pass


def sample(phase):
    system = platform.system()
    profile = os.environ.get("PROTECTED_PROOF_RESOURCE_PROFILE")
    if system == "Darwin":
        if profile not in (None, "macos-memory-pressure-v1"):
            raise ResourceGateError(
                "Hosted resource policy cannot replace the Mac guard"
            )
        output = subprocess.run(
            ["memory_pressure"], check=True, capture_output=True, text=True, timeout=15
        ).stdout
        match = re.search(r"System-wide memory free percentage: (\d+)%", output)
        if match is None:
            raise ResourceGateError("Native Mac memory measurement unavailable")
        pressure = subprocess.run(
            ["sysctl", "-n", "kern.memorystatus_vm_pressure_level"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout.strip()
        if not 0 <= int(match[1]) <= 100:
            raise ResourceGateError("Invalid native Mac memory percentage")
        if not pressure.isdecimal():
            raise ResourceGateError("Native Mac pressure level unavailable")
        value = {
            "profile": "macos-memory-pressure-v1",
            "phase": phase,
            "freePercent": int(match[1]),
            "pressureLevel": int(pressure),
        }
    elif system == "Linux" and profile == HOSTED_PROFILE:
        expected = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
        }
        if any(os.environ.get(key) != required for key, required in expected.items()):
            raise ResourceGateError(
                "Hosted policy requires the declared fresh GitHub runner"
            )
        release = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                release[key] = value.strip('"')
        if (
            release.get("ID") != "ubuntu"
            or release.get("VERSION_ID") != "24.04"
            or platform.machine() != "x86_64"
        ):
            raise ResourceGateError("Hosted policy requires Ubuntu24.04 amd64")
        memory = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] == "kB":
                memory[parts[0].removesuffix(":")] = int(parts[1]) * 1024
        total, available = memory.get("MemTotal", 0), memory.get("MemAvailable", 0)
        if total < 6 * GIB or not 0 <= available <= total:
            raise ResourceGateError(
                "Hosted memory measurement below supported runner size"
            )
        value = {
            "profile": HOSTED_PROFILE,
            "phase": phase,
            "freePercent": 100 * available // total,
            "availableBytes": available,
            "totalBytes": total,
            "containerHardBytes": GIB,
        }
    else:
        raise ResourceGateError("No approved resource policy for this runtime")
    _observations.append(value)
    return value


def permitted(value, starting):
    if value["freePercent"] < (35 if starting else 25):
        return False
    if value["profile"] == "macos-memory-pressure-v1":
        return value["pressureLevel"] <= 1
    return value["availableBytes"] >= (3 if starting else 2) * GIB


def require_start():
    deadline = time.monotonic() + 60
    while True:
        value = sample("before-native-start")
        if permitted(value, starting=True):
            print("Protected resource decision:", value, flush=True)
            return
        if time.monotonic() >= deadline:
            raise ResourceGateError("Native launch resource gate expired after60s")
        time.sleep(5)


def require_active(phase):
    value = sample(phase)
    if not permitted(value, starting=False):
        raise ResourceGateError("Native proof resource floor violated")


def evidence():
    return {
        "measurements": len(_observations),
        "minimumFreePercent": min(
            (v["freePercent"] for v in _observations), default=None
        ),
        "startDecisions": [
            v for v in _observations if v["phase"] == "before-native-start"
        ],
        "lastMeasurement": _observations[-1] if _observations else None,
        "noSyntheticMacMeasurements": True,
    }
