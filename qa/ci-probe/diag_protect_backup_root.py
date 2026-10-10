"""Probe the vault backup ACL helper without exposing host identity details."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from leviathan_vault.transaction import _PRIVATE_DIRECTORY_SCRIPT

STAGES = {
    0: "OK",
    11: "OWNER_READ",
    12: "OWNER_MISMATCH",
    13: "ACL_SET",
    14: "ACL_VERIFY",
    15: "INHERITANCE",
}

OWNER_STATE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $adminSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $elevation = if ($principal.IsInRole($adminSid)) { 'admin' } else { 'not_admin' }
    $owner = (Get-Acl -LiteralPath $env:XYRA_IMPORT_BACKUP_ROOT).GetOwner(
        [Security.Principal.SecurityIdentifier]).Value
    if ($owner -eq $identity.User.Value) { $category = 'current_user' }
    elseif ($owner -eq 'S-1-5-32-544') { $category = 'Administrators' }
    else { $category = 'other' }
    Write-Output "$elevation|$category"
} catch { 'unknown|other' }
"""


def main() -> int:
    powershell = shutil.which("powershell.exe")
    if os.name != "nt" or powershell is None:
        print("stage=OWNER_READ helper_exit_status=126 elevation=unknown owner_category=other")
        return 0

    with tempfile.TemporaryDirectory(prefix="leviathan-acl-probe-") as temporary:
        backup_root = Path(temporary) / ".local" / "registry-backups"
        backup_root.mkdir(parents=True)
        environment = {**os.environ, "XYRA_IMPORT_BACKUP_ROOT": str(backup_root)}
        helper = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _PRIVATE_DIRECTORY_SCRIPT,
            ],
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        state = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                OWNER_STATE_SCRIPT,
            ],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        lines = state.stdout.strip().splitlines()
        identity_state = lines[-1].split("|") if lines else []
        if len(identity_state) != 2:
            elevation, owner_category = "unknown", "other"
        else:
            elevation, owner_category = identity_state
        stage = STAGES.get(helper.returncode, "OWNER_READ")
        print(
            f"stage={stage} helper_exit_status={helper.returncode} "
            f"elevation={elevation} owner_category={owner_category}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
