"""Static contracts for the Windows installer; the script itself is never run."""

from __future__ import annotations

import unittest
from pathlib import Path

INSTALLER = Path(__file__).resolve().parents[1] / "install.ps1"


class WindowsInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8-sig")

    def test_shims_use_utf8_and_switch_the_console_for_non_ascii_paths(self) -> None:
        # Set-Content -Encoding ASCII used to replace non-ASCII install paths
        # with '?', so the generated .cmd shims pointed at a file that did not exist.
        self.assertNotIn("-Encoding ASCII", self.source)
        self.assertIn("[IO.File]::WriteAllText($Shim, $Body", self.source)
        self.assertIn("chcp 65001 >nul", self.source)

    def test_protocol_is_chosen_from_the_scope_before_the_mode_is_set(self) -> None:
        self.assertIn(
            '$DesiredProtocol = if ($DesiredOpMode -eq "proxy") { "masque" } else { "wireguard" }',
            self.source,
        )
        protocol = self.source.index('Invoke-Warp @("tunnel", "protocol", "set", $DesiredProtocol)')
        mode = self.source.index('Invoke-Warp @("mode", $DesiredOpMode)')
        self.assertLess(protocol, mode)
        self.assertLess(self.source.index("$DesiredProtocol = if"), protocol)

    def test_unknown_protocol_is_not_silently_skipped(self) -> None:
        # An empty/unreadable settings value must still be corrected; the old
        # `if ($protocol -and ...)` guard skipped the repair exactly then.
        self.assertIn("if ($protocol -ne $DesiredProtocol) {", self.source)
        self.assertNotIn('if ($protocol -and $protocol -ne "wireguard")', self.source)


if __name__ == "__main__":
    unittest.main()
