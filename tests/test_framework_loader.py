"""Tests for framework YAML loading and control resolution."""
from agent.framework_loader import get_framework_registry
from agent.models import System


class TestFrameworkRegistry:
    def setup_method(self):
        self.reg = get_framework_registry()

    def test_all_frameworks_load(self):
        assert "soc2" in self.reg.frameworks
        assert "iso27001" in self.reg.frameworks
        assert "nist_csf2" in self.reg.frameworks
        assert "nydfs" in self.reg.frameworks
        assert "sig_lite" in self.reg.frameworks
        assert "caiq" in self.reg.frameworks

    def test_soc2_lookup(self):
        systems = self.reg.lookup("soc2", "CC6.1")
        assert System.OKTA in systems
        assert System.AWS in systems

    def test_iso27001_lookup(self):
        systems = self.reg.lookup("iso27001", "8.8")
        assert System.CROWDSTRIKE in systems
        assert System.SEMGREP in systems

    def test_nydfs_sub_letter_resolution(self):
        """500.5a should resolve via 500.5 prefix."""
        systems = self.reg.lookup("nydfs", "500.5a")
        assert System.JIRA in systems

    def test_nist_subcategory_resolution(self):
        """GV.OC-1 should resolve via GV.OC prefix."""
        systems = self.reg.lookup("nist_csf2", "GV.OC-1")
        assert System.CONFLUENCE in systems

    def test_unknown_control_returns_empty(self):
        systems = self.reg.lookup("soc2", "ZZZZZ")
        assert systems == []

    def test_category_lookup(self):
        cat = self.reg.category("soc2", "CC6.1")
        assert cat == "Logical Access"

    def test_detect_soc2(self):
        assert self.reg.detect(["CC6.1", "CC7.2", "CC8.1"]) == "soc2"

    def test_detect_nydfs(self):
        assert self.reg.detect(["500.2", "500.5", "500.14"]) == "nydfs"

    def test_detect_caiq(self):
        assert self.reg.detect(["IAM-01", "LOG-02", "CCC-03"]) == "caiq"

    def test_detect_sig_lite(self):
        assert self.reg.detect(["A.1", "B.2", "C.3"]) == "sig_lite"
