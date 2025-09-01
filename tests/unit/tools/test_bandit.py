import pytest
from pydantic import ValidationError
from sast_model.findings.bandit import BanditFinding


class TestBanditFinding:

    finding = {
        "code": '254         logging.info("app=vAPI:uptime src_ip=%s action=success signature=\\"Uptime request\\"" % src_ip) \n255     output = os.popen(command).read() \n256     response = {\'response\':\n',
        "col_offset": 13,
        "end_col_offset": 30,
        "filename": "./vAPI.py",
        "issue_confidence": "HIGH",
        "issue_cwe": {
            "id": 78,
            "link": "https://cwe.mitre.org/data/definitions/78.html",
        },
        "issue_severity": "HIGH",
        "issue_text": "Starting a process with a shell, possible injection detected, security issue.",
        "line_number": 255,
        "line_range": [255],
        "more_info": "https://bandit.readthedocs.io/en/1.7.9/plugins/b605_start_process_with_a_shell.html",
        "test_id": "B605",
        "test_name": "start_process_with_a_shell",
    }

    def test_valid(self):
        BanditFinding(**self.finding)

    @pytest.mark.parametrize("field", ["issue_confidence", "issue_severity"])
    def test_invalid(self, field):
        finding = self.finding
        finding[field] = None
        with pytest.raises(ValidationError):
            BanditFinding(**finding)
