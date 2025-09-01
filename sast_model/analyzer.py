import os
import json
import anthropic
import logging
from pydantic import (
    BaseModel,
    field_validator,
    DirectoryPath,
    ValidationInfo,
    ValidationError,
)
from typing import List, Optional

from .tools.openvex import OPENVEX_TOOL
from .findings.bandit import BanditFinding
from anthropic.types import ToolParam, MessageParam

LOGGER_NAME = "sast_analyzer"
logging.basicConfig(format="%(levelname)s - %(message)s")
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.DEBUG)
logger.propagate = True


class Prompt(BaseModel):
    role: str = "user"
    content: str

    @field_validator("role")
    def validate_confidence(cls, value, info: ValidationInfo):
        allowed_values = {"user", "assistant"}
        if value not in allowed_values:
            raise ValueError(f"role must be one of {allowed_values}")
        return value


class SASTReport(BaseModel):
    findings: List[BanditFinding]


class SASTAnalyzer:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def _call_claude(self, messages: List[MessageParam], tools: List[ToolParam]) -> str:

        client = anthropic.Anthropic(api_key=self.api_key)
        data = {
            "max_tokens": 1024,
            "model": "claude-3-5-sonnet-20240620",
            "system": """
            You're a software security expert who analyzes SAST report findings and source code to determine 
            if they are false positves and provides an openvex statement for your analysis.""",
            "messages": messages,
        }
        if tools:
            data["tools"] = tools

        return client.messages.create(**data)

    def analyze_bandit_finding(self, finding: BanditFinding, source_code: str) -> str:
        """
        Analyze a single SAST finding using Claude AI.
        :param finding: A SASTFinding object containing SAST finding details.
        :param source_code: The source code associated with the finding.
        :return: Analysis result as a string.
        """
        content = f"""
        A SAST tool found the following issue in a codebase:

        Finding:
        - File: {finding.filename}
        - Line: {finding.line_number}
        - Vulnerability: {finding.issue_text}
        - CWE: {finding.issue_cwe.id} ({finding.issue_cwe.link})
        - Confidence: {finding.issue_confidence}
        - Severity: {finding.issue_severity}
        - More info: {finding.more_info or 'N/A'}

        Here is the relevant code:
        {source_code}

        Based on the code and the information, is this finding valid? Take into consideration the following when answering:
        - Is the vulnerability present in the source code?
        - Are the any existing mitigations in the source code?
        - Is the vulnerability exploitable in the given source code?
        - Is input directly passed to any vulnerable classes or methods?
        - Can this vulnerability lead to other vulnerabilities?
        Use these considerations to determine a not_affected or affected status. If there are mitgations present, the status 
        should be not_affected unless the mitigations are unsatisfactory.
        I want an openvex statement from your analysis.
        """

        claude_input = [
            Prompt(content="Hi Claude"),
            Prompt(role="assistant", content="Hello there!"),
            Prompt(content=content),
        ]

        # Convert the list of Prompts to JSON
        claude_input_json: List[MessageParam] = [
            prompt.model_dump() for prompt in claude_input
        ]

        tools = [OPENVEX_TOOL]

        return self._call_claude(messages=claude_input_json, tools=tools)

    def analyze_report(
        self, sast_report: SASTReport, source_code_dir: DirectoryPath
    ) -> dict:
        """
        Analyze an entire SAST report.
        :param sast_report: A validated SASTReport object.
        :param source_code_dir: Directory path where source code files are located.
        :return: A dictionary containing the results of the analysis.
        """
        results = {}

        for finding in sast_report.findings:
            # Load the source code related to the finding
            file_path = os.path.join(source_code_dir, finding.filename)
            if not os.path.exists(file_path):
                results[finding.test_id] = "Source code not found"
                continue

            with open(file_path, "r") as f:
                source_code = f.read()

            # Get Claude's analysis
            analysis = self.analyze_bandit_finding(finding, source_code)
            analysis_json = analysis.model_dump_json()
            print(analysis_json)
            try:
                results[finding.test_id] = json.loads(analysis_json)["content"][1][
                    "input"
                ]
                return results
            except KeyError:
                logger.error("Response incomplete")

        return None


# Example usage
if __name__ == "__main__":
    try:
        # Load the SAST report (example JSON format)
        # sast_report_path = (
        #     "/Users/azunna/Documents/MyProjects/vulnerable-api/bandit-report.json"
        # )
        # with open(sast_report_path, "r") as f:
        #     sast_report_data = json.load(f)["results"]

        # high_severity = [
        #     finding
        #     for finding in sast_report_data
        #     if finding["issue_severity"] == "HIGH"
        # ]
        # # Validate SAST report using Pydantic
        # sast_report = SASTReport(findings=high_severity)

        findings = [
            {
                "code": "22 import re\n23 import xml.etree.ElementTree as ET\n24 import logging\n",
                "col_offset": 0,
                "end_col_offset": 34,
                "filename": "./vAPI-fixed.py",
                "issue_confidence": "HIGH",
                "issue_cwe": {
                    "id": 20,
                    "link": "https://cwe.mitre.org/data/definitions/20.html",
                },
                "issue_severity": "LOW",
                "issue_text": "Using xml.etree.ElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
                "line_number": 23,
                "line_range": [23],
                "more_info": "https://bandit.readthedocs.io/en/1.7.9/blacklists/blacklist_imports.html#b405-import-xml-etree",
                "test_id": "B405",
                "test_name": "blacklist",
            },
        ]
        sast_report = SASTReport(findings=findings)

        # Directory containing the source code files
        source_code_dir = "/Users/azunna/Documents/MyProjects/vulnerable-api"

        # Initialize ClaudeSASTAnalyzer with your API key
        analyzer = SASTAnalyzer(api_key=os.environ.get("ANTHROPIC_API_KEY"))

        # Analyze the SAST report
        analysis_results = analyzer.analyze_report(sast_report, source_code_dir)

        # Output the results
        output_path = "analysis_results.json"
        with open(output_path, "w") as f:
            json.dump(analysis_results, f, indent=4)

        print(f"Analysis results saved to {output_path}")

    except ValidationError as e:
        print(f"Validation error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
