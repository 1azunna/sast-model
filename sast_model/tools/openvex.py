OPENVEX_TOOL = {
    "name": "openvex_analysis",
    "description": """
    Analyzes the findings presented from a SAST tool to determine if the findings are valid or not.
    justification and impact_statements should only be provided when a finding has a status of not_affected.
    action_statement should only be provided when a finding has a status of affected.
    """,
    "input_schema": {
        "type": "object",
        "properties": {
            "vulnerability": {
                "type": "object",
                "description": "The vulnerability details",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": """
                        The vulnerability name should be a single logical word descibing the issue.
                        It should only include numbers, alphabets and an uderscore. An example is `hardcoded_sql_expressions`
                        """,
                    },
                    "description": {
                        "type": "string",
                        "description": "A freeform text describing why the vulnerabilityis valid",
                    },
                },
                "required": ["name", "description"],
            },
            "justification": {
                "type": "string",
                "enum": [
                    "component_not_present",
                    "vulnerable_code_not_present",
                    "vulnerable_code_not_in_execute_path",
                    "vulnerable_code_cannot_be_controlled_by_adversary",
                    "inline_mitigations_already_exist",
                ],
                "description": "Why the application is not affected by the vulnerability, as described by the openVEX justifications spec.",
            },
            "impact_statement": {
                "type": "string",
                "description": "A free form text containing a description of why the vulnerability cannot be exploited.",
            },
            "action_statement": {
                "type": "string",
                "description": """
                A short description of the actions required to remediate or mitigate the vulnerability. 
                Reference any functions or lines to be changed and provied a sample fix if possible.""",
            },
            "status": {
                "type": "string",
                "enum": ["not_affected", "affected"],
                "description": "The status of the finding after determining if it is valid or not.",
            },
        },
        "required": ["vulnerability", "status"],
    },
}
