
import re


TOOL_ARGUMENT_SCHEMAS = {
    "search_policy": {
        "required": {"keyword"},
        "allowed": {"keyword"}
    },

    "list_documents": {
        "required": set(),
        "allowed": set()
    },

    "get_employee_record": {
        "required": {"employee_id"},
        "allowed": {"employee_id"}
    },

    "view_audit_logs": {
        "required": set(),
        "allowed": {"limit"}
    }
}


def validate_arguments(tool_name, arguments):
    """Validate tool names, argument keys, types and values."""

    if not isinstance(tool_name, str):
        return {
            "valid": False,
            "reason": "Tool name must be a string."
        }

    if not isinstance(arguments, dict):
        return {
            "valid": False,
            "reason": "Tool arguments must be a dictionary."
        }

    schema = TOOL_ARGUMENT_SCHEMAS.get(tool_name)

    if schema is None:
        return {
            "valid": False,
            "reason": "Unknown tool."
        }

    required = schema["required"]
    allowed = schema["allowed"]

    supplied = set(arguments.keys())

    missing = required - supplied
    unexpected = supplied - allowed

    if missing:
        return {
            "valid": False,
            "reason": f"Missing required arguments: {sorted(missing)}"
        }

    if unexpected:
        return {
            "valid": False,
            "reason": f"Unexpected arguments: {sorted(unexpected)}"
        }

    if tool_name == "search_policy":

        keyword = arguments["keyword"]

        if not isinstance(keyword, str):
            return {
                "valid": False,
                "reason": "Keyword must be a string."
            }

        if not keyword.strip():
            return {
                "valid": False,
                "reason": "Keyword cannot be empty."
            }

        if len(keyword) > 100:
            return {
                "valid": False,
                "reason": "Keyword exceeds the 100-character limit."
            }

    elif tool_name == "get_employee_record":

        employee_id = arguments["employee_id"]

        if not isinstance(employee_id, str):
            return {
                "valid": False,
                "reason": "Employee ID must be a string."
            }

        if not re.fullmatch(r"EMP\d{3}", employee_id.strip().upper()):
            return {
                "valid": False,
                "reason": (
                    "Invalid employee ID format. "
                    "Expected EMP followed by 3 digits."
                )
            }

    elif tool_name == "view_audit_logs":

        limit = arguments.get("limit", 20)

        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > 100
        ):
            return {
                "valid": False,
                "reason": "Audit log limit must be an integer between 1 and 100."
            }

    return {
        "valid": True,
        "reason": "Arguments passed validation."
    }


if __name__ == "__main__":

    print("\nAgentShield Argument Validator Test")
    print("=" * 50)

    tests = [
        ("view_audit_logs", {}),
        ("view_audit_logs", {"limit": 5}),
        ("view_audit_logs", {"limit": 0}),
        ("view_audit_logs", {"limit": True}),
        ("list_documents", {}),
        ("get_employee_record", {"employee_id": "EMP001"}),
        ("unknown_tool", {})
    ]

    for tool_name, arguments in tests:

        result = validate_arguments(tool_name, arguments)

        status = "VALID" if result["valid"] else "REJECTED"

        print(f"\nTool: {tool_name}")
        print(f"Arguments: {arguments}")
        print(f"Result: {status}")
        print(f"Reason: {result['reason']}")
