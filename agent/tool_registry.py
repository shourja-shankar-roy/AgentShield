TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "search_policy",
            "description": "Search authorized policy documents using a keyword.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to search for."
                    }
                },
                "required": ["keyword"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_employee_record",
            "description": "Retrieve a mock employee record using an employee ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "employee_id": {
                        "type": "string",
                        "description": "The employee ID to look up."
                    }
                },
                "required": ["employee_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_documents",
            "description": "List available documents that the user is authorized to access.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    }
]


def get_tool_definitions():
    return TOOL_DEFINITIONS


def get_registered_tool_names():
    return [
        tool["function"]["name"]
        for tool in TOOL_DEFINITIONS
    ]


if __name__ == "__main__":
    print("Registered AgentShield Tools:\n")

    for name in get_registered_tool_names():
        print(f"- {name}")