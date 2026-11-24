
from tools.employee_tools import (
    get_employee_record,
    search_policy,
    list_documents,
    view_audit_logs
)


TOOL_FUNCTIONS = {
    "get_employee_record": get_employee_record,
    "search_policy": search_policy,
    "list_documents": list_documents,
    "view_audit_logs": view_audit_logs
}


def execute_tool(tool_name, arguments):
    if not isinstance(tool_name, str):
        raise TypeError("Tool name must be a string.")

    if not isinstance(arguments, dict):
        raise TypeError("Tool arguments must be a dictionary.")

    tool_function = TOOL_FUNCTIONS.get(tool_name)

    if tool_function is None:
        raise ValueError(f"Unknown tool: {tool_name}")

    return tool_function(**arguments)


def get_available_tool_names():
    return list(TOOL_FUNCTIONS.keys())
