
from security.rbac import has_permission


TOOL_PERMISSION_MAP = {
    "search_policy": "search_policy",
    "list_documents": "list_documents",
    "get_employee_record": "get_employee_record",
    "view_audit_logs": "view_audit_logs"
}


def authorize_tool(role, tool_name, arguments=None, user_id=None):
    """Check whether a role can execute a registered tool."""

    required_permission = TOOL_PERMISSION_MAP.get(tool_name)

    if required_permission is None:
        return {
            "allowed": False,
            "reason": "Tool is not registered for authorization."
        }

    if tool_name == "get_employee_record" and role == "employee":
        if has_permission(role, "get_employee_record_own"):
            return {
                "allowed": True,
                "reason": "Employee role may request an ownership-checked record."
            }

    if not has_permission(role, required_permission):
        return {
            "allowed": False,
            "reason": (
                f"Role '{role}' does not have permission "
                f"to execute '{tool_name}'."
            )
        }

    return {
        "allowed": True,
        "reason": "Permission granted."
    }
