
from security.tool_authorization import authorize_tool
from security.argument_validator import validate_arguments
from security.output_inspector import inspect_output
from security.identity import validate_identity_context

from tools.tool_executor import execute_tool
from database.audit_logger import log_event


# ==================================================
# AUDIT LOGGING
# ==================================================

def _record_event(role, tool_name, decision, status, details):
    """Record an event without storing sensitive tool arguments."""

    try:
        log_event(
            user_role=role,
            tool_name=tool_name,
            decision=decision,
            status=status,
            details=details
        )
    except Exception as error:
        raise RuntimeError(
            "Security audit logging failed. Tool execution cannot continue."
        ) from error


# ==================================================
# EMPLOYEE OWNERSHIP VALIDATION
# ==================================================

def _check_employee_ownership(user_id, employee_id):
    """Verify that an employee requests their own record."""

    if not isinstance(user_id, str) or not user_id.strip():
        return False

    if not isinstance(employee_id, str):
        return False

    return user_id.strip().upper() == employee_id.strip().upper()


# ==================================================
# SECURE TOOL EXECUTION
# ==================================================

def execute_secure_tool(
    tool_name,
    arguments,
    identity_context=None,
    role=None,
    user_id=None,
    enforcement_enabled=True
):
    """
    Execute a tool through the AgentShield security engine.

    PROTECTED MODE:
        Validates identity, arguments, permissions, ownership
        and tool output.

    BASELINE MODE:
        Simulates a vulnerable configuration by bypassing
        AgentShield identity, argument, authorization,
        ownership and output controls.

        The underlying tool registry and basic executor
        type checks remain active in both configurations.
    """

    # --------------------------------------------------
    # NORMALIZE TOOL NAME
    # --------------------------------------------------

    normalized_tool = (
        tool_name.strip()
        if isinstance(tool_name, str)
        else "invalid_tool"
    )

    # --------------------------------------------------
    # IDENTITY VALIDATION
    # --------------------------------------------------

    if enforcement_enabled:

        if not validate_identity_context(identity_context):

            _record_event(
                "unknown",
                normalized_tool,
                "DENIED",
                "INVALID_IDENTITY",
                "Missing, forged or unrecognized identity context."
            )

            return {
                "success": False,
                "decision": "DENIED",
                "error": "Access denied: invalid identity context."
            }

        normalized_role = identity_context.role
        normalized_user_id = identity_context.user_id

    else:

        normalized_role = (
            role.strip().lower()
            if isinstance(role, str)
            else "unknown"
        )

        normalized_user_id = user_id

    # --------------------------------------------------
    # ARGUMENT VALIDATION
    # --------------------------------------------------

    if enforcement_enabled:

        validation = validate_arguments(
            normalized_tool,
            arguments
        )

        if not validation["valid"]:

            _record_event(
                normalized_role,
                normalized_tool,
                "DENIED",
                "INVALID_ARGUMENTS",
                validation["reason"]
            )

            return {
                "success": False,
                "decision": "DENIED",
                "error": validation["reason"]
            }

    # --------------------------------------------------
    # AUTHORIZATION
    # --------------------------------------------------

    if enforcement_enabled:

        authorization = authorize_tool(
            normalized_role,
            normalized_tool,
            arguments,
            normalized_user_id
        )

        if not authorization["allowed"]:

            _record_event(
                normalized_role,
                normalized_tool,
                "DENIED",
                "BLOCKED",
                authorization["reason"]
            )

            return {
                "success": False,
                "decision": "DENIED",
                "error": authorization["reason"]
            }

        # --------------------------------------------------
        # EMPLOYEE OWNERSHIP CHECK
        # --------------------------------------------------

        if (
            normalized_tool == "get_employee_record"
            and normalized_role == "employee"
        ):

            requested_id = arguments["employee_id"]

            if not _check_employee_ownership(
                normalized_user_id,
                requested_id
            ):

                reason = (
                    "Employee access denied: "
                    "you can only retrieve your own record."
                )

                _record_event(
                    normalized_role,
                    normalized_tool,
                    "DENIED",
                    "OWNERSHIP_VIOLATION",
                    reason
                )

                return {
                    "success": False,
                    "decision": "DENIED",
                    "error": reason
                }

    # --------------------------------------------------
    # TOOL EXECUTION
    # --------------------------------------------------

    try:

        result = execute_tool(
            normalized_tool,
            arguments
        )

    except Exception as error:

        _record_event(
            normalized_role,
            normalized_tool,
            "ALLOWED" if enforcement_enabled else "BYPASSED",
            "EXECUTION_ERROR",
            str(error)
        )

        return {
            "success": False,
            "decision": "ERROR",
            "error": str(error)
        }

    # --------------------------------------------------
    # OUTPUT INSPECTION
    # --------------------------------------------------

    if enforcement_enabled:

        inspection = inspect_output(
            result,
            role=normalized_role
        )

        result = inspection["output"]

    # --------------------------------------------------
    # AUDIT RESULT
    # --------------------------------------------------

    decision = "ALLOWED" if enforcement_enabled else "BYPASSED"

    status = (
        "SUCCESS"
        if enforcement_enabled
        else "BASELINE_SUCCESS"
    )

    _record_event(
        normalized_role,
        normalized_tool,
        decision,
        status,
        "Tool execution completed."
    )

    return {
        "success": True,
        "decision": decision,
        "result": result
    }
