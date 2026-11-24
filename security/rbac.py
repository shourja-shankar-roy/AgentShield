
# AgentShield Role-Based Access Control (RBAC)

# Permissions assigned to each simulated user role.
ROLE_PERMISSIONS = {
    "guest": {
        "search_policy",
        "list_documents"
    },

    "employee": {
        "search_policy",
        "list_documents",
        "get_employee_record_own"
    },

    "security_admin": {
        "search_policy",
        "list_documents",
        "get_employee_record",
        "view_audit_logs"
    }
}


def get_role_permissions(role):
    """Return the permissions assigned to a role."""

    if not isinstance(role, str):
        return set()

    return ROLE_PERMISSIONS.get(role.strip().lower(), set()).copy()


def has_permission(role, permission):
    """Check whether a role has a specific permission."""

    if not isinstance(permission, str):
        return False

    permissions = get_role_permissions(role)

    return permission in permissions


def get_available_roles():
    """Return all configured roles."""

    return list(ROLE_PERMISSIONS.keys())


if __name__ == "__main__":

    print("\nAgentShield RBAC Test")
    print("=" * 40)

    for role in get_available_roles():

        print(f"\nRole: {role}")
        print("-" * 30)

        for permission in sorted(get_role_permissions(role)):
            print(f"[ALLOWED] {permission}")

    print("\nPermission checks:")
    print("-" * 30)

    tests = [
        ("guest", "get_employee_record"),
        ("guest", "search_policy"),
        ("employee", "get_employee_record_own"),
        ("employee", "view_audit_logs"),
        ("security_admin", "get_employee_record"),
        ("security_admin", "view_audit_logs"),
        ("unknown_role", "search_policy")
    ]

    for role, permission in tests:

        result = has_permission(role, permission)

        print(
            f"{role} -> {permission}: "
            f"{'ALLOWED' if result else 'DENIED'}"
        )
