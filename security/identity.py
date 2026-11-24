
from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityContext:
    """
    Immutable identity context for AgentShield demo sessions.

    This represents a selected demo identity, not a
    production-authenticated user.
    """
    identity_id: str
    role: str
    user_id: str | None


_DEMO_IDENTITIES = {
    "Guest": {
        "identity_id": "guest",
        "role": "guest",
        "user_id": None,
    },
    "Employee — Alice (EMP001)": {
        "identity_id": "alice",
        "role": "employee",
        "user_id": "EMP001",
    },
    "Security Admin — Diana (EMP004)": {
        "identity_id": "diana",
        "role": "security_admin",
        "user_id": "EMP004",
    },
}


def resolve_demo_identity(identity_name):
    """
    Resolve a selected demo identity into a validated context.
    """
    if not isinstance(identity_name, str):
        raise ValueError("Invalid demo identity.")

    identity = _DEMO_IDENTITIES.get(identity_name)

    if identity is None:
        raise ValueError("Unknown demo identity.")

    return IdentityContext(
        identity_id=identity["identity_id"],
        role=identity["role"],
        user_id=identity["user_id"],
    )


def validate_identity_context(context):
    """
    Verify that an identity context matches a registered
    demo identity exactly.
    """
    if not isinstance(context, IdentityContext):
        return False

    for identity in _DEMO_IDENTITIES.values():
        if (
            context.identity_id == identity["identity_id"]
            and context.role == identity["role"]
            and context.user_id == identity["user_id"]
        ):
            return True

    return False
