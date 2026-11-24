
import re


# Fields that should not be disclosed to ordinary users.
SENSITIVE_FIELDS = {
    "salary",
    "password",
    "password_hash",
    "secret",
    "api_key",
    "access_token",
    "private_key"
}


def inspect_output(output, role="guest"):
    """
    Inspect tool output for sensitive information.

    Security Admin can receive authorized employee records.
    Other roles have sensitive fields removed.

    This is a basic output filter, not a complete
    data-loss prevention system.
    """

    if not isinstance(role, str):
        role = "guest"

    role = role.strip().lower()

    findings = []
    sanitized_output = output

    def sanitize(value, path=""):
        nonlocal findings

        if isinstance(value, dict):

            cleaned = {}

            for key, item in value.items():

                key_name = str(key).lower()

                if key_name in SENSITIVE_FIELDS and role != "security_admin":
                    findings.append(
                        f"Sensitive field blocked: {path}{key}"
                    )
                    continue

                cleaned[key] = sanitize(
                    item,
                    f"{path}{key}."
                )

            return cleaned

        if isinstance(value, list):
            return [
                sanitize(item, path)
                for item in value
            ]

        return value

    if isinstance(output, (dict, list)):
        sanitized_output = sanitize(output)

    elif isinstance(output, str):

        if role != "security_admin":
            for field in SENSITIVE_FIELDS:

                pattern = (
                    rf"(?i)(['\"]?{re.escape(field)}['\"]?\s*[:=]\s*)"
                    rf"(['\"]?)[^,;\n}}]+"
                )

                if re.search(pattern, sanitized_output):
                    findings.append(
                        f"Potential sensitive field detected: {field}"
                    )

                    sanitized_output = re.sub(
                        pattern,
                        r"\1[REDACTED]",
                        sanitized_output
                    )

    return {
        "safe": len(findings) == 0,
        "findings": findings,
        "output": sanitized_output
    }


if __name__ == "__main__":

    import json

    print("\nAgentShield Output Inspector Test")
    print("=" * 45)

    sample_record = {
        "employee_id": "EMP001",
        "name": "Alice Johnson",
        "department": "Human Resources",
        "email": "alice.johnson@example.com",
        "salary": 65000,
        "status": "active"
    }

    print("\n1. Guest output inspection:")

    result = inspect_output(
        sample_record,
        role="guest"
    )

    print(json.dumps(result, indent=4))

    print("\n2. Employee output inspection:")

    result = inspect_output(
        sample_record,
        role="employee"
    )

    print(json.dumps(result, indent=4))

    print("\n3. Security Admin output inspection:")

    result = inspect_output(
        sample_record,
        role="security_admin"
    )

    print(json.dumps(result, indent=4))
