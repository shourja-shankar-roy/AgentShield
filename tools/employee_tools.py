
import json
import re
from pathlib import Path

from database.audit_logger import get_recent_logs


# ==================================================
# PROJECT PATHS
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_ROOT / "data"
DOCUMENT_DIRECTORY = DATA_DIRECTORY / "documents"
EMPLOYEE_DATABASE = DATA_DIRECTORY / "mock_records.json"


# ==================================================
# DOCUMENT SECURITY INSPECTION
# ==================================================

SUSPICIOUS_INSTRUCTION_PATTERNS = {
    "role_manipulation": re.compile(
        r"\byou are now (?:operating|acting|functioning) as\b",
        re.IGNORECASE
    ),

    "security_override": re.compile(
        r"\b(?:disregard|override|bypass)\b"
        r".{0,100}\b(?:security|access|restrictions|permissions|instructions)\b",
        re.IGNORECASE
    ),

    "system_prompt_extraction": re.compile(
        r"\b(?:reveal|disclose|print|show|expose)\b"
        r".{0,100}\b(?:system prompt|hidden prompt|system instructions)\b",
        re.IGNORECASE
    ),

    "unauthorized_data_access": re.compile(
        r"\b(?:retrieve|access|dump|extract|exfiltrate)\b"
        r".{0,100}\b(?:employee record|employee records|salary|personal information)\b",
        re.IGNORECASE
    ),

    "instruction_concealment": re.compile(
        r"\b(?:do not tell|don't tell|hide this|conceal this)\b",
        re.IGNORECASE
    ),
}


QUARANTINE_THRESHOLD = 3
MAX_DOCUMENT_CHARACTERS = 12000


def inspect_document_content(content):
    """
    Inspect document content for suspicious instruction patterns.

    This is a heuristic detector, not a complete prompt-injection
    defense. A document is quarantined when multiple indicators
    are detected.
    """

    if not isinstance(content, str):
        raise TypeError("Document content must be a string.")

    findings = []

    for category, pattern in SUSPICIOUS_INSTRUCTION_PATTERNS.items():
        if pattern.search(content):
            findings.append(category)

    quarantined = len(findings) >= QUARANTINE_THRESHOLD

    return {
        "quarantined": quarantined,
        "findings": findings,
        "risk_indicator_count": len(findings),
    }


# ==================================================
# EMPLOYEE DATABASE
# ==================================================

def load_employee_records():
    """Load fictional employee records from the JSON database."""

    if not EMPLOYEE_DATABASE.exists():
        raise FileNotFoundError(
            f"Employee database not found: {EMPLOYEE_DATABASE}"
        )

    with EMPLOYEE_DATABASE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    employees = data.get("employees", [])

    if not isinstance(employees, list):
        raise ValueError("Invalid employee database structure.")

    return employees


def get_employee_record(employee_id):
    """Retrieve a fictional employee record."""

    if not isinstance(employee_id, str):
        raise TypeError("Employee ID must be a string.")

    employee_id = employee_id.strip().upper()

    if not employee_id:
        raise ValueError("Employee ID cannot be empty.")

    employees = load_employee_records()

    for employee in employees:
        if employee.get("employee_id", "").upper() == employee_id:
            return employee

    return {"error": "Employee record not found."}


# ==================================================
# SECURE POLICY SEARCH
# ==================================================

def search_policy(keyword):
    """
    Search policy documents after security inspection.

    Complete document content is returned only when:
    1. The document contains the requested keyword.
    2. The document passes the security inspection.
    3. The document is within the configured size limit.

    Quarantined document contents are never returned.
    """

    if not isinstance(keyword, str):
        raise TypeError("Search keyword must be a string.")

    keyword = keyword.strip()

    if not keyword:
        raise ValueError("Search keyword cannot be empty.")

    if not DOCUMENT_DIRECTORY.exists():
        raise FileNotFoundError(
            "Policy documents directory does not exist."
        )

    results = []

    for document in sorted(DOCUMENT_DIRECTORY.glob("*.txt")):

        if not document.is_file():
            continue

        content = document.read_text(encoding="utf-8")

        # Inspect the complete document before returning any content.
        inspection = inspect_document_content(content)

        if keyword.casefold() not in content.casefold():
            continue

        # Quarantined documents must never expose their contents.
        if inspection["quarantined"]:
            results.append({
                "document": document.name,
                "status": "QUARANTINED",
                "content": "",
                "matches": [],
                "security_warning": (
                    "Document quarantined because multiple "
                    "suspicious instruction indicators were detected."
                ),
                "findings": inspection["findings"],
            })

            continue

        # Enforce a document-size limit.
        if len(content) > MAX_DOCUMENT_CHARACTERS:
            results.append({
                "document": document.name,
                "status": "AVAILABLE",
                "content": "",
                "matches": [],
                "security_warning": (
                    "Document exceeds the maximum retrieval size. "
                    "Full content was not returned."
                ),
            })

            continue

        # Return the complete inspected document so the LLM
        # can understand all relevant policy sections.
        matching_lines = [
            line.strip()
            for line in content.splitlines()
            if keyword.casefold() in line.casefold()
        ]

        results.append({
            "document": document.name,
            "status": "AVAILABLE",
            "content": content,
            "matches": matching_lines,
        })

    return {
        "keyword": keyword,
        "results": results,
        "total_documents": len(results),
        "quarantined_documents": sum(
            1 for result in results
            if result["status"] == "QUARANTINED"
        ),
    }


# ==================================================
# DOCUMENT LISTING
# ==================================================

def list_documents():
    """List available text documents."""

    if not DOCUMENT_DIRECTORY.exists():
        raise FileNotFoundError(
            "Policy documents directory does not exist."
        )

    documents = sorted(
        document.name
        for document in DOCUMENT_DIRECTORY.glob("*.txt")
        if document.is_file()
    )

    return {
        "documents": documents,
        "total_documents": len(documents)
    }


# ==================================================
# AUDIT LOG ACCESS
# ==================================================

def view_audit_logs(limit=20):
    """Retrieve recent security audit logs."""

    return get_recent_logs(limit=limit)


# ==================================================
# LOCAL TESTING
# ==================================================

if __name__ == "__main__":

    print("\nAgentShield Employee Tools Test")
    print("=" * 40)

    print("\n1. Employee record test:")
    print(json.dumps(get_employee_record("EMP001"), indent=4))

    print("\n2. Policy search test:")
    print(json.dumps(search_policy("employee"), indent=4))

    print("\n3. Document listing test:")
    print(json.dumps(list_documents(), indent=4))

    print("\n4. Audit log retrieval test:")
    print(json.dumps(view_audit_logs(5), indent=4))

    print("\n5. Malicious document inspection:")
    print(json.dumps(
        inspect_document_content(
            (DOCUMENT_DIRECTORY / "malicious_policy.txt").read_text(
                encoding="utf-8"
            )
        ),
        indent=4
    ))
