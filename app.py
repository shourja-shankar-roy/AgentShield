
import streamlit as st
import pandas as pd
import io
import sqlite3
from contextlib import redirect_stdout

from agent.agent_runtime import run_agent
from attacks.attack_simulator import run_initial_attacks
from database.audit_logger import (
    get_recent_logs,
    initialize_database,
    DATABASE_PATH,
)
from security.identity import IdentityContext


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="AgentShield",
    page_icon="🛡️",
    layout="wide",
)


# ==================================================
# AUDIT METRICS
# ==================================================

def get_audit_dashboard_data():
    """Retrieve aggregate metrics from the full audit database."""

    initialize_database()

    with sqlite3.connect(DATABASE_PATH) as connection:

        total = connection.execute(
            "SELECT COUNT(*) FROM audit_logs"
        ).fetchone()[0]

        allowed = connection.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE UPPER(decision) = 'ALLOWED'"
        ).fetchone()[0]

        denied = connection.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE UPPER(decision) = 'DENIED'"
        ).fetchone()[0]

        flagged_inputs = connection.execute("""
            SELECT COUNT(*) FROM audit_logs
            WHERE tool_name = 'input_inspector'
            AND UPPER(decision) = 'FLAGGED'
        """).fetchone()[0]

        blocked_inputs = connection.execute("""
            SELECT COUNT(*) FROM audit_logs
            WHERE tool_name = 'input_inspector'
            AND UPPER(decision) = 'BLOCKED'
        """).fetchone()[0]

        decision_rows = connection.execute("""
            SELECT UPPER(decision), COUNT(*)
            FROM audit_logs
            GROUP BY UPPER(decision)
            ORDER BY COUNT(*) DESC
        """).fetchall()

    decisions = {
        str(decision): count
        for decision, count in decision_rows
    }

    return {
        "total": total,
        "allowed": allowed,
        "denied": denied,
        "flagged_inputs": flagged_inputs,
        "blocked_inputs": blocked_inputs,
        "decisions": decisions,
    }


# ==================================================
# ATTACK SIMULATION METRICS
# ==================================================

def get_attack_metrics(results):
    """Calculate attack simulator statistics."""

    total = len(results)

    passed = sum(
        1 for result in results
        if result.get("passed")
    )

    blocked = sum(
        1 for result in results
        if result.get("blocked")
    )

    quarantined = sum(
        1 for result in results
        if (
            result.get("passed")
            and (
                "quarant" in str(
                    result.get("expected_protection", "")
                ).lower()
                or (
                    isinstance(result.get("protected"), dict)
                    and result["protected"].get("quarantined") is True
                )
            )
        )
    )

    sanitized = sum(
        1 for result in results
        if (
            result.get("expected_protection") == "sanitize"
            and result.get("passed")
        )
    )

    pass_rate = (
        passed / total * 100
        if total else 0
    )

    return {
        "total": total,
        "passed": passed,
        "blocked": blocked,
        "quarantined": quarantined,
        "sanitized": sanitized,
        "pass_rate": pass_rate,
    }


# ==================================================
# RESULT DISPLAY HELPER
# ==================================================

def get_result_label(result, mode):
    """Extract the actual security decision from a scenario."""

    details = result.get(mode, {})

    if not isinstance(details, dict):
        return str(details)

    # Check direct decision fields.
    for key in ("decision", "status", "result", "outcome"):
        if details.get(key) is not None:
            return str(details[key])

    # Detect direct prompt injection blocking.
    for event in details.get("tool_events", []):
        if (
            event.get("tool") == "input_inspector"
            and str(event.get("decision", "")).upper() == "BLOCKED"
        ):
            return "BLOCKED"

    # Detect document quarantine.
    if details.get("quarantined") is True:
        return "QUARANTINED"

    # Detect other blocking results.
    if details.get("blocked") is True:
        return "BLOCKED"

    # Use success status as a fallback.
    if details.get("success") is False:
        return "BLOCKED"

    return "N/A"


# ==================================================
# IDENTITY CONFIGURATION
# ==================================================

IDENTITIES = {
    "Guest": IdentityContext(
        identity_id="guest",
        role="guest",
        user_id=None,
    ),
    "Employee Alice (EMP001)": IdentityContext(
        identity_id="alice",
        role="employee",
        user_id="EMP001",
    ),
    "Security Admin Diana (EMP004)": IdentityContext(
        identity_id="diana",
        role="security_admin",
        user_id="EMP004",
    ),
}


# ==================================================
# SESSION STATE
# ==================================================

if "messages" not in st.session_state:
    st.session_state.messages = []

if "attack_results" not in st.session_state:
    st.session_state.attack_results = None

if "attack_output" not in st.session_state:
    st.session_state.attack_output = ""


# ==================================================
# SIDEBAR
# ==================================================

with st.sidebar:

    st.title("🛡️ AgentShield")

    st.caption("AI Agent Runtime Security Framework")

    st.divider()

    st.subheader("Workspace")

    selected_page = st.radio(
        "Navigation",
        [
            "Chat",
            "Security Overview",
            "Attack Simulator",
            "Audit Logs",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.subheader("Demo Identity")

    selected_identity = st.selectbox(
        "Select simulated user",
        list(IDENTITIES.keys()),
    )

    identity_context = IDENTITIES[selected_identity]

    st.caption(f"Role: {identity_context.role}")

    st.caption(
        f"User ID: {identity_context.user_id or 'None'}"
    )

    st.warning(
        "Demo identities are simulated, not production authentication."
    )

    st.divider()

    st.subheader("Local Model")

    st.caption("Qwen 3.5 4B via Ollama")

    st.caption("Protected tool execution enabled")


# ==================================================
# CHAT PAGE
# ==================================================

if selected_page == "Chat":

    st.title("AgentShield AI Agent")

    st.caption(
        "Interact with the local AI agent protected by "
        "AgentShield runtime security controls."
    )

    if st.button("New Chat"):
        st.session_state.messages = []
        st.rerun()

    st.divider()

    for message in st.session_state.messages:

        with st.chat_message(message["role"]):

            st.markdown(message["content"])

            if message.get("tool_events"):

                with st.expander("Security Tool Events"):

                    st.dataframe(
                        pd.DataFrame(message["tool_events"]),
                        use_container_width=True,
                    )

    prompt = st.chat_input("Message AgentShield...")

    if prompt:

        st.session_state.messages.append({
            "role": "user",
            "content": prompt,
        })

        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):

            with st.spinner(
                "Running AgentShield protected agent..."
            ):

                agent_result = run_agent(
                    user_message=prompt,
                    identity_context=identity_context,
                )

            answer = agent_result.get(
                "response",
                "The agent did not return a response.",
            )

            st.markdown(answer)

            tool_events = agent_result.get(
                "tool_events",
                [],
            )

            if tool_events:

                st.subheader("Security Tool Events")

                st.dataframe(
                    pd.DataFrame(tool_events),
                    use_container_width=True,
                )

            if not agent_result.get("success"):

                st.warning(
                    "The agent did not complete the request successfully."
                )

        st.session_state.messages.append({
            "role": "assistant",
            "content": answer,
            "tool_events": tool_events,
        })


# ==================================================
# SECURITY OVERVIEW
# ==================================================

elif selected_page == "Security Overview":

    st.title("Security Overview")

    st.caption(
        "Live audit metrics and implemented AgentShield "
        "runtime security controls."
    )

    st.divider()

    # --------------------------------------------------
    # AUDIT METRICS
    # --------------------------------------------------

    st.subheader("Security Metrics Dashboard")

    try:

        metrics = get_audit_dashboard_data()

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric(
            "Total Audit Events",
            metrics["total"],
        )

        col2.metric(
            "Allowed Events",
            metrics["allowed"],
        )

        col3.metric(
            "Denied Events",
            metrics["denied"],
        )

        col4.metric(
            "Flagged Inputs",
            metrics["flagged_inputs"],
        )

        col5.metric(
            "Blocked Inputs",
            metrics["blocked_inputs"],
        )

        st.caption(
            "Metrics represent all persisted events in the SQLite "
            "audit database. Input flags and blocks count only "
            "input_inspector events."
        )

        st.divider()

        st.subheader("Security Decision Distribution")

        if metrics["decisions"]:

            decision_df = pd.DataFrame(
                [
                    {
                        "Decision": decision,
                        "Events": count,
                    }
                    for decision, count in metrics["decisions"].items()
                ]
            )

            st.bar_chart(
                decision_df.set_index("Decision"),
                y="Events",
                use_container_width=True,
            )

        else:

            st.info("No audit events are available yet.")

        st.divider()

        st.subheader("Recent Security Activity")

        recent_logs = get_recent_logs(limit=10)

        if recent_logs:

            activity_df = pd.DataFrame(recent_logs)

            display_columns = [
                "id",
                "timestamp",
                "user_role",
                "tool_name",
                "decision",
                "status",
                "identity_id",
            ]

            st.dataframe(
                activity_df[display_columns],
                use_container_width=True,
                hide_index=True,
            )

        else:

            st.info("No recent security activity found.")

    except Exception as error:

        st.error(
            f"Could not load security metrics: {error}"
        )

    st.divider()

    # --------------------------------------------------
    # ATTACK SIMULATION METRICS
    # --------------------------------------------------

    st.subheader("Attack Simulation Statistics")

    results = st.session_state.attack_results

    if results is not None and len(results) > 0:

        attack_metrics = get_attack_metrics(results)

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric(
            "Total Scenarios",
            attack_metrics["total"],
        )

        col2.metric(
            "Passed Scenarios",
            attack_metrics["passed"],
        )

        col3.metric(
            "Attacks Blocked",
            attack_metrics["blocked"],
        )

        col4.metric(
            "Documents Quarantined",
            attack_metrics["quarantined"],
        )

        col5.metric(
            "Data Sanitized",
            attack_metrics["sanitized"],
        )

        st.metric(
            "Scenario Pass Rate",
            f"{attack_metrics['pass_rate']:.2f}%",
        )

        st.caption(
            "These results represent the most recent attack simulation "
            "in the current dashboard session. Scenario pass rate is "
            "not a general attack prevention guarantee."
        )

    else:

        st.info(
            "No attack simulation results are available in this "
            "session. Run the Attack Simulator to display results here."
        )

    st.divider()

    # --------------------------------------------------
    # RUNTIME SECURITY CONTROLS
    # --------------------------------------------------

    st.subheader("Runtime Security Controls")

    controls = [
        (
            "Input Inspection",
            "ACTIVE",
            "Heuristically detects suspicious instructions before "
            "the request reaches the language model. HIGH-risk "
            "requests are blocked; MEDIUM-risk requests are flagged.",
        ),
        (
            "Identity Validation",
            "ACTIVE",
            "Validates registered simulated identity contexts.",
        ),
        (
            "Role-Based Access Control",
            "ACTIVE",
            "Restricts tool access according to user roles.",
        ),
        (
            "Argument Validation",
            "ACTIVE",
            "Validates tool arguments and input formats.",
        ),
        (
            "Ownership Verification",
            "ACTIVE",
            "Prevents employees from accessing other employees' records.",
        ),
        (
            "Output Inspection",
            "ACTIVE",
            "Sanitizes sensitive fields according to user roles.",
        ),
        (
            "Audit Logging",
            "ACTIVE",
            "Records tool execution and security decisions.",
        ),
        (
            "Document Inspection",
            "ACTIVE",
            "Uses heuristic indicators to identify and quarantine suspicious documents.",
        ),
    ]

    for name, status, description in controls:

        with st.container(border=True):

            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown(f"**{name}**")
                st.caption(description)

            with col2:

                if status == "ACTIVE":
                    st.success(status)
                else:
                    st.warning(status)

    st.divider()

    # --------------------------------------------------
    # EXECUTION ARCHITECTURE
    # --------------------------------------------------

    st.subheader("Execution Architecture")

    st.code(
        """
User Request
     |
     v
AgentShield Input Inspection
     |
     +---- LOW: Allow
     |
     +---- MEDIUM: Flag and Continue
     |
     +---- HIGH: Block Request
     |
     v
LLM Agent (Qwen 3.5 4B)
     |
     v
Tool Call Request
     |
     v
AgentShield Security Engine
     |
     +---- Identity Validation
     |
     +---- Argument Validation
     |
     +---- RBAC Authorization
     |
     +---- Ownership Verification
     |
     v
Tool Execution
     |
     v
Output Inspection
     |
     v
Audit Logging
     |
     v
Agent Response
        """,
        language="text",
    )

    st.info(
        "Input inspection uses heuristic detection. Authorization "
        "and tool execution security are enforced by deterministic "
        "Python controls, not by the LLM."
    )


# ==================================================
# ATTACK SIMULATOR
# ==================================================

elif selected_page == "Attack Simulator":

    st.title("Attack Simulator")

    st.caption(
        "Compare baseline execution with AgentShield protected execution."
    )

    st.warning(
        "This simulator contains nine controlled security scenarios: "
        "seven tool-security scenarios, one direct prompt-injection "
        "scenario, and one indirect prompt-injection document scenario. "
        "The prompt-injection baselines use simulated bypasses or raw "
        "document inspection; they are not live unprotected LLM exploits."
    )

    st.divider()

    if st.button(
        "Run All Attack Scenarios",
        type="primary",
        use_container_width=True,
    ):

        output_buffer = io.StringIO()

        try:

            with st.spinner(
                "Executing all nine attack scenarios..."
            ):

                with redirect_stdout(output_buffer):

                    results = run_initial_attacks()

                st.session_state.attack_results = results

                st.session_state.attack_output = (
                    output_buffer.getvalue()
                )

        except Exception as error:

            st.error(
                f"Attack simulation failed: {error}"
            )

    results = st.session_state.attack_results

    if results is not None:

        attack_metrics = get_attack_metrics(results)

        st.subheader("Simulation Summary")

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric(
            "Total Scenarios",
            attack_metrics["total"],
        )

        col2.metric(
            "Passed",
            attack_metrics["passed"],
        )

        col3.metric(
            "Attacks Blocked",
            attack_metrics["blocked"],
        )

        col4.metric(
            "Documents Quarantined",
            attack_metrics["quarantined"],
        )

        col5.metric(
            "Data Sanitized",
            attack_metrics["sanitized"],
        )

        st.metric(
            "Overall Scenario Pass Rate",
            f"{attack_metrics['pass_rate']:.2f}%",
        )

        st.divider()

        st.subheader("Scenario Results")

        summary = []

        for result in results:

            summary.append({
                "Attack": result.get("attack_name", "Unknown"),
                "Baseline": get_result_label(result, "baseline"),
                "Protected": get_result_label(result, "protected"),
                "Expected Protection": result.get(
                    "expected_protection",
                    "N/A",
                ),
                "Passed": result.get("passed", False),
            })

        st.dataframe(
            pd.DataFrame(summary),
            use_container_width=True,
            hide_index=True,
        )

        st.divider()

        st.subheader("Detailed Results")

        for result in results:

            status = (
                "PASSED"
                if result.get("passed")
                else "FAILED"
            )

            attack_name = result.get(
                "attack_name",
                "Unknown Scenario",
            )

            with st.expander(
                f"{attack_name} — {status}"
            ):

                st.markdown("**Baseline Mode**")

                st.json(result.get("baseline", {}))

                st.markdown("**Protected Mode**")

                st.json(result.get("protected", {}))

                st.markdown(
                    f"Expected protection: "
                    f"`{result.get('expected_protection', 'N/A')}`"
                )

                if result.get("passed"):
                    st.success("Scenario passed.")
                else:
                    st.error("Scenario failed.")

        with st.expander("Full Simulation Console Output"):

            st.code(
                st.session_state.attack_output,
                language="text",
            )

        st.caption(
            "A passing scenario means the implemented control met "
            "that scenario's expected result. It does not establish "
            "protection against every possible attack."
        )

    else:

        st.info(
            "Click 'Run All Attack Scenarios' to begin testing."
        )


# ==================================================
# AUDIT LOGS
# ==================================================

elif selected_page == "Audit Logs":

    st.title("Audit Logs")

    st.caption(
        "Security and tool execution event records."
    )

    if identity_context.role != "security_admin":

        st.error(
            "Access denied. Only Security Admin can view audit logs."
        )

    else:

        col1, col2 = st.columns([2, 1])

        with col1:

            log_limit = st.selectbox(
                "Number of recent events",
                [10, 20, 50, 100],
                index=2,
            )

        with col2:

            st.write("")
            st.write("")

            st.button(
                "Refresh Logs",
                use_container_width=True,
            )

        try:

            logs = get_recent_logs(limit=log_limit)

            if logs:

                st.metric(
                    "Events Retrieved",
                    len(logs),
                )

                st.dataframe(
                    pd.DataFrame(logs),
                    use_container_width=True,
                    hide_index=True,
                )

            else:

                st.info("No audit events found.")

        except Exception as error:

            st.error(
                f"Could not retrieve audit logs: {error}"
            )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.caption(
    "AgentShield | AI Agent Runtime Security Framework"
)
