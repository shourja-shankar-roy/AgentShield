
import json
from datetime import datetime
from pathlib import Path

from evaluation.benign_input_evaluation import run_benign_evaluation
from evaluation.contextual_bypass_evaluation import (
    run_contextual_bypass_evaluation
)
from evaluation.holdout_input_evaluation import run_holdout_evaluation
from evaluation.input_inspector_benchmark import run_benchmark
from attacks.attack_simulator import run_initial_attacks


# ============================================================
# CONFIGURATION
# ============================================================

REPORT_DIR = Path("reports")

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# HELPERS
# ============================================================

def make_json_safe(value):
    """Convert evaluation results into JSON-compatible values."""

    if isinstance(value, dict):
        return {
            str(key): make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [make_json_safe(item) for item in value]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def run_section(name, function):
    """Run one evaluation and capture its result."""

    print("\n" + "=" * 70)
    print("RUNNING:", name)
    print("=" * 70)

    try:
        result = function()

        print("\nCompleted:", name)

        return {
            "status": "COMPLETED",
            "results": make_json_safe(result)
        }

    except Exception as error:
        print("\nERROR:", name)
        print(str(error))

        return {
            "status": "FAILED",
            "error": str(error)
        }


def format_results(value, indent=0):
    """Convert nested results into readable report text."""

    spacing = " " * indent
    lines = []

    if isinstance(value, dict):

        for key, item in value.items():

            if isinstance(item, (dict, list)):
                lines.append(f"{spacing}{key}:")
                lines.append(format_results(item, indent + 4))
            else:
                lines.append(f"{spacing}{key}: {item}")

    elif isinstance(value, list):

        for index, item in enumerate(value, start=1):
            lines.append(f"{spacing}Item {index}:")
            lines.append(format_results(item, indent + 4))

    else:
        lines.append(f"{spacing}{value}")

    return "\n".join(lines)


# ============================================================
# MAIN EVALUATION INTEGRATION
# ============================================================

def run_full_evaluation():

    print("\n")
    print("=" * 70)
    print("AGENTSHIELD - FULL EVALUATION")
    print("=" * 70)

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    results = {
        "project": "AgentShield",
        "evaluation_timestamp": timestamp,
        "evaluation_note": (
            "The 40-prompt diagnostic dataset was used during "
            "detector refinement. Its results must not be described "
            "as an untouched independent holdout evaluation."
        ),
        "evaluations": {}
    }

    # --------------------------------------------------------
    # 1. BENIGN INPUT EVALUATION
    # --------------------------------------------------------

    results["evaluations"]["benign_input_evaluation"] = (
        run_section(
            "Benign Input Evaluation",
            run_benign_evaluation
        )
    )

    # --------------------------------------------------------
    # 2. CONTEXTUAL BYPASS EVALUATION
    # --------------------------------------------------------

    results["evaluations"]["contextual_bypass_evaluation"] = (
        run_section(
            "Contextual Bypass Evaluation",
            run_contextual_bypass_evaluation
        )
    )

    # --------------------------------------------------------
    # 3. DIAGNOSTIC INPUT EVALUATION
    # --------------------------------------------------------

    results["evaluations"]["diagnostic_input_evaluation"] = (
        run_section(
            "Diagnostic Input Evaluation",
            run_holdout_evaluation
        )
    )

    # --------------------------------------------------------
    # 4. INPUT INSPECTOR BENCHMARK
    # --------------------------------------------------------

    results["evaluations"]["input_inspector_benchmark"] = (
        run_section(
            "Input Inspector Benchmark",
            run_benchmark
        )
    )

    # --------------------------------------------------------
    # 5. ATTACK SIMULATOR
    # --------------------------------------------------------

    attack_section = run_section(
        "Nine-Scenario Attack Simulation",
        run_initial_attacks
    )

    results["evaluations"]["attack_simulator"] = attack_section

    # --------------------------------------------------------
    # ATTACK SUMMARY
    # --------------------------------------------------------

    attack_summary = {
        "total_scenarios": 0,
        "passed_scenarios": 0,
        "failed_scenarios": 0,
        "pass_rate": 0.0
    }

    if attack_section["status"] == "COMPLETED":

        attack_results = attack_section["results"]

        if isinstance(attack_results, list):

            total = len(attack_results)

            passed = sum(
                1
                for attack in attack_results
                if isinstance(attack, dict)
                and attack.get("passed") is True
            )

            failed = total - passed

            attack_summary = {
                "total_scenarios": total,
                "passed_scenarios": passed,
                "failed_scenarios": failed,
                "pass_rate": round(
                    (passed / total) * 100,
                    2
                ) if total else 0.0
            }

    results["attack_summary"] = attack_summary

    # --------------------------------------------------------
    # OVERALL STATUS
    # --------------------------------------------------------

    section_statuses = [
        section["status"]
        for section in results["evaluations"].values()
    ]

    results["overall_status"] = (
        "COMPLETED"
        if all(status == "COMPLETED" for status in section_statuses)
        else "COMPLETED_WITH_ERRORS"
    )

    # --------------------------------------------------------
    # SAVE JSON RESULTS
    # --------------------------------------------------------

    json_path = REPORT_DIR / "evaluation_results.json"

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False
        )

    # --------------------------------------------------------
    # GENERATE READABLE TEXT REPORT
    # --------------------------------------------------------

    report_lines = [
        "AGENTSHIELD - EVALUATION REPORT",
        "=" * 70,
        f"Evaluation timestamp: {timestamp}",
        f"Overall status: {results['overall_status']}",
        "",
        "IMPORTANT EVALUATION LIMITATION",
        "-" * 70,
        results["evaluation_note"],
        "",
        "ATTACK SIMULATOR SUMMARY",
        "-" * 70,
        f"Total scenarios: {attack_summary['total_scenarios']}",
        f"Passed scenarios: {attack_summary['passed_scenarios']}",
        f"Failed scenarios: {attack_summary['failed_scenarios']}",
        f"Pass rate: {attack_summary['pass_rate']:.2f}%",
        "",
        "DETAILED EVALUATION RESULTS",
        "=" * 70
    ]

    for name, section in results["evaluations"].items():

        report_lines.append("")
        report_lines.append(name.upper().replace("_", " "))
        report_lines.append("-" * 70)
        report_lines.append(f"Status: {section['status']}")

        if section["status"] == "COMPLETED":
            report_lines.append(
                format_results(section["results"])
            )
        else:
            report_lines.append(
                f"Error: {section.get('error', 'Unknown error')}"
            )

    report_lines.extend([
        "",
        "=" * 70,
        "END OF EVALUATION REPORT"
    ])

    text_path = REPORT_DIR / "evaluation_report.txt"

    with open(text_path, "w", encoding="utf-8") as file:
        file.write("\n".join(report_lines))

    # --------------------------------------------------------
    # FINAL OUTPUT
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("AGENTSHIELD EVALUATION SUMMARY")
    print("=" * 70)

    print("Overall status:", results["overall_status"])

    print("\nAttack simulation:")
    print("Total:", attack_summary["total_scenarios"])
    print("Passed:", attack_summary["passed_scenarios"])
    print("Failed:", attack_summary["failed_scenarios"])
    print("Pass rate:", f"{attack_summary['pass_rate']:.2f}%")

    print("\nEvaluation files generated:")
    print("JSON:", json_path)
    print("Text:", text_path)

    print("\nFULL EVALUATION FINISHED")

    return results


# ============================================================
# EXECUTION
# ============================================================

if __name__ == "__main__":
    run_full_evaluation()
