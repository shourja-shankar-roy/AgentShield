
from evaluation.input_test_dataset import (
    BENIGN_PROMPTS,
    MALICIOUS_PROMPTS
)

from security.input_inspector import inspect_input


def percentage(numerator, denominator):
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100


def run_benchmark():
    print("\nAgentShield Input Inspector Benchmark")
    print("=" * 55)

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    false_positives = []
    false_negatives = []

    # Benign prompts: expected classification is SAFE.
    print("\nTesting benign prompts...")

    for index, prompt in enumerate(BENIGN_PROMPTS, start=1):
        result = inspect_input(prompt)
        detected = not result["safe"]

        if detected:
            fp += 1
            false_positives.append((index, prompt, result))
        else:
            tn += 1

    # Malicious prompts: expected classification is MALICIOUS.
    print("Testing malicious prompts...")

    for index, prompt in enumerate(MALICIOUS_PROMPTS, start=1):
        result = inspect_input(prompt)
        detected = not result["safe"]

        if detected:
            tp += 1
        else:
            fn += 1
            false_negatives.append((index, prompt, result))

    total = tp + tn + fp + fn

    accuracy = percentage(tp + tn, total)
    precision = percentage(tp, tp + fp)
    recall = percentage(tp, tp + fn)
    f1_score = (
        2 * precision * recall / (precision + recall)
        if precision + recall > 0
        else 0.0
    )
    false_positive_rate = percentage(fp, fp + tn)

    print("\n" + "=" * 55)
    print("CONFUSION MATRIX")
    print("=" * 55)

    print(f"True Positives  (TP): {tp}")
    print(f"True Negatives  (TN): {tn}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")

    print("\n" + "=" * 55)
    print("PERFORMANCE METRICS")
    print("=" * 55)

    print(f"Total prompts:       {total}")
    print(f"Accuracy:            {accuracy:.2f}%")
    print(f"Precision:           {precision:.2f}%")
    print(f"Recall:              {recall:.2f}%")
    print(f"F1-score:            {f1_score:.2f}%")
    print(f"False-positive rate: {false_positive_rate:.2f}%")

    if false_positives:
        print("\n" + "=" * 55)
        print("FALSE POSITIVES")
        print("=" * 55)

        for index, prompt, result in false_positives:
            print(f"\nBenign prompt #{index}: {prompt}")
            print(f"Risk: {result['risk_level']}")
            print(f"Findings: {result['findings']}")

    if false_negatives:
        print("\n" + "=" * 55)
        print("FALSE NEGATIVES")
        print("=" * 55)

        for index, prompt, result in false_negatives:
            print(f"\nMalicious prompt #{index}: {prompt}")
            print(f"Risk: {result['risk_level']}")
            print(f"Findings: {result['findings']}")

    print("\n" + "=" * 55)
    print("BENCHMARK COMPLETED")
    print("=" * 55)

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "false_positive_rate": false_positive_rate
    }


if __name__ == "__main__":
    run_benchmark()
