"""Run the small, synthetic TrustMail behavior check set (no network access)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trustmail.analyzer.evaluator import evaluate_email
from trustmail.parser import parse_email_defensively
from trustmail.analyzer.models import FindingCategory


CASES_FILE = Path(__file__).parent / "fixtures" / "synthetic_emails.json"


def main() -> int:
    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    false_positives = []
    false_negatives = []
    unsupported = 0
    unknown = 0
    exact_matches = 0

    for case in cases:
        assessment = evaluate_email(parse_email_defensively(case["email"].encode("utf-8")))
        # Dataset labels cover heuristic alerts, not routine facts or unknown states.
        actual_ids = sorted(
            f.id for f in assessment.findings if f.category == FindingCategory.HEURISTIC_FINDING
        )
        expected_ids = sorted(case["expected_finding_ids"])
        exact = actual_ids == expected_ids
        exact_matches += int(exact)
        actual_review = assessment.human_review_required
        if actual_review and not case["expected_review"]:
            false_positives.append(case["id"])
        elif case["expected_review"] and not actual_review:
            false_negatives.append(case["id"])

        unknown += sum(f.category == FindingCategory.UNKNOWN_INFORMATION for f in assessment.findings)
        unsupported += sum(
            f.category == FindingCategory.HEURISTIC_FINDING and not f.observations
            for f in assessment.findings
        )
        print(f"{case['id']}: expected IDs={expected_ids}; actual IDs={actual_ids}; "
              f"expected review={case['expected_review']}; actual review={actual_review}; "
              f"finding match={'yes' if exact else 'NO'}")

    count = len(cases)
    print("\nSynthetic evaluation summary")
    print(f"Cases evaluated: {count}")
    print(f"Exact expected-finding matches: {exact_matches}/{count}")
    print(f"Review-label false positives: {len(false_positives)} {false_positives}")
    print(f"Review-label false negatives: {len(false_negatives)} {false_negatives}")
    print(f"Unknown-information findings: {unknown}")
    print(f"Heuristic findings without structured observations: {unsupported}")
    print("Limit: these are synthetic examples and hand-written behavior labels; results do not estimate real-world accuracy.")
    return 0 if exact_matches == count and not false_positives and not false_negatives else 1


if __name__ == "__main__":
    raise SystemExit(main())
