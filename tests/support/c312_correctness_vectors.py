#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reuse captured wire bytes with explicit current correctness decisions."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SUITES = ['c312-hid-ownership', 'c312-usb-readiness', 'c312-hid-admission',
          'c312-hid-channels', 'c312-usb-control']
DECISIONS = {'L8', 'C1-RETRIES', 'CID1', 'U3', 'U4'}


def generate():
    cases = []
    count = 0
    for suite in SUITES:
        original = json.loads((ROOT / 'tests/fixtures' / suite / 'vectors.json').read_text())
        for case in original['cases']:
            # Only decision metadata changes. No expected C/Rust byte, fixture
            # state, operation or schedule is normalized or regenerated.
            if 'difference' in case:
                difference = case['difference']
                assert difference['id'] in DECISIONS
                difference['disposition'] = 'intentional difference'
                difference['decision'] = 'docs/sync/c312-correctness-decisions.md'
                count += 1
            cases.append(case)
    assert count == 17
    return dict(schema=1, scope='Existing literal USB contracts with five explicit correctness decisions; all seventeen unequal cases remain outside parity totals.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(), indent=2) + '\n')
