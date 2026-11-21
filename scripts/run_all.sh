#!/usr/bin/env bash
# run_all.sh — reproduce every check in this pack from a fresh clone.
#
# What it needs (already installed on a normal dev machine):
#   python3 (>= 3.9, standard library only). No other tools, no network.
#   The scripts read only the vendored data/PQCkemKAT_*.rsp files; nothing
#   is fetched at run time.
#
# What it runs (in order, each log unedited into outputs/):
#   1. spec_fidelity.py    — KAT verification, accept + reject paths, 3 sets
#   2. tail_mutation.py    — Das tail-mutation sweep, every byte position
#   3. input_checks.py     — FIPS 203 section 7.2 / 7.3 input-check battery
#   4. timing.py           — accept vs reject decapsulation timing
#   5. key_mismatch.py     — Shao et al. baseline-comparison probe
#   6. caller_misuse.py    — three minimal caller-misuse transcripts
#   7. missing_fo_check.py — detector for a removed FO re-encryption check
#
# Exit status: 0 only if every script exits 0; otherwise non-zero.
# Prints a final ALL CHECKS PASSED / FAILED summary.
#
# NOTE: scripts are invoked via `python3` (not `./`) on purpose: files
# uploaded through the GitHub web UI lose their executable bit, so a fresh
# clone would fail with exit 126 if run_all.sh called ./script.py directly.
#
# NOTE on determinism: every script is deterministic (fixed seeds, no
# randomness, no timestamps, no network) EXCEPT scripts/timing.py, whose
# raw nanosecond measurements vary run to run by nature. Its log is
# reproducible in its verdict line ("TIMING VERDICT: PASS/FAIL"), N, and
# parameter sets -- not in the raw timings. See scripts/README.md.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p outputs
echo "=== run_all.sh ==="
echo "python3: $(python3 --version 2>&1)"
echo "scripts: 7 python3 checks (see outputs/)"

FAILED=""
for script in spec_fidelity tail_mutation input_checks timing \
              key_mismatch caller_misuse missing_fo_check; do
    log="outputs/${script}.log"
    echo "--- running scripts/${script}.py -> ${log} ---"
    if python3 "scripts/${script}.py" > "$log" 2>&1; then
        echo "PASS ${script} (see ${log})"
    else
        echo "FAIL ${script} (see ${log})"
        FAILED="$FAILED $script"
    fi
    echo
done

if [ -n "$FAILED" ]; then
    echo "RUN_ALL RESULT: FAILED — failing scripts:$FAILED"
    exit 1
fi
echo "RUN_ALL RESULT: ALL CHECKS PASSED (7/7 scripts)"
exit 0
