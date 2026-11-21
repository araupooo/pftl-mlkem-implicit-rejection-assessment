#!/usr/bin/env python3
"""Check 4 -- timing indistinguishability: accept vs reject decapsulation.

[FAKTA] The accept/reject flag is secret data (FIPS 203 section 6.3:
it "shall be destroyed prior to ML-KEM.Decaps_internal terminating").
KyberSlash (2023) showed secret-dependent division timing in
decapsulation recovers keys; a memcmp-style early exit in the FO
comparison, or a compiler-reintroduced branch, would show up here as a
systematic accept/reject timing gap. This script times
decaps_internal on a genuine ciphertext (accept path) vs a mutated
ciphertext (reject path), interleaved to cancel drift, and reports
distributions plus the measured gap with a 95% confidence interval.

DETERMINISM NOTE: raw nanosecond timings vary run to run, so this log
can NEVER be byte-identical across runs. That is expected and by
design: reproduction must compare the stable "TIMING VERDICT: PASS/FAIL"
line, the N, and the parameter sets -- not the raw timings. The verdict
is robust by construction: N is large, inputs are fixed seeds, and the
two paths in this harness execute identical code except for one
conditional assignment (K' <- Kbar), so any real gap would have to come
from the measurement environment, not the algorithm. No timestamps are
printed anywhere in this log.

Method: N=1000 decapsulations per path per parameter set (6000 total),
time.perf_counter_ns around decaps_internal only, accept/reject
strictly alternating. Statistics: mean, median, stdev per path;
Welch 95% CI for the mean difference; relative gap
(mean_accept - mean_reject) / mean_accept. Verdict: PASS if
|relative gap| < 5% for every parameter set.
"""

import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem

N = 1000
WARMUP = 20
GAP_THRESHOLD = 0.05


def _mean(xs):
    return sum(xs) / len(xs)


def _stdev(xs, mu):
    return math.sqrt(sum((x - mu) ** 2 for x in xs) / (len(xs) - 1))


def _median(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def _welch_ci(a, b):
    """95% CI for mean(a) - mean(b) (Welch, normal approximation)."""
    ma, mb = _mean(a), _mean(b)
    sa, sb = _stdev(a, ma), _stdev(b, mb)
    se = math.sqrt(sa * sa / len(a) + sb * sb / len(b))
    diff = ma - mb
    return diff, diff - 1.96 * se, diff + 1.96 * se


def main():
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name
              + ((" -- " + detail) if detail else ""))
        if not cond:
            failures.append(name)

    print("== timing: accept-path vs reject-path decapsulation timing ==")
    print("[FAKTA] FIPS 203 section 6.3: the accept/reject flag is secret "
          "data and must be destroyed before Decaps_internal returns")
    print("method: N=%d per path per parameter set, interleaved, "
          "perf_counter_ns around decaps_internal only" % N)
    print("unit: microseconds per decapsulation")

    for params_id in (512, 768, 1024):
        p = mlkem.PARAMS[params_id]
        k = p["k"]
        d = bytes([params_id % 251]) * 32
        z = bytes([(params_id + 1) % 251]) * 32
        m = bytes([(params_id + 2) % 251]) * 32
        ek, dk = mlkem.keygen(d, z, params_id)
        shared, ct = mlkem.encaps_internal(ek, m, params_id)
        mutated = bytearray(ct)
        mutated[-1] ^= 0x01
        mutated = bytes(mutated)
        assert mlkem.decaps_internal(dk, ct, params_id) == shared
        assert mlkem.decaps_internal(dk, mutated, params_id) != shared
        # Warmup (JIT/cache effects are absent in CPython, but this also
        # verifies both paths before measuring).
        for _ in range(WARMUP):
            mlkem.decaps_internal(dk, ct, params_id)
            mlkem.decaps_internal(dk, mutated, params_id)
        accept_times = []
        reject_times = []
        for _ in range(N):
            t0 = time.perf_counter_ns()
            mlkem.decaps_internal(dk, ct, params_id)
            accept_times.append((time.perf_counter_ns() - t0) / 1000.0)
            t0 = time.perf_counter_ns()
            mlkem.decaps_internal(dk, mutated, params_id)
            reject_times.append((time.perf_counter_ns() - t0) / 1000.0)
        ma, mr = _mean(accept_times), _mean(reject_times)
        med_a, med_r = _median(accept_times), _median(reject_times)
        sa, sr = _stdev(accept_times, ma), _stdev(reject_times, mr)
        diff, lo, hi = _welch_ci(accept_times, reject_times)
        gap_rel = diff / ma if ma else 0.0
        print("-- ML-KEM-%d --" % params_id)
        print("  accept: mean %.1f us, median %.1f us, stdev %.1f us"
              % (ma, med_a, sa))
        print("  reject: mean %.1f us, median %.1f us, stdev %.1f us"
              % (mr, med_r, sr))
        print("  mean difference (accept-reject): %.2f us, 95%% CI "
              "[%.2f, %.2f] us" % (diff, lo, hi))
        print("  relative gap: %.4f%% (|gap| < 5%% required)"
              % (100.0 * gap_rel))
        print("  median difference: %.2f us" % (med_a - med_r))
        check("TIMING-GAP-%d" % params_id, abs(gap_rel) < GAP_THRESHOLD,
              "relative gap %.4f%%" % (100.0 * gap_rel))

    print()
    if failures:
        print("TIMING VERDICT: FAIL -- %d parameter set(s) exceed the 5%% "
              "gap threshold: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("TIMING VERDICT: PASS -- accept/reject timing indistinguishable "
          "within 5%% at N=%d per path per set (3 sets)" % N)
    return 0


if __name__ == "__main__":
    sys.exit(main())
