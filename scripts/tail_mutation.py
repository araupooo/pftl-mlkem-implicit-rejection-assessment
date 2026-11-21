#!/usr/bin/env python3
"""Check 2 -- tail-mutation sweep (Das test).

[FAKTA] Das (IACR ePrint 2026/1682) shows an incomplete FO ciphertext
comparison is a key-recovery vulnerability: wolfSSL compared only 1,536
of 1,568 bytes (AVX2) / ~half the ciphertext (NEON), and 98.0% of 2,048
secret coefficients were recovered from 400 chosen ciphertexts. The
recommended test is a tail-mutation sweep: mutate single bytes confined
to the ciphertext tail; any mutation that fails to trigger implicit
rejection means the comparison is incomplete.

This script mutates EVERY byte position of a valid ciphertext, one at a
time (XOR 0x01), for each parameter set, and asserts every mutation
yields exactly the expected rejection key Kbar = J(z || c'). Positions
tested: 768 (ML-KEM-512) + 1088 (768) + 1568 (1024) = 3424. Acceptances
must be 0. The final 32 bytes (the v-component tail, the exact region
wolfSSL's AVX2 path skipped) are reported separately.

Deterministic: fixed keypair (d, z) and message m per set; no randomness,
no timestamps, no network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem

# Fixed seeds per parameter set (d, z, m as 32-byte values).
SEEDS = {
    512: (bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))),
    768: (bytes([7]) * 32, bytes([11]) * 32, bytes([13]) * 32),
    1024: (bytes([3]) * 32, bytes([5]) * 32, bytes([9]) * 32),
}


def main():
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name
              + ((" -- " + detail) if detail else ""))
        if not cond:
            failures.append(name)

    print("== tail_mutation: Das tail-mutation sweep (every byte position) ==")
    print("[FAKTA] Das 2026/1682: wolfSSL AVX2 compared 1536/1568 bytes; "
          "98.0% of 2048 coefficients recovered from 400 chosen ciphertexts")

    total_positions = 0
    total_accepted = 0
    for params_id in (512, 768, 1024):
        p = mlkem.PARAMS[params_id]
        k = p["k"]
        d, z, m = SEEDS[params_id]
        ek, dk = mlkem.keygen(d, z, params_id)
        shared, ct = mlkem.encaps_internal(ek, m, params_id)
        assert mlkem.decaps_internal(dk, ct, params_id) == shared
        z_key = dk[768 * k + 64:768 * k + 96]
        n = len(ct)
        accepted = []
        tail_accepted = []
        tail_checked = 0
        for pos in range(n):
            mutated = bytearray(ct)
            mutated[pos] ^= 0x01
            mutated = bytes(mutated)
            expected = mlkem._j(z_key + mutated)
            got = mlkem.decaps_internal(dk, mutated, params_id)
            if got != expected:
                accepted.append(pos)
            if pos >= n - 32:
                tail_checked += 1
                if got != expected:
                    tail_accepted.append(pos)
        total_positions += n
        total_accepted += len(accepted)
        print("-- ML-KEM-%d: ct %d bytes, positions tested %d, "
              "acceptances %d (tail-32: tested %d, acceptances %d) --"
              % (params_id, n, n, len(accepted), tail_checked,
                 len(tail_accepted)))
        check("TAIL-%d" % params_id, len(accepted) == 0,
              "%d/%d mutations rejected with exact Kbar" % (n - len(accepted), n))
        check("TAIL32-%d" % params_id, len(tail_accepted) == 0,
              "final 32 bytes: %d/%d rejected" % (tail_checked - len(tail_accepted),
                                                  tail_checked))
        if accepted:
            print("  accepted positions (first 20): %s" % accepted[:20])

    print()
    if failures or total_accepted:
        print("TAIL_MUTATION VERDICT: FAIL -- %d positions tested, %d "
              "acceptance(s)" % (total_positions, total_accepted))
        return 1
    print("TAIL_MUTATION VERDICT: PASS -- %d positions tested, 0 "
          "acceptances; every mutation yields exactly J(z||c')"
          % total_positions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
