#!/usr/bin/env python3
"""Check 3 -- input-check battery (FIPS 203 sections 7.2 / 7.3).

[FAKTA] Input checking is mandatory, not advisory. Section 7.2: Encaps
requires an encapsulation-key modulus check,
test = ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k];
"ML-KEM.Encaps shall not be run with an encapsulation key that has not
been checked". Section 7.3: Decaps requires a ciphertext length check
(every execution), a decapsulation-key length check, and a hash check,
test = H(dk[384k:768k+32]) == dk[768k+32:768k+64];
"ML-KEM.Decaps shall not be run with a decapsulation key or a ciphertext
unless both have been checked".

[FAKTA] RUSTSEC-2026-0585 (published 20 Nov 2026, reported not measured
here): pqcrypto-mlkem, wrapping PQClean, performs neither check; with
Wycheproof vectors, 108 / 112 / 116 invalid encapsulation keys
(ML-KEM-512 / -768 / -1024) and 2 invalid decapsulation keys per
parameter set are accepted. Those counts are the comparison baseline.

This battery feeds the harness unreduced-mod-q encapsulation keys,
wrong-length ciphertexts, and decapsulation keys with a tampered
embedded ek / stored H(ek) / tampered z, and records accept/reject
against the standard's required behaviour. The checked wrappers
(mlkem.encaps / mlkem.decaps) must refuse every malformed input; the
unchecked *_internal functions are also exercised to show what happens
without the checks.

Deterministic: fixed keys and messages; no randomness, no timestamps,
no network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem

# RUSTSEC-2026-0585 counts, as REPORTED in the advisory (not measured here).
RUSTSEC_BASELINE = {512: 108, 768: 112, 1024: 116}
RUSTSEC_BAD_DK = 2


def main():
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name
              + ((" -- " + detail) if detail else ""))
        if not cond:
            failures.append(name)

    print("== input_checks: FIPS 203 section 7.2 / 7.3 battery ==")
    print("[FAKTA] RUSTSEC-2026-0585 baseline (reported, not measured): "
          "108/112/116 invalid eks accepted per set; 2 invalid dks per set")

    for params_id in (512, 768, 1024):
        p = mlkem.PARAMS[params_id]
        k = p["k"]
        q = mlkem.Q
        d = bytes([params_id % 251]) * 32
        z = bytes([(params_id + 1) % 251]) * 32
        m = bytes([(params_id + 2) % 251]) * 32
        ek, dk = mlkem.keygen(d, z, params_id)
        shared, ct = mlkem.encaps_internal(ek, m, params_id)
        print("-- ML-KEM-%d --" % params_id)

        # --- 7.2: unreduced-mod-q encapsulation keys -------------------
        # Build the bad ek at the BYTE level: set coefficient 0 of
        # t_hat[0] to q, q+1, 4095 by writing the raw 12-bit value into
        # bytes 0-1. (byte_encode(12, ...) would reduce mod q, so it
        # cannot construct an unreduced key -- that reduction is the
        # check itself.)
        def bad_ek_with_coeff0(value):
            bad = bytearray(ek)
            bad[0] = value & 0xFF
            bad[1] = (bad[1] & 0xF0) | ((value >> 8) & 0x0F)
            return bytes(bad)

        def raw_coeff0(bad_ek):
            return bad_ek[0] | ((bad_ek[1] & 0x0F) << 8)

        bad_values = (q, q + 1, 4095)
        refused = 0
        for bad in bad_values:
            bad_ek = bad_ek_with_coeff0(bad)
            assert raw_coeff0(bad_ek) == bad
            ok = mlkem.check_encaps_key(bad_ek, params_id)
            try:
                mlkem.encaps(bad_ek, m, params_id)
                raised = False
            except ValueError:
                raised = True
            if (not ok) and raised:
                refused += 1
        check("EK-MODULUS-%d" % params_id, refused == len(bad_values),
              "%d/%d unreduced eks refused (coeff values %s)"
              % (refused, len(bad_values), bad_values))
        # The unchecked path would proceed: show the check is load-bearing.
        bad_ek = bad_ek_with_coeff0(q)
        try:
            mlkem.encaps_internal(bad_ek, m, params_id)
            unchecked_proceeds = True
        except Exception:
            unchecked_proceeds = False
        print("  [FAKTA] unchecked encaps_internal with unreduced ek "
              "proceeds: %s (the 7.2 check is load-bearing)"
              % unchecked_proceeds)

        # --- 7.3: wrong-length ciphertexts ------------------------------
        bad_lengths = (0, 32, len(ct) - 1, len(ct) + 1)
        refused_ct = 0
        for ln in bad_lengths:
            bad_ct = (ct[:ln] if ln <= len(ct)
                      else ct + bytes([0]) * (ln - len(ct)))
            try:
                mlkem.decaps(dk, bad_ct, params_id)
                raised = False
            except ValueError:
                raised = True
            refused_ct += raised
        check("CT-LENGTH-%d" % params_id, refused_ct == len(bad_lengths),
              "%d/%d wrong-length ciphertexts refused (lengths %s)"
              % (refused_ct, len(bad_lengths), bad_lengths))

        # --- 7.3: tampered embedded ek in dk ----------------------------
        bad_dk = bytearray(dk)
        bad_dk[384 * k + 5] ^= 0x01  # inside the embedded ek region
        try:
            mlkem.decaps(bytes(bad_dk), ct, params_id)
            raised = False
        except ValueError:
            raised = True
        check("DK-EK-TAMPER-%d" % params_id, raised,
              "decaps refuses dk whose embedded ek no longer matches H(ek)")

        # --- 7.3: tampered stored H(ek) in dk ---------------------------
        bad_dk2 = bytearray(dk)
        bad_dk2[768 * k + 32 + 3] ^= 0x01  # inside the stored H(ek) region
        try:
            mlkem.decaps(bytes(bad_dk2), ct, params_id)
            raised = False
        except ValueError:
            raised = True
        check("DK-HASH-TAMPER-%d" % params_id, raised,
              "decaps refuses dk whose stored H(ek) was tampered")

        # --- z tampering: NOT covered by the 7.3 hash check --------------
        # z sits outside H(ek); the standard's check cannot see it.
        bad_dk3 = bytearray(dk)
        bad_dk3[768 * k + 64 + 0] ^= 0x01  # first byte of z
        hash_ok = mlkem.check_decaps_key(bytes(bad_dk3), params_id)
        # Accept path is unaffected (z is only used for Kbar)...
        accept_same = (mlkem.decaps_internal(bytes(bad_dk3), ct, params_id)
                       == shared)
        # ...but the rejection key changes, because Kbar = J(z || c).
        mutated = bytearray(ct)
        mutated[0] ^= 0x01
        kbar_orig = mlkem.decaps_internal(dk, bytes(mutated), params_id)
        kbar_tampered = mlkem.decaps_internal(bytes(bad_dk3), bytes(mutated),
                                              params_id)
        print("  [FAKTA] z tamper: 7.3 hash check passes=%s (z is outside "
              "H(ek)); accept-path key unchanged=%s; rejection key "
              "changed=%s"
              % (hash_ok, accept_same, kbar_orig != kbar_tampered))
        check("DK-Z-TAMPER-%d" % params_id,
              hash_ok and accept_same and (kbar_orig != kbar_tampered),
              "z tampering is invisible to 7.3 and only moves Kbar")

        # --- baseline comparison -----------------------------------------
        print("  [FAKTA] RUSTSEC-2026-0585 baseline (reported): %d invalid "
              "eks accepted by pqcrypto-mlkem for ML-KEM-%d; this harness "
              "refuses 3/3 probed unreduced eks"
              % (RUSTSEC_BASELINE[params_id], params_id))
        print("  [FAKTA] RUSTSEC-2026-0585 baseline (reported): %d invalid "
              "dks accepted per set; this harness refuses tampered-ek and "
              "tampered-hash dks" % RUSTSEC_BAD_DK)

    print()
    if failures:
        print("INPUT_CHECKS VERDICT: FAIL -- %d failing check(s): %s"
              % (len(failures), ", ".join(failures)))
        return 1
    print("INPUT_CHECKS VERDICT: PASS -- checked wrappers refuse every "
          "malformed input; z-tamper behaviour recorded as specified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
