#!/usr/bin/env python3
"""Check 7 -- missing-FO-check detector (Case 6).

[FAKTA] "Verifiable Decapsulation: Recognizing Faulty Implementations of
Post-Quantum KEMs" (Glabush, Günther, Hövelmanns & Stebila, IACR ePrint
2025/450; CRYPTO 2025) shows the re-encryption check in the FO transform
"is essential for security, but not for functionality. In other words,
it will go unnoticed if this essential step is omitted or wrongly
implemented, opening the door for key recovery attacks."

This script constructs ciphertexts that decrypt to a chosen message but
fail re-encryption, and shows the harness distinguishes a correct
implementation from a deliberately neutered one (FO check removed,
scripts/mlkem_neutered.py):
  * control: a genuine ciphertext passes on BOTH implementations --
    proving a correctness-only test suite cannot tell them apart;
  * adversarial: single-byte mutations of the genuine ciphertext's
    c1 component that still decrypt to the SAME message m (the
    compression slack absorbs the change) but fail re-encryption.
    The correct decapsulation returns Kbar = J(z || c*); the neutered
    variant returns K' = G(m || h) -- the genuine shared secret -- for
    a ciphertext that must be rejected.

Deterministic: fixed keypair and message; no randomness, no timestamps,
no network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem
import mlkem_neutered

PARAMS_ID = 768
N_ADVERSARIAL = 3


def main():
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name
              + ((" -- " + detail) if detail else ""))
        if not cond:
            failures.append(name)

    print("== missing_fo_check: detector for a removed FO check ==")
    print("[FAKTA] Verifiable Decapsulation (IACR ePrint 2025): the "
          "re-encryption check is essential for security but not for "
          "functionality -- omitting it is invisible to correctness tests")

    d = bytes([83]) * 32
    z = bytes([89]) * 32
    m = bytes([97]) * 32
    ek, dk = mlkem.keygen(d, z, PARAMS_ID)
    p = mlkem.PARAMS[PARAMS_ID]
    k = p["k"]
    dk_pke = dk[:384 * k]
    z_key = dk[768 * k + 64:768 * k + 96]
    shared, ct = mlkem.encaps_internal(ek, m, PARAMS_ID)

    # --- control: genuine ciphertext, both implementations agree -------
    correct = mlkem.decaps_internal(dk, ct, PARAMS_ID)
    neutered = mlkem_neutered.decaps_neutered(dk, ct, PARAMS_ID)
    print("control: genuine ct -> correct==shared: %s, "
          "neutered==shared: %s, correct==neutered: %s"
          % (correct == shared, neutered == shared,
             correct == neutered))
    check("CONTROL-AGREE", correct == neutered == shared,
          "correctness tests cannot distinguish the two implementations")

    # --- adversarial: mutate c1 until decryption still yields m --------
    # c1 is ct[:32*du*k]; a 1-bit flip there perturbs the decompressed u
    # slightly, and the message survives whenever no Compress1 boundary
    # is crossed. Any such ciphertext MUST be rejected (its
    # re-encryption is the original ct), but the neutered variant
    # returns the genuine shared secret for it.
    c1_len = 32 * p["du"] * k
    adversarial = []
    for pos in range(c1_len):
        if len(adversarial) >= N_ADVERSARIAL:
            break
        mutated = bytearray(ct)
        mutated[pos] ^= 0x01
        mutated = bytes(mutated)
        if mlkem.kpke_decrypt(dk_pke, mutated, PARAMS_ID) == m:
            adversarial.append((pos, mutated))
    print("adversarial ciphertexts found: %d (scanned c1 byte positions "
          "until %d found)" % (len(adversarial), N_ADVERSARIAL))
    check("ADVERSARIAL-FOUND", len(adversarial) == N_ADVERSARIAL,
          "%d ciphertexts decrypt to the chosen message but fail "
          "re-encryption" % len(adversarial))

    distinguished = 0
    for pos, c_star in adversarial:
        got_correct = mlkem.decaps_internal(dk, c_star, PARAMS_ID)
        got_neutered = mlkem_neutered.decaps_neutered(dk, c_star, PARAMS_ID)
        expected_kbar = mlkem._j(z_key + c_star)
        print("  c1 byte %d flipped: correct -> Kbar==J(z||c*): %s; "
              "neutered -> shared secret K: %s; differ: %s"
              % (pos, got_correct == expected_kbar,
                 got_neutered == shared,
                 got_correct != got_neutered))
        if got_correct == expected_kbar and got_neutered == shared:
            distinguished += 1
    check("DETECTOR-DISTINGUISHES", distinguished == len(adversarial),
          "%d/%d adversarial ciphertexts separate correct from neutered"
          % (distinguished, len(adversarial)))

    print()
    if failures:
        print("MISSING_FO_CHECK VERDICT: FAIL -- %s" % ", ".join(failures))
        return 1
    print("MISSING_FO_CHECK VERDICT: PASS -- pack catches the invisible "
          "failure class: %d/%d adversarial ciphertexts return Kbar on "
          "the correct implementation and the genuine shared secret on "
          "the neutered one" % (distinguished, len(adversarial)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
