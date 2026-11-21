#!/usr/bin/env python3
"""Check 6 -- caller-misuse scenarios (runnable transcripts).

[ANALISIS] Implicit rejection hands every caller a plausible-looking
32-byte key on failure. The danger is not in decapsulation -- it is in
what callers do with the result. Three minimal callers, each with a
concrete runnable transcript:

  (i)   No key confirmation, uses Kbar as a session key: a tampered
        ciphertext decapsulates to a deterministic rejection key; the
        caller treats it as genuine, so the "session" is silently wrong
        (the peer, holding the true K, cannot communicate) -- and the
        same tampered ciphertext always yields the same Kbar, so the
        rejection is deterministic and replayable.
  (ii)  Logs decapsulation outcomes: the caller logs ACCEPT/REJECT per
        ciphertext (e.g. from key confirmation succeeding or failing).
        Those log lines are a decryption-failure oracle in a file: an
        attacker who can read the logs -- or who can trigger log volume
        -- learns accept/reject per chosen ciphertext, exactly the
        oracle the FO transform exists to close (FIPS 203 section 6.3:
        returning the flag "in any form is not permitted").
  (iii) Retries a rejected ciphertext: decapsulation is deterministic
        (FIPS 203 section 6.3: "Decapsulation does not use any
        randomness"), so retrying the same ciphertext returns the same
        Kbar forever; only a fresh encapsulation can succeed.

Deterministic: fixed keys and messages; no randomness, no timestamps,
no network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem

PARAMS_ID = 768


def _setup():
    d = bytes([61]) * 32
    z = bytes([67]) * 32
    m = bytes([71]) * 32
    ek, dk = mlkem.keygen(d, z, PARAMS_ID)
    shared, ct = mlkem.encaps_internal(ek, m, PARAMS_ID)
    return ek, dk, shared, ct


def scenario_no_key_confirmation(ek, dk, shared, ct):
    """(i) Caller uses the decapsulated key with no key confirmation."""
    print("-- scenario (i): no key confirmation, Kbar used as session key --")
    tampered = bytearray(ct)
    tampered[100] ^= 0x01
    tampered = bytes(tampered)
    # The caller decapsulates the tampered ciphertext and uses the result
    # directly as a session key, without any key confirmation step.
    session_key_1 = mlkem.decaps_internal(dk, tampered, PARAMS_ID)
    session_key_2 = mlkem.decaps_internal(dk, tampered, PARAMS_ID)
    peer_key = shared  # the peer holds the true K from encapsulation
    print("  tampered ct decaps -> session key: %s..."
          % session_key_1.hex()[:16])
    print("  same tampered ct decaps again -> identical key: %s"
          % (session_key_1 == session_key_2))
    print("  peer's true session key:          %s..."
          % peer_key.hex()[:16])
    print("  caller key == peer key: %s" % (session_key_1 == peer_key))
    print("  [ANALISIS] LEAK/BREAK: the caller silently uses Kbar as if "
          "it were K -- the session is broken (peer cannot decrypt "
          "anything), and the failure is deterministic: the same "
          "ciphertext always yields the same Kbar, so the rejection is "
          "replayable and recognisable across sessions")
    return session_key_1 != peer_key and session_key_1 == session_key_2


def scenario_logs_outcomes(ek, dk, shared, ct):
    """(ii) Caller logs decapsulation outcomes (accept/reject per ct)."""
    print("-- scenario (ii): caller logs decapsulation outcomes --")
    log_lines = []
    probes = []
    for i in range(4):
        probe = bytearray(ct)
        probe[i * 200] ^= 0x01
        probes.append(bytes(probe))
    probes.append(ct)  # one genuine ciphertext, for contrast
    for probe in probes:
        got = mlkem.decaps_internal(dk, probe, PARAMS_ID)
        # The caller "knows" accept/reject via key confirmation against
        # the expected shared secret (lab stand-in for a real KCF step).
        outcome = "ACCEPT" if got == shared else "REJECT"
        line = "decaps ct=%s... %s" % (probe.hex()[:12], outcome)
        log_lines.append(line)
        print("  LOG: " + line)
    print("  [ANALISIS] LEAK/BREAK: the log records accept/reject for "
          "every chosen ciphertext -- a decryption-failure oracle written "
          "to disk. Anyone who can read the logs (or count log volume / "
          "error counters) learns exactly which crafted ciphertexts the "
          "key accepted, which is the oracle FIPS 203 section 6.3 "
          "forbids returning 'in any form'")
    return all("REJECT" in line for line in log_lines[:-1]) and \
        "ACCEPT" in log_lines[-1]


def scenario_retries_rejected(ek, dk, shared, ct):
    """(iii) Caller retries a rejected ciphertext."""
    print("-- scenario (iii): caller retries a rejected ciphertext --")
    tampered = bytearray(ct)
    tampered[500] ^= 0x01
    tampered = bytes(tampered)
    results = [mlkem.decaps_internal(dk, tampered, PARAMS_ID)
               for _ in range(3)]
    print("  retry 1 -> %s..." % results[0].hex()[:16])
    print("  retry 2 -> %s... (same: %s)"
          % (results[1].hex()[:16], results[1] == results[0]))
    print("  retry 3 -> %s... (same: %s)"
          % (results[2].hex()[:16], results[2] == results[0]))
    # A fresh encapsulation succeeds: the fix is a new ciphertext, not
    # a retry.
    fresh_shared, fresh_ct = mlkem.encaps_internal(ek, bytes([73]) * 32,
                                                   PARAMS_ID)
    fresh_ok = mlkem.decaps_internal(dk, fresh_ct, PARAMS_ID) == fresh_shared
    print("  fresh encapsulation decaps == shared: %s" % fresh_ok)
    print("  [ANALISIS] LEAK/BREAK: retrying a rejected ciphertext never "
          "changes the outcome -- decapsulation is deterministic, so a "
          "retry loop burns queries and, against a static key, hands a "
          "key-mismatch attacker free oracle queries; only a fresh "
          "encapsulation can succeed")
    return results[0] == results[1] == results[2] and fresh_ok


def main():
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name
              + ((" -- " + detail) if detail else ""))
        if not cond:
            failures.append(name)

    print("== caller_misuse: three minimal callers, runnable transcripts ==")
    print("[FAKTA] FIPS 203 section 6.3: decapsulation uses no randomness "
          "and never signals failure; the accept/reject flag must not be "
          "returned in any form")
    ek, dk, shared, ct = _setup()
    print("setup: ML-KEM-768, genuine decaps == shared: %s"
          % (mlkem.decaps_internal(dk, ct, PARAMS_ID) == shared))

    ok1 = scenario_no_key_confirmation(ek, dk, shared, ct)
    check("MISUSE-NO-KCF", ok1,
          "Kbar used as session key, != peer K, deterministic across runs")
    ok2 = scenario_logs_outcomes(ek, dk, shared, ct)
    check("MISUSE-LOGS", ok2,
          "log lines leak ACCEPT/REJECT per chosen ciphertext")
    ok3 = scenario_retries_rejected(ek, dk, shared, ct)
    check("MISUSE-RETRY", ok3,
          "3 retries return identical Kbar; fresh encaps succeeds")

    print()
    if failures:
        print("CALLER_MISUSE VERDICT: FAIL -- %s" % ", ".join(failures))
        return 1
    print("CALLER_MISUSE VERDICT: PASS -- all three misuse transcripts "
          "demonstrate the concrete leak/break as specified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
