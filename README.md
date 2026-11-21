# ML-KEM Implicit-Rejection Assessment

A clean-room ML-KEM implementation (FIPS 203, August 2024) plus seven
runnable analyses of the implicit-rejection decapsulation mechanism:
what it is, where it has failed in the field, and how a caller or a
deployment can silently convert it into explicit rejection. Every
substantive claim is labelled [FAKTA] (verified, source + date),
[ESTIMASI] (modelled/reported number), or [ANALISIS] (interpretation),
and every claim is mapped to a runnable check and a pinned primary
source in `docs/CLAIMS.md` and `docs/claim-evidence-index.md`; the
assessment itself is `docs/assessment-report.md`, and the reproduction
procedure is `docs/fresh-clone-repro.md`.

## What this pack proves

[FAKTA] FIPS 203 Algorithm 18 specifies implicit rejection exactly: on
a re-encryption mismatch, decapsulation returns K̄ = J(z ‖ c) — SHAKE256
of a secret 32-byte value z concatenated with the received ciphertext —
and never signals failure. The harness in `scripts/mlkem.py` reproduces
all 100 reference KAT vectors per parameter set byte-exactly (pk, sk, ct,
ss), including exact K̄ values for mutated ciphertexts.

[FAKTA] The FO comparison in this harness covers every ciphertext byte:
a tail-mutation sweep over all 3,424 byte positions (768 + 1,088 +
1,568) yields 0 acceptances. The 2026 wolfSSL failure this test is
designed to catch compared only 1,536 of 1,568 bytes (AVX2) and enabled
98.0% private-key recovery from 400 chosen ciphertexts (Das, IACR
ePrint 2026/1682).

[FAKTA] The checked wrappers enforce the FIPS 203 §7.2/§7.3 input
checks and refuse every malformed input in the battery (unreduced-mod-q
encapsulation keys, wrong-length ciphertexts, tampered embedded ek /
stored H(ek)). The reported RUSTSEC-2026-0585 baseline is 108/112/116
invalid encapsulation keys accepted per parameter set by an
implementation that skipped those checks.

[FAKTA] Accept-path and reject-path decapsulation are timing
indistinguishable in this harness at N=1000 per path per set (measured
relative gaps +1.0755% / −1.4641% / −0.9105% for ML-KEM-512/768/1024 in
the latest committed run, `outputs/timing.log`; 95% confidence
intervals all include zero). The specific percentages are from the
latest committed run and vary run to run — the stable, reproducible
fact is the verdict (PASS within 5% at N=1000 per path per set).

[FAKTA] The Shao et al. (ESORICS 2026) baseline-comparison key-mismatch
probe recovers 16/16 secret coefficients of s₀ at 2.25
queries/coefficient (1.11 queries/bit vs a 2.03-bit Huffman bound) using
a lab plaintext-checking oracle — and the same crafted ciphertexts all
return exactly K̄ from full decapsulation, because the bare
decapsulation API does not supply that oracle.

[ANALISIS] The three caller-misuse transcripts show concretely what
breaks when callers treat a rejection key as genuine, log outcomes, or
retry: a silently wrong session key, a decryption-failure oracle in a
log file, and a retry loop that can never succeed. And the
missing-FO-check detector proves the pack catches the invisible failure
class: ciphertexts that decrypt to a chosen message but fail
re-encryption return the genuine shared secret from the neutered
implementation and K̄ from the correct one, while a correctness-only
test suite cannot tell the two apart.

## How to run it

```sh
bash scripts/run_all.sh
```

Python 3.9+ standard library only; no network at run time — the scripts
read only the vendored `data/PQCkemKAT_*.rsp`. Each script prints
PASS/FAIL per check and writes its unedited stdout to
`outputs/<script>.log`. The runner exits non-zero if any script fails
and prints a final `ALL CHECKS PASSED` / `FAILED` summary.

Determinism note: every log is byte-identical across runs except
`outputs/timing.log`, whose raw nanosecond measurements vary by nature;
reproduce that check by its `TIMING VERDICT: PASS/FAIL` line, N, and
parameter sets. See `scripts/README.md`.

## File map

| Path | Contents |
|---|---|
| `scripts/mlkem.py` | Clean-room ML-KEM-512/768/1024 (FIPS 203 Algorithms 16–18) + NIST KAT DRBG |
| `scripts/mlkem_neutered.py` | Deliberately neutered decapsulation (FO check removed) — test fixture only |
| `scripts/spec_fidelity.py` | Check 1: KAT verification, accept + reject paths, 3 sets |
| `scripts/tail_mutation.py` | Check 2: Das tail-mutation sweep, every byte position |
| `scripts/input_checks.py` | Check 3: FIPS 203 §7.2/§7.3 input-check battery |
| `scripts/timing.py` | Check 4: accept vs reject decapsulation timing |
| `scripts/key_mismatch.py` | Check 5: Shao et al. baseline-comparison probe |
| `scripts/caller_misuse.py` | Check 6: three minimal caller-misuse transcripts |
| `scripts/missing_fo_check.py` | Check 7: detector for a removed FO check |
| `scripts/run_all.sh` | Runs all seven checks, captures unedited logs to `outputs/` |
| `data/PQCkemKAT_*.rsp` | Vendored reference KAT vectors, 100 per parameter set |
| `outputs/` | Unedited logs from the latest `run_all.sh` run (7/7 passed) |
| `docs/SOURCES.md` | Pinned primary sources |
| `docs/assessment-report.md` | Assessment: mechanism, cases, measurements, ledger integration |
| `docs/claim-evidence-index.md` | Numbered claim-to-evidence index (C1..Cn, incl. NOT VERIFIED) |
| `docs/CLAIMS.md` | Numbered claim list with label and evidence pointer |
| `docs/fresh-clone-repro.md` | Fresh-clone reproduction procedure |
| `repro/` | Fresh-clone reproduction log |
| `SHA256SUMS` | SHA-256 of every file in this pack (`sha256sum -c SHA256SUMS`) |

## Pinned sources

- FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
  Standard", 13 Aug 2024: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
  (§3.2, §3.3, §4.1–4.3, Algorithms 5–18, §7.2–7.3, §8).
- Reference implementation KATs: pq-crystals/kyber, branch `standard`,
  commit `d5b791c0c601b543233daccbae2845c6197a9e77`
  (https://github.com/pq-crystals/kyber) — `ref/nistkat/` generator;
  liboqs `tests/KATs/kem/kats.json`, commit
  `b6689666b934f56773d43dfdcb14e42d898d7dec`.
- Das, "Incomplete Ciphertext Comparison in ML-KEM", IACR ePrint
  2026/1682 (15 Aug 2026); CVE-2026-10097, CVE-2026-6330.
- Shao et al., "Closing the Gap: Huffman-Optimal and Stealthy
  Key-Mismatch Attacks on ML-KEM", ESORICS 2026, first online
  27 Sep 2026.
- RUSTSEC-2026-0585, "ML-KEM does not perform the FIPS 203 input
  checks", published 20 Nov 2026.
- "Verifiable Decapsulation: Recognizing Faulty Implementations of
  Post-Quantum KEMs" (Glabush, Günther, Hövelmanns & Stebila), IACR
  ePrint 2025/450; CRYPTO 2025.

Full source list with pins: `docs/SOURCES.md`.
