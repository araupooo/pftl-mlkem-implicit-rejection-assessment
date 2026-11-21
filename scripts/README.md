# scripts/ — ML-KEM implicit-rejection analysis harness

Clean-room ML-KEM-512/768/1024 from FIPS 203 (August 2024), Python
standard library only. Every script prints a PASS/FAIL verdict line and
is deterministic (fixed seeds, no randomness, no timestamps, no network)
with one documented exception below.

## Files

| Path | Contents |
|---|---|
| `mlkem.py` | Clean-room ML-KEM (K-PKE §5 + FO transform, Algorithms 16–18), plus the NIST KAT DRBG (AES-256, used only for KAT seed expansion) |
| `mlkem_neutered.py` | Deliberately neutered decapsulation (FO re-encryption check removed) — test fixture only, used by `missing_fo_check.py` |
| `spec_fidelity.py` | Check 1: KAT verification, accept + reject paths, all 3 sets |
| `tail_mutation.py` | Check 2: Das tail-mutation sweep, every byte position |
| `input_checks.py` | Check 3: FIPS 203 §7.2/§7.3 input-check battery |
| `timing.py` | Check 4: accept vs reject decapsulation timing |
| `key_mismatch.py` | Check 5: Shao et al. baseline-comparison probe |
| `caller_misuse.py` | Check 6: three minimal caller-misuse transcripts |
| `missing_fo_check.py` | Check 7: detector for a removed FO check |
| `run_all.sh` | Runs all seven checks, captures unedited logs to `outputs/` |

## KAT vector source + commit

[FAKTA] The KAT vectors in `../data/PQCkemKAT_{512,768,1024}.rsp` were
generated locally from the NIST reference implementation
(pq-crystals/kyber, branch `standard`, commit
`d5b791c0c601b543233daccbae2845c6197a9e77`, 21 Aug 2024) by compiling its
`ref/nistkat/PQCgenKAT_kem.c` generator and running it (100 vectors per
parameter set). The pack's implementation reproduces all 100 vectors per
set byte-exactly (pk, sk, ct, ss), and the recomputed kat_kem stdout
hashes match liboqs `tests/KATs/kem/kats.json` (commit
`b6689666b934f56773d43dfdcb14e42d898d7dec`, 17 Jun 2026) `single` and
`all` SHA-256 values for ML-KEM-512/768/1024. The vectors are ML-KEM
KATs, not pre-standard Kyber KATs. Second independent cross-check:
bidirectional interop with pqcrypto's `ml_kem_512/768/1024` (build-time
check only, never a runtime dependency).

## Timing-log determinism exception

`timing.py` measures real nanosecond timings, so its log can never be
byte-identical across runs. Reproduction must compare its stable
`TIMING VERDICT: PASS/FAIL` line, the N (1000 per path per set), and the
parameter sets — not the raw timings. All other logs are byte-identical
across runs.
