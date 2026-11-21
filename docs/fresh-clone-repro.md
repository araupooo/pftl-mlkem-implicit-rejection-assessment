# Fresh-Clone Reproduction

Exact procedure for reproducing this pack's results from a fresh copy.
No network access is needed at any step.

## Prerequisites

- [FAKTA] python3 ≥ 3.9, standard library only. No other tools, no
  network at run time — the scripts read only the vendored
  `data/PQCkemKAT_*.rsp` files; nothing is fetched.
- `sha256sum` (for the checksum step) and `bash`.
- A fresh copy of the pack: copy the whole pack directory to a new
  location (or clone the repository fresh) and work in the copy, so the
  committed `outputs/` are not overwritten in place.

## Commands

```sh
# 1. From the pack root, verify the pristine copy first.
#    This MUST run before the checks below: scripts/run_all.sh
#    regenerates outputs/, and outputs/timing.log is non-deterministic
#    (raw nanosecond measurements), so a checksum check after the run
#    would fail on timing.log. The checksum step proves checkout
#    integrity; the run step proves the checks pass.
sha256sum -c SHA256SUMS

# 2. Run all seven checks (captures unedited logs to outputs/).
bash scripts/run_all.sh

# 3. List the artifact (the seven unedited logs).
ls -la outputs/
```

The CI workflow (`.github/workflows/verify.yml`) runs these steps in
exactly this order: checksum on the pristine checkout, then the run,
then upload of `outputs/` as the `evidence-logs` artifact.

## Expected outputs

- Step 1: every file reports `OK` (the checksum file lists every file
  in the pack except itself).
- Step 2: each script prints `PASS <name>` and the runner prints the
  final line:

  ```
  RUN_ALL RESULT: ALL CHECKS PASSED (7/7 scripts)
  ```

  The runner exits 0 only if every script exits 0; otherwise it prints
  `RUN_ALL RESULT: FAILED` and exits non-zero.
- Step 3: seven logs in `outputs/`:
  `spec_fidelity.log`, `tail_mutation.log`, `input_checks.log`,
  `timing.log`, `key_mismatch.log`, `caller_misuse.log`,
  `missing_fo_check.log`.

Expected verdict lines (one per log):

```
SPEC_FIDELITY VERDICT: PASS -- accept + reject paths byte-exact for 100 vectors x 3 parameter sets; liboqs single+all hashes match
TAIL_MUTATION VERDICT: PASS -- 3424 positions tested, 0 acceptances; every mutation yields exactly J(z||c')
INPUT_CHECKS VERDICT: PASS -- checked wrappers refuse every malformed input; z-tamper behaviour recorded as specified
TIMING VERDICT: PASS -- accept/reject timing indistinguishable within 5% at N=1000 per path per set (3 sets)
KEY_MISMATCH VERDICT: PASS -- 16 coefficients recovered at 2.2500 queries/coefficient (1.1080 queries/bit vs 2.0306-bit Huffman bound); CCA decaps rejects all crafted ciphertexts
CALLER_MISUSE VERDICT: PASS -- all three misuse transcripts demonstrate the concrete leak/break as specified
MISSING_FO_CHECK VERDICT: PASS -- pack catches the invisible failure class: 3/3 adversarial ciphertexts return Kbar on the correct implementation and the genuine shared secret on the neutered one
```

## Expected SHA-256 of each committed log

[FAKTA] These are the committed values from `SHA256SUMS` (the committed
logs themselves; the file hashes of the logs do not change when the
documentation is revised). Every log except `timing.log` must match
byte-for-byte after a fresh run. For `timing.log`, see the exception
below — compare its verdict line, N, and parameter sets, not its hash.

```
ec5e7f282f4e6b080215dfbd6d62f8215ed66e878f60a8cd30f77a6e384208db  outputs/caller_misuse.log
cc65d6a8902ff06b2f3c89ccd9fa79bee883d1765d981d78de49c7c7e94ec1f6  outputs/input_checks.log
008c088e02c9dce72c0d128bd57cc3805d70fc87f57dac9a2a7024a897279d5d  outputs/key_mismatch.log
36bfd5e0cdc1aeba215f89bc9570bb024912959b1b39a3c8280378771f04e4da  outputs/missing_fo_check.log
78e9f83e93cf99ca7f57c8e60cd45a323344da09cd7e909b331ae5781fa756f0  outputs/spec_fidelity.log
a0296cb18101c045a0c1fffe5f582672ef5d03f5c1a6263553024fe2fc8e9156  outputs/tail_mutation.log
09423c76ddfce80e8bb770aa876518fdc9059587f3fca97f0b6462906ea5a2cc  outputs/timing.log
```

## The timing-log exception

[FAKTA] `timing.py` measures real nanosecond timings, so its log can
never be byte-identical across runs. Reproduction must compare its stable
`TIMING VERDICT: PASS/FAIL` line, the N (1000 per path per set), and the
parameter sets — not the raw timings and not the per-run relative-gap
percentages. The committed run's gaps were +1.0755% / −1.4641% /
−0.9105% (512 / 768 / 1024) with 95% confidence intervals all including
zero; a fresh run will show different percentages. The stable,
reproducible fact is the verdict: PASS within 5% at N=1000 per path per
set. A simulation run during this pack's preparation returned gaps of
0.0168% / 0.7382% / 1.0768% with the same PASS verdict, confirming that
the percentages vary run to run while the verdict holds.

## If a check fails

- A failure in any log other than `timing.log` is a real regression:
  those logs are deterministic (fixed seeds, no randomness, no
  timestamps, no network) and must be byte-identical to the committed
  versions above.
- A `TIMING VERDICT: FAIL` means the accept/reject gap exceeded 5% on
  that machine: re-run once (machine load affects the measurement), and
  if it still fails, treat it as a genuine timing signal to investigate,
  not as flakiness to ignore.
- Do not "fix" a failing reproduction by editing a committed log or by
  editing `SHA256SUMS` by hand; report the failing log verbatim.

## This run

Record of the fresh-copy reproduction run for this copy of the pack
(22 Nov 2026, 00:08 WIB):

- Method: `cp -r pack /tmp/mlkem-fresh`, `rm -rf outputs`, then
  `bash scripts/run_all.sh` in the copy. Python 3.12.3.
- Result: **ALL CHECKS PASSED (7/7 scripts)**, exit 0, runtime 2m17.9s.
  Full run stdout is in `repro/fresh-clone-run.log`
  (SHA-256 `137fcc2718bae6494ef6d551c1383a31c872edc0cc7a923fcdbbf4d91f144650`).
- Comparison against the committed `outputs/`: 6/6 deterministic logs
  byte-identical (`spec_fidelity`, `tail_mutation`, `input_checks`,
  `key_mismatch`, `caller_misuse`, `missing_fo_check`).
  `timing.log` matches on its verdict line
  (`TIMING VERDICT: PASS`, N=1000 per path per set, 3 sets); the fresh
  run's relative gaps were −0.4309% / −0.9479% / −0.7721%
  (512 / 768 / 1024), different percentages from the committed run, same
  PASS verdict — as the timing-log exception above predicts.

Second independent verification, same method, after a wording-only fix
pass (22 Nov 2026, 00:26 WIB; `cp -r pack /tmp/mlkem-fresh2`, `rm -rf
outputs`, `bash scripts/run_all.sh`, Python 3.12.3): **ALL CHECKS PASSED
(7/7 scripts)**, exit 0, runtime 2m15.988s. 6/6 deterministic logs
byte-identical; timing verdict PASS with fresh-run gaps −0.2513% /
+0.3614% / −0.1076% (512 / 768 / 1024). Full record appended in
`repro/fresh-clone-run.log`.
