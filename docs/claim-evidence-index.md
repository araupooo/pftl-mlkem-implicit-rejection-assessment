# Claim–Evidence Index — ML-KEM Implicit-Rejection Assessment

Each numbered claim (C1–C48 verified; NV1–NV6 not verified) with the exact
evidence behind it: the script, the committed log file, and the exact PASS
line or figure — or the pinned source entry. Labels: [FAKTA] verified with
source + date, [ESTIMASI] modelled/reported number, [ANALISIS]
interpretation. Status is `verified` or `not verified`; nothing in the
NV section is presented as verified anywhere in this pack.

Log hashes are the committed values in `SHA256SUMS`. All logs except
`outputs/timing.log` are byte-identical across runs; for the timing log,
compare the `TIMING VERDICT` line, N, and parameter sets — not raw
timings (see `docs/fresh-clone-repro.md`).

## A — FIPS 203 mechanism

| # | Claim | Label | Evidence | Status |
|---|---|---|---|---|
| C1 | FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard", published 13 August 2024 (DOI 10.6028/NIST.FIPS.203) | [FAKTA] | `docs/SOURCES.md §1` (PDF read directly 21 Nov 2026, 1,252,341 bytes, SHA-256 fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac) | verified |
| C2 | Three parameter sets: ML-KEM-512 (category 1), ML-KEM-768 (category 3), ML-KEM-1024 (category 5) | [FAKTA] | `docs/SOURCES.md §1` (§3.2, Table 2); `scripts/spec_fidelity.py` → `outputs/spec_fidelity.log`, all three set headers present | verified |
| C3 | Sizes: ek 800 / 1,184 / 1,568 B; dk 1,632 / 2,400 / 3,168 B; ct 768 / 1,088 / 1,568 B; ss 32 B; n = 256, q = 3329; ML-KEM-768 is NIST's recommended default | [FAKTA] | `docs/SOURCES.md §1` (§8, Tables 2–3); `outputs/spec_fidelity.log`: `100 vectors` per set, ciphertext lengths exercised in `outputs/tail_mutation.log` (`ct 768 bytes`, `ct 1088 bytes`, `ct 1568 bytes`) | verified |
| C4 | K-PKE is IND-CPA-only and "shall not be used as a stand-alone scheme"; IND-CCA2 comes only from the FO transform | [FAKTA] | `docs/SOURCES.md §1` (§3.2, verbatim quote) | verified |
| C5 | H(s) := SHA3-256(s); J(s) := SHAKE256(s, 256 bits); G(s) := SHA3-512(s), split into two 32-byte outputs (K, r) | [FAKTA] | `docs/SOURCES.md §1` (§4.1, eq. 4.4–4.5); implemented in `scripts/mlkem.py` | verified |
| C6 | Algorithm 16: dk = dkPKE ‖ ek ‖ H(ek) ‖ z, z a random 32-byte value used in the implicit-rejection mechanism of Algorithm 18 | [FAKTA] | `docs/SOURCES.md §1` (§6.1); `outputs/spec_fidelity.log`: `PASS ACCEPT-512 -- 100/100 decaps == ss` (and 768/1024) | verified |
| C7 | Algorithm 18, standard's step numbers: step 5 m′ ← K-PKE.Decrypt; step 6 (K′, r′) ← G(m′ ‖ h); step 7 K̄ ← J(z ‖ c); step 8 c′ ← K-PKE.Encrypt; steps 9–10 if c ≠ c′ then K′ ← K̄; step 12 return K′; no randomness | [FAKTA] | `docs/SOURCES.md §1` (§6.3, pp. 33–34); `scripts/spec_fidelity.py` → `outputs/spec_fidelity.log`: `PASS REJECT-512 -- 200/200 mutated decaps == J(z\|\|c') exactly, != ss` (and 768/1024) | verified |
| C8 | The accept/reject flag is secret data: "shall be destroyed prior to ML-KEM.Decaps_internal terminating"; "returning the value of the flag as an output in any form is not permitted" | [FAKTA] | `docs/SOURCES.md §1` (§6.3, p. 33, verbatim); `outputs/caller_misuse.log`: `PASS MISUSE-LOGS -- log lines leak ACCEPT/REJECT per chosen ciphertext` | verified |
| C9 | "The key establishment procedure of ML-KEM will never explicitly fail"; genuine failure rates 2^-138.8 (512), 2^-164.8 (768), 2^-174.8 (1024) | [FAKTA] | `docs/SOURCES.md §1` (§3.2, Table 1, verbatim) | verified |
| C10 | §3.3: internal functions test-only; "shall not use floating-point arithmetic"; intermediate values destroyed as soon as no longer needed | [FAKTA] | `docs/SOURCES.md §1` (§3.3) | verified |
| C11 | §7.2 modulus check test ← ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k]; "ML-KEM.Encaps shall not be run with an encapsulation key that has not been checked" | [FAKTA] | `docs/SOURCES.md §1` (§7.2); `outputs/input_checks.log`: `PASS EK-MODULUS-512 -- 3/3 unreduced eks refused (coeff values (3329, 3330, 4095))` (and 768/1024) | verified |
| C12 | §7.3: ciphertext length check "with every execution", dk length check, hash check test ← H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64]; "ML-KEM.Decaps shall not be run with a decapsulation key or a ciphertext unless both have been checked" | [FAKTA] | `docs/SOURCES.md §1` (§7.3); `outputs/input_checks.log`: `PASS CT-LENGTH-512 -- 4/4 wrong-length ciphertexts refused (lengths (0, 32, 767, 769))` (and 768/1024); `PASS DK-HASH-TAMPER-512` (and 768/1024) | verified |
| C13 | Errata spreadsheet lists exactly two issues, neither touching Alg 18 / §6.3 / FO / any parameter, key size, or test vector; header: corrections "DO NOT introduce new technical requirements" | [FAKTA] | `docs/SOURCES.md §2` (file 23,849 bytes, SHA-256 edf899c89762449f43d7713883caeefc2e4ae9ae98d5a76b339547db22cb3ac7; issues identified 2025-03-31 App. A and 2025-10-17 §5.3) | verified |

## B — Implicit vs. explicit rejection

| # | Claim | Label | Evidence | Status |
|---|---|---|---|---|
| C14 | Explicit rejection returns ⊥; implicit rejection returns a 32-byte pseudorandom K̄ with output shape identical to success | [FAKTA] | `docs/SOURCES.md §1` (§6.3), `§3`; `outputs/spec_fidelity.log`: reject path returns exact J(z‖c′) values | verified |
| C15 | Hövelmanns & Kudinov, ePrint 2025/062, received 15 January 2025 (not 14 January); PQCrypto 2025, LNCS vol. 15578, pp. 325–350, first online 15 March 2025, DOI 10.1007/978-3-031-86602-9_12 | [FAKTA] | `docs/SOURCES.md §3` (ePrint metadata: received 2025-01-15, approved 2025-01-16) | verified |
| C16 | Explicit rejection not less secure than implicit in the classical ROM "up to a rare edge case", lifted to the quantum setting via eQROM, with an alternative indirect proof avoiding the eQROM; prior work proved only the opposite direction | [FAKTA] | `docs/SOURCES.md §3` (ePrint abstract) | verified |
| C17 | "Implicit rejection introduces complexity and can easily deteriorate into explicit rejection in practice" | [FAKTA] | `docs/SOURCES.md §3` (abstract, verbatim); `outputs/caller_misuse.log` (logging route) and `outputs/timing.log` (timing route) test the two deterioration routes | verified |
| C18 | The two modes are near-equivalent as abstract designs; the choice is engineering (API shape, diagnosability, caller obligations), not a security hierarchy | [ANALISIS] | Follows from C15–C17; no separate measurement | verified (as analysis) |

## C — Known failure cases

| # | Claim | Label | Evidence | Status |
|---|---|---|---|---|
| C19 | wolfSSL 5.7.0–5.9.1 (NEON 5.7.4–5.9.1): AVX2 compared 1,536 of 1,568 bytes; NEON left 784 of 1,568 unchecked (CVE-2026-10097, CVSS 4.0 8.3, CWE-697; CVE-2026-6330); patched in 5.9.2, 23 June 2026 | [FAKTA] | `docs/SOURCES.md §4` (CVE records + postquantum.com write-up, 15 Aug 2026) | verified |
| C20 | Das: 98.0% of 2,048 coefficients from 400 chosen ciphertexts (AVX2); 98.5% from 600 (NEON); full recovery ~1,300 ciphertexts; total budget 10^5–10^6 decapsulation queries per key | [FAKTA] | `docs/SOURCES.md §4` (figures via the corroborating write-up, not the paper PDF — see NV1) | verified (via stated secondary source) |
| C21 | Attack needs a static key + plaintext-checking oracle; ephemeral hybrid TLS 1.3 is not vulnerable to key recovery (distinguishing break only) | [FAKTA] | `docs/SOURCES.md §4`; `outputs/key_mismatch.log`: `PASS CCA-NO-PC-ORACLE -- bare decaps API does not supply the plaintext-checking oracle` | verified |
| C22 | KyberSlash: divisions by q = 3329 on secret-derived values leak timing; keys recovered within minutes (KyberSlash2) / a few hours (KyberSlash1); reference patched 1 Dec 2023 and 30 Dec 2023 | [FAKTA] | `docs/SOURCES.md §5` (TCHES 2025, Vol. 2, pp. 209–234; commit history dda29cc6/bc8e6407, 272125f6/11d00ff1) | verified |
| C23 | RUSTSEC-2026-0585 (20 Nov 2026): pqcrypto-mlkem performs neither §7.2 nor §7.3 check; 108 / 112 / 116 invalid eks and 2 invalid dks per set accepted; no key disclosure; unmaintained, no patch expected | [FAKTA] | `docs/SOURCES.md §6` (advisory, 2026-11-20T12:00:00Z); `outputs/input_checks.log` header restates the baseline as reported, not measured | verified |
| C24 | liboqs 0.16.0 DOES both checks + full FO compare: `mlk_kem_check_pk` (kem.c 43–74), `mlk_kem_check_sk` (76–115, called line 396), line 422 full-length `mlk_ct_memcmp`, line 431 `mlk_ct_cmov_zero` | [FAKTA] | `docs/SOURCES.md §10` (tag commit 5a1a854b0dc9f2141bdc771c555ee60c37950183, released 9 Jul 2026; kem.c 446 lines) | verified |
| C25 | PQClean does NEITHER input check (full read of `crypto_kem/ml-kem-1024/clean/kem.c`, 164 lines); its FO comparison is full-length (line 155) and constant-time | [FAKTA] | `docs/SOURCES.md §11` (commit 0586a824fc0d49df0b6b6e9179d8d15d06d0974f; verify.c lines 17–27, 41–52) | verified |
| C26 | RatioLabs "liboqs performs neither check" is specific to liboqs 0.12.0; liboqs and PQClean must not be presented as equivalent on input checks | [FAKTA] | `docs/SOURCES.md §6` + `§10` (C24 vs C25) | verified |
| C27 | Shao et al.: H(c) omission re-enables Huffman-bound key-mismatch attacks, incl. a profiling-free plaintext-checking-oracle variant; stealthy construction evades all six detectors, "practically indistinguishable from legitimate ML-KEM traffic" | [FAKTA] | `docs/SOURCES.md §7` (ESORICS 2026, LNCS vol. 16969, pp. 341–362, first online 27 Sep 2026; Springer abstract) | verified |
| C28 | Clang reintroduced a secret-dependent branch in `poly_frommsg` (Purnal, 2024): source constant-time, binary not | [FAKTA] | `docs/SOURCES.md §13` (pqc-forum report, summarised in the postquantum.com wolfSSL analysis, 15 Aug 2026) | verified |
| C29 | Glabush et al.: re-encryption check "essential for security, but not for functionality"; omission "will go unnoticed"; HQC flaw unnoticed 19 months; modified FO binds re-encryption to functionality "with negligible overhead" | [FAKTA] | `docs/SOURCES.md §8` (ePrint 2025/450; CRYPTO 2025, LNCS vol. 16002, pp. 543–574); `outputs/missing_fo_check.log`: `PASS CONTROL-AGREE -- correctness tests cannot distinguish the two implementations` | verified |
| C30 | Callers that skip key confirmation, log outcomes, or retry convert silent rejection into vulnerability or silent outage | [ANALISIS] | `outputs/caller_misuse.log`: `PASS MISUSE-NO-KCF`, `PASS MISUSE-LOGS`, `PASS MISUSE-RETRY` (all three transcripts) | verified (as analysis) |

## D — What this pack measured

| # | Claim | Label | Evidence | Status |
|---|---|---|---|---|
| C31 | Spec fidelity: 100 vectors/set; accept 100/100 == ss; reject 200/200 == J(z‖c′) exactly; liboqs kat_kem stdout hashes match (single + all, all three sets) | [FAKTA] | `scripts/spec_fidelity.py` → `outputs/spec_fidelity.log`: `PASS KAT-COUNT-512 -- 100 vectors`, `PASS ACCEPT-512 -- 100/100 decaps == ss`, `PASS REJECT-512 -- 200/200 mutated decaps == J(z\|\|c') exactly, != ss` (and 768/1024); `PASS LIBOQS-SINGLE-512 -- sha256=c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782`, `PASS LIBOQS-ALL-512 -- sha256=74b470e797cbdbd589a31d387d36c72aad5033446ab5159bf4014c24652b1173` (and 768/1024 equivalents in the log); `SPEC_FIDELITY VERDICT: PASS` | verified |
| C32 | Tail sweep: 3,424 positions (768 + 1,088 + 1,568), 0 acceptances; final-32-bytes 32/32 rejected per set | [FAKTA] | `scripts/tail_mutation.py` → `outputs/tail_mutation.log`: `PASS TAIL-512 -- 768/768 mutations rejected with exact Kbar`, `PASS TAIL32-512 -- final 32 bytes: 32/32 rejected` (and 768/1024); `TAIL_MUTATION VERDICT: PASS -- 3424 positions tested, 0 acceptances` | verified |
| C33 | Input battery: 3/3 unreduced eks refused per set; 4/4 wrong-length cts refused per set; tampered-ek / tampered-hash dks refused per set; z-tamper invisible to §7.3 | [FAKTA] | `scripts/input_checks.py` → `outputs/input_checks.log`: `PASS EK-MODULUS-768 -- 3/3 unreduced eks refused (coeff values (3329, 3330, 4095))`, `PASS CT-LENGTH-768 -- 4/4 wrong-length ciphertexts refused (lengths (0, 32, 1087, 1089))`, `PASS DK-EK-TAMPER-768`, `PASS DK-HASH-TAMPER-768`, `PASS DK-Z-TAMPER-768 -- z tampering is invisible to 7.3 and only moves Kbar` (and 512/1024); `INPUT_CHECKS VERDICT: PASS` | verified |
| C34 | Timing indistinguishable within 5% at N=1000/path/set; committed gaps +1.0755% / −1.4641% / −0.9105%; 95% CIs all include zero | [FAKTA] | `scripts/timing.py` → `outputs/timing.log`: `PASS TIMING-GAP-512 -- relative gap 1.0755%`, `PASS TIMING-GAP-768 -- relative gap -1.4641%`, `PASS TIMING-GAP-1024 -- relative gap -0.9105%`; `95% CI [-81.07, 255.25] us` / `[-372.94, 24.91] us` / `[-526.14, 213.81] us`; `TIMING VERDICT: PASS` | verified |
| C35 | Key-mismatch probe: 16/16 coefficients at 2.2500 queries/coefficient (36 queries; 1.1080 queries/bit vs 2.0306-bit Huffman bound); 8/8 crafted ciphertexts return exactly K̄ from full decaps | [FAKTA] | `scripts/key_mismatch.py` → `outputs/key_mismatch.log`: `PASS RECOVER-16 -- 16/16 coefficients`, `PASS QUERIES-BOUND -- 2.2500 queries/coefficient (Huffman bound 2.0306 bits)`, `PASS CCA-NO-PC-ORACLE -- bare decaps API does not supply the plaintext-checking oracle`; `KEY_MISMATCH VERDICT: PASS` | verified |
| C36 | Full-key extrapolation ≈ 1,728 queries for a full static key (768 coefficients × 2.2500), before lattice post-processing | [ESTIMASI] | `outputs/key_mismatch.log`: `[ESTIMASI] full-key extrapolation: 768 secret coefficients (k*n = 768) at 2.2500 queries/coefficient ~= 1728 queries for a full static key, before lattice post-processing` | verified (as estimate) |
| C37 | Caller misuse: (i) K̄ as session key ≠ peer key, deterministic; (ii) logs leak ACCEPT/REJECT per chosen ciphertext; (iii) 3 retries return identical K̄, fresh encaps succeeds | [FAKTA] | `scripts/caller_misuse.py` → `outputs/caller_misuse.log`: `PASS MISUSE-NO-KCF -- Kbar used as session key, != peer K, deterministic across runs`, `PASS MISUSE-LOGS -- log lines leak ACCEPT/REJECT per chosen ciphertext`, `PASS MISUSE-RETRY -- 3 retries return identical Kbar; fresh encaps succeeds`; `CALLER_MISUSE VERDICT: PASS` | verified |
| C38 | Missing-FO detector: control agrees; 3 adversarial ciphertexts (c1 bytes 0, 2, 3 flipped); 3/3 separate correct (K̄) from neutered (genuine K) | [FAKTA] | `scripts/missing_fo_check.py` → `outputs/missing_fo_check.log`: `PASS CONTROL-AGREE`, `PASS ADVERSARIAL-FOUND -- 3 ciphertexts decrypt to the chosen message but fail re-encryption`, `PASS DETECTOR-DISTINGUISHES -- 3/3 adversarial ciphertexts separate correct from neutered`; `MISSING_FO_CHECK VERDICT: PASS` | verified |
| C39 | KAT provenance: pq-crystals/kyber `standard` @ d5b791c0c601b543233daccbae2845c6197a9e77 (21 Aug 2024), 100 vectors/set; vendored `.rsp` hashes match; pqcrypto interop cross-check (build-time only) | [FAKTA] | `docs/SOURCES.md §14` (rsp SHA-256: 512 `a30184edee53b3b009356e1e31d7f9e93ce82550e3c622d7192e387b0cc84f2e`, 768 `729367b590637f4a93c68d5e4a4d2e2b4454842a52c9eec503e3a0d24cb66471`, 1024 `3fba7327d0320cb6134badf2a1bcb963a5b3c0026c7dece8f00d6a6155e47b33`); liboqs `kats.json` commit b6689666b934f56773d43dfdcb14e42d898d7dec (17 Jun 2026) | verified |

## E — Ledger integration (forward-looking)

| # | Claim | Label | Evidence | Status |
|---|---|---|---|---|
| C40 | postfiatd tree (HEAD 24c5487d9bfc99171380960e4eeb1543a724cfae) has no ML-KEM: 0 matches for `ml-kem\|mlkem\|kyber`, 0 whole-word `kem` | [FAKTA] | `docs/SOURCES.md §12` (local grep, 21 Nov 2026) | verified |
| C41 | OpenSSL is floor-only: `find_package(OpenSSL 1.1.1 REQUIRED)`, no maximum, no pinned version; no conanfile/vcpkg manifest; no submodules | [FAKTA] | `docs/SOURCES.md §12` (`CMakeLists.txt:88`, `cmake/RippleConfig.cmake:48`; `git submodule status` empty) | verified |
| C42 | OpenSSL 3.5.0 (8 Apr 2025) added native ML-KEM; pre-3.5 has none; system OpenSSL here is 3.0.13 | [FAKTA] | `docs/SOURCES.md §12` | verified |
| C43 | TLS context leaves TLS 1.3 groups at OpenSSL defaults (only SSLv2/SSLv3/TLS 1.0/TLS 1.1 disabled; only a TLS 1.2 cipher list set; no TLS 1.3 group/ciphersuite call anywhere in `src/`) | [FAKTA] | `docs/SOURCES.md §12` (`make_SSLContext.cpp:349–365`; zero matches for `SSL_CTX_set1_groups` / `SSL_CTX_set_ciphersuites` / `SSL_CTX_set1_curves`) | verified |
| C44 | "No ML-KEM in source; ML-KEM reachable via default TLS 1.3 groups on OpenSSL ≥ 3.5 builds" — exposure is a function of the build's OpenSSL version, not of postfiatd's source | [ANALISIS] | Follows from C40–C43 | verified (as analysis) |
| C45 | RFC 9954 (Jul 2026) framework; RFC 10024 (Aug 2026): X25519MLKEM768 0x11EC Recommended Y (0x11EB / 0x11ED Recommended N); hybrid secret = ML-KEM secret ‖ X25519 secret | [FAKTA] | `docs/SOURCES.md §9` (RFC 10024 §4.3) | verified |
| C46 | Finished-fingerprint binding (overlay README lines 312–332) is the key-confirmation layer a hybrid handshake must preserve | [FAKTA] | `docs/SOURCES.md §12` (local source read) | verified |
| C47 | Ephemeral hybrid keys per session are not exposed to cumulative key-mismatch leakage; static keys are — long-term keys must never double as ML-KEM decapsulation keys | [ANALISIS] | C21, C27, C35–C36 | verified (as analysis) |
| C48 | Rotation/monitoring checklist: per-build tail sweep; per-upgrade input battery; shipped-binary timing measurement; rejection-rate alerting (honest failures ~2^-165); no accept/reject logging; key confirmation before any use of a decapsulated key | [ANALISIS] | C9 (failure rates), C32–C34, C37; checks are the scripts named in the claim | verified (as analysis) |

## NOT VERIFIED

| # | Claim | Label | Evidence / reason | Status |
|---|---|---|---|---|
| NV1 | "The Das paper (ePrint 2026/1682) was read directly"; any figure attributed to the paper PDF itself | [FAKTA] | ePrint paper page returned HTTP 403 on 21 Nov 2026, not retried. Figures rest on the postquantum.com write-up (15 Aug 2026), CVE records, and the ePrint 2026 listing mirror (`docs/SOURCES.md §4`). | not verified |
| NV2 | "RFC 9954 is the successor to draft-ietf-tls-hybrid-design-14 (expired 22 Jan 2026)" | [FAKTA] | Not checked in this pass. RFC dates/titles/code points verified (C45); the draft-successor detail is not. | not verified |
| NV3 | Any claim resting on the mlkemcipher.com write-up (e.g. "systematic bug surfaces only as interop failure two layers up") | [FAKTA] | Date and contents not independently verified in this pass. Used only as analysis framing, never as a sourced fact. | not verified |
| NV4 | Any claim about liboqs CUDA decapsulation paths (cupqc, icicle) | [FAKTA] | Not inspected. liboqs claims cover x86_64 / AArch64 / portable-C only (`docs/SOURCES.md §10`). | not verified |
| NV5 | Any claim about the PQClean `aarch64` ML-KEM variant | [FAKTA] | Not line-checked. PQClean claims cover the `clean` implementation only (`docs/SOURCES.md §11`). | not verified |
| NV6 | Any claim that a postfiatd system dependency's upstream source contains no ML-KEM code | [FAKTA] | Manifest-level check only; upstream sources not individually audited (`docs/SOURCES.md §12`). | not verified |

## Coverage note

- C1–C13 cover the mechanism; C14–C18 the implicit/explicit comparison;
  C19–C30 the failure cases; C31–C39 what this pack measured; C40–C48
  the forward-looking ledger integration. NV1–NV6 are the complete list
  of items that could not be verified; no other substantive claim in
  `docs/assessment-report.md` rests on an unverified source.
- Count: 48 verified claims (C1–C48) + 6 not-verified items (NV1–NV6).
