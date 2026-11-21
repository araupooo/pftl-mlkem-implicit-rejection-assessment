# Claims Index — ML-KEM Implicit-Rejection Assessment

Every substantive claim in the assessment, mapped to the runnable check
that tests it, the unedited log that records the result, and the pinned
primary source. Labels: [FAKTA] verified with source + date, [ESTIMASI]
modelled/reported number, [ANALISIS] interpretation.

Evidence pointers: `scripts/<name>.py` + `outputs/<name>.log` for measured
claims; `docs/SOURCES.md §<n>` for sourced claims. Full source pins live
in `docs/SOURCES.md`; the assessment narrative is
`docs/assessment-report.md`. Claims resting on items that could not be
verified are listed separately as NV1–NV6 at the end and are never
presented as verified.

## A — FIPS 203 mechanism (Algorithm 18, §6.3, §7.2/§7.3)

| # | Claim | Label | Check | Pinned source |
|---|---|---|---|---|
| C1 | FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard", was published 13 August 2024 (DOI 10.6028/NIST.FIPS.203) | [FAKTA] | — | `docs/SOURCES.md §1` |
| C2 | ML-KEM has three parameter sets: ML-KEM-512 (category 1), ML-KEM-768 (category 3), ML-KEM-1024 (category 5) | [FAKTA] | `spec_fidelity.py` (all 3 sets) | `docs/SOURCES.md §1` (§3.2, Table 2) |
| C3 | Sizes: encapsulation key 800 / 1,184 / 1,568 B; decapsulation key 1,632 / 2,400 / 3,168 B; ciphertext 768 / 1,088 / 1,568 B; shared secret 32 B in all three; n = 256, q = 3329; ML-KEM-768 is NIST's recommended default | [FAKTA] | `spec_fidelity.py` (KAT sizes) | `docs/SOURCES.md §1` (§8, Tables 2–3) |
| C4 | K-PKE is IND-CPA-only: "not IND-CCA2-secure and shall not be used as a stand-alone scheme" — IND-CCA2 comes only from the FO transform | [FAKTA] | — | `docs/SOURCES.md §1` (§3.2) |
| C5 | Hash wrappers: H(s) := SHA3-256(s); J(s) := SHAKE256(s, 256 bits); G(s) := SHA3-512(s), split into two 32-byte outputs (K, r) | [FAKTA] | `mlkem.py` implements all three | `docs/SOURCES.md §1` (§4.1, eq. 4.4–4.5) |
| C6 | Key generation (Algorithm 16) builds dk = dkPKE ‖ ek ‖ H(ek) ‖ z, where z is a random 32-byte value used in the implicit-rejection mechanism of Algorithm 18 | [FAKTA] | `spec_fidelity.py` (KAT keypairs) | `docs/SOURCES.md §1` (§6.1) |
| C7 | Algorithm 18 (standard's own step numbers): step 5 m′ ← K-PKE.Decrypt(dkPKE, c); step 6 (K′, r′) ← G(m′ ‖ h); step 7 K̄ ← J(z ‖ c); step 8 c′ ← K-PKE.Encrypt(ekPKE, m′, r′); steps 9–10 if c ≠ c′ then K′ ← K̄; step 12 return K′; decapsulation uses no randomness | [FAKTA] | `spec_fidelity.py` (accept + reject paths byte-exact) | `docs/SOURCES.md §1` (§6.3, pp. 33–34) |
| C8 | The accept/reject flag is secret data: it "shall be destroyed prior to ML-KEM.Decaps_internal terminating" and "returning the value of the flag as an output in any form is not permitted" | [FAKTA] | `caller_misuse.py` scenario (ii) shows what breaking this leaks | `docs/SOURCES.md §1` (§6.3, p. 33) |
| C9 | "The key establishment procedure of ML-KEM will never explicitly fail"; genuine decapsulation-failure rates are 2^-138.8 (512), 2^-164.8 (768), 2^-174.8 (1024) | [FAKTA] | — | `docs/SOURCES.md §1` (§3.2, Table 1) |
| C10 | §3.3 obligations: internal (derandomized) functions "should not be made available to applications other than for testing purposes"; implementations "shall not use floating-point arithmetic"; intermediate values shall be destroyed as soon as no longer needed | [FAKTA] | — | `docs/SOURCES.md §1` (§3.3) |
| C11 | §7.2 modulus check: test ← ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k]; "ML-KEM.Encaps shall not be run with an encapsulation key that has not been checked as above" | [FAKTA] | `input_checks.py` EK-MODULUS checks | `docs/SOURCES.md §1` (§7.2) |
| C12 | §7.3 checks: ciphertext length check "shall be performed with every execution of ML-KEM.Decaps", decapsulation-key length check, and hash check test ← H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64]; "ML-KEM.Decaps shall not be run with a decapsulation key or a ciphertext unless both have been checked" | [FAKTA] | `input_checks.py` CT-LENGTH / DK checks | `docs/SOURCES.md §1` (§7.3) |
| C13 | The FIPS 203 errata spreadsheet lists exactly two issues, neither touching Algorithm 18 / §6.3, the FO transform, or any parameter, key size, or test vector (App. A zeta-table clarification, 2025-03-31; §5.3 Alg 15 line 7 comment "polynomial v" → "polynomial w", 2025-10-17); its header states corrections "DO NOT introduce new technical requirements" | [FAKTA] | — | `docs/SOURCES.md §2` |

## B — Implicit vs. explicit rejection

| # | Claim | Label | Check | Pinned source |
|---|---|---|---|---|
| C14 | Explicit rejection returns a failure symbol ⊥; implicit rejection returns a pseudorandom key K̄ = J(z ‖ c) with output shape identical to success | [FAKTA] | `spec_fidelity.py` (reject path returns 32-byte K̄) | `docs/SOURCES.md §1` (§6.3); `§3` |
| C15 | Hövelmanns & Kudinov, ePrint 2025/062, received 15 January 2025 (not 14 January); PQCrypto 2025, Springer LNCS vol. 15578, pp. 325–350, first online 15 March 2025 | [FAKTA] | — | `docs/SOURCES.md §3` |
| C16 | Explicit rejection is not less secure than implicit rejection in the classical random-oracle model "up to a rare edge case", lifted to the quantum setting via the extractable QROM (eQROM), with an alternative indirect proof avoiding the eQROM; prior work had proven only the opposite direction | [FAKTA] | — | `docs/SOURCES.md §3` |
| C17 | "Implicit rejection introduces complexity and can easily deteriorate into explicit rejection in practice" | [FAKTA] | `caller_misuse.py` + `timing.py` test the two deterioration routes (logging, timing) | `docs/SOURCES.md §3` (abstract) |
| C18 | The two modes are near-equivalent as abstract designs, so the choice between them is an engineering decision (API shape, diagnosability, caller obligations), not a security hierarchy | [ANALISIS] | — | C15–C17 |

## C — Known failure cases

| # | Claim | Label | Check | Pinned source |
|---|---|---|---|---|
| C19 | wolfSSL 5.7.0–5.9.1 (NEON path 5.7.4–5.9.1): AVX2 `mlkem_cmp_avx2` compared only 1,536 of 1,568 bytes of an ML-KEM-1024 ciphertext; ARM64 NEON used `ins` where `ext` was intended, leaving 784 of 1,568 bytes unchecked (CVE-2026-10097, CVSS 4.0 8.3, CWE-697; CVE-2026-6330); patched in wolfSSL 5.9.2, released 23 June 2026 | [FAKTA] | `tail_mutation.py` is the test this bug fails | `docs/SOURCES.md §4` |
| C20 | Das (ePrint 2026/1682, posted 15 Aug 2026): 98.0% of the 2,048 secret coefficients recovered with 400 chosen ciphertexts (AVX2) and 98.5% with 600 (NEON); full recovery of all 2,048 needed ~1,300 ciphertexts against a reference model, at a total budget of 10^5–10^6 decapsulation queries per key | [FAKTA] | — (reported figures, via the corroborating write-up; see NV1) | `docs/SOURCES.md §4` |
| C21 | The wolfSSL attack requires a static (reused) key and a plaintext-checking oracle; ephemeral hybrid TLS 1.3 handshakes (fresh key per session) are not vulnerable to key recovery — there the bug is only a distinguishing break | [FAKTA] | `key_mismatch.py` CCA-NO-PC-ORACLE check | `docs/SOURCES.md §4` |
| C22 | KyberSlash (Bernstein et al., disclosed Dec 2023; TCHES 2025, Vol. 2, pp. 209–234): divisions by q = 3329 on secret-derived values take data-dependent time on some CPUs; keys reliably recovered within minutes (KyberSlash2) and a few hours (KyberSlash1); reference implementation patched 1 Dec 2023 (KyberSlash1) and 30 Dec 2023 (KyberSlash2) | [FAKTA] | `timing.py` measures the decapsulation timing surface | `docs/SOURCES.md §5` |
| C23 | RUSTSEC-2026-0585, published 20 Nov 2026: `pqcrypto-mlkem` (wrapping PQClean) performs neither the §7.2 modulus check nor the §7.3 hash check; 108 / 112 / 116 invalid encapsulation keys accepted (512 / 768 / 1024) and 2 invalid decapsulation keys per parameter set; no key material disclosed; crate unmaintained, no patched version expected | [FAKTA] | `input_checks.py` (this harness refuses all probed malformed inputs) | `docs/SOURCES.md §6` |
| C24 | Current liboqs 0.16.0 (tag commit 5a1a854b0dc9f2141bdc771c555ee60c37950183, released 9 Jul 2026) DOES both input checks and the full FO comparison: `mlk_kem_check_pk` (kem.c lines 43–74), `mlk_kem_check_sk` (lines 76–115, called from `mlk_kem_dec` line 396), line 422 `fail = mlk_ct_memcmp(ct, tmp, MLKEM_INDCCA_CIPHERTEXTBYTES)` over the full ciphertext length, rejection key via `mlk_hash_j`, line 431 `mlk_ct_cmov_zero` | [FAKTA] | `spec_fidelity.py` liboqs KAT cross-check | `docs/SOURCES.md §10` |
| C25 | PQClean (commit 0586a824fc0d49df0b6b6e9179d8d15d06d0974f) does NEITHER input check: a full read of `crypto_kem/ml-kem-1024/clean/kem.c` (164 lines) finds no §7.2 modulus check in encaps and no §7.3 hash check in decaps — while its FO comparison itself is full-length (line 155 `verify(ct, cmp, KYBER_CIPHERTEXTBYTES)`) and constant-time | [FAKTA] | `input_checks.py` (same gap, measured on the harness's checked wrappers as the conforming baseline) | `docs/SOURCES.md §11` |
| C26 | The RatioLabs finding that liboqs "performs neither check" is specific to liboqs 0.12.0 and must not be cited against current liboqs; liboqs and PQClean must not be presented as equivalent on input checks | [FAKTA] | — | `docs/SOURCES.md §6`, `§10` |
| C27 | Shao et al., ESORICS 2026 (LNCS vol. 16969, pp. 341–362, first online 27 Sep 2026): omitting H(c) from the shared-key derivation "unintentionally re-enables a class of highly efficient key-mismatch attacks" at the information-theoretic Huffman bound, including a profiling-free plaintext-checking-oracle variant; the stealthy composite-ciphertext construction evades all six detectors evaluated and "remains practically indistinguishable from legitimate ML-KEM traffic" | [FAKTA] | `key_mismatch.py` reproduces the baseline-comparison probe shape | `docs/SOURCES.md §7` |
| C28 | In 2024, PQShield's Antoon Purnal reported recent Clang versions recognised the reference implementation's `poly_frommsg` as a bit test and generated a secret-dependent branch absent from the source: the source was constant-time; the binary was not | [FAKTA] | `timing.py` (tests the compiled artefact's timing, not the source) | `docs/SOURCES.md §13` |
| C29 | Glabush, Günther, Hövelmanns & Stebila, ePrint 2025/450 (received 10 Mar 2025, revised 10 Jun 2025), CRYPTO 2025 (LNCS vol. 16002, pp. 543–574): the re-encryption check "is essential for security, but not for functionality. In other words, it will go unnoticed if this essential step is omitted or wrongly implemented, opening the door for key recovery attacks"; the flaw sat in HQC's reference implementation unnoticed for 19 months | [FAKTA] | `missing_fo_check.py` is the detector for this failure class | `docs/SOURCES.md §8` |
| C30 | A caller that uses the decapsulated key without key confirmation, logs decapsulation outcomes, or retries a rejected ciphertext converts silent rejection into a live vulnerability or a silent outage | [ANALISIS] | `caller_misuse.py` (all three transcripts) | C8, C29 |

## D — What this pack measured

| # | Claim | Label | Check | Pinned source |
|---|---|---|---|---|
| C31 | Spec fidelity: 100 KAT vectors per parameter set; accept path 100/100 decaps == ss and reject path 200/200 mutated decaps == J(z‖c′) exactly, for all three sets; recomputed kat_kem stdout hashes match liboqs `tests/KATs/kem/kats.json` (single + all, all three sets) | [FAKTA] | `spec_fidelity.py` → `outputs/spec_fidelity.log` | `docs/SOURCES.md §14` (KAT source) |
| C32 | Tail-mutation sweep: 3,424 byte positions tested (768 + 1,088 + 1,568), 0 acceptances; every mutation yields exactly J(z‖c′); final-32-bytes sub-sweep 32/32 rejected per set | [FAKTA] | `tail_mutation.py` → `outputs/tail_mutation.log` | C19–C20 (Das test) |
| C33 | Input-check battery: 3/3 unreduced encapsulation keys refused per set (coefficient values 3329, 3330, 4095); 4/4 wrong-length ciphertexts refused per set; decapsulation keys with tampered embedded ek or tampered stored H(ek) refused per set; z-tampering is invisible to the §7.3 check (hash passes, accept-path key unchanged, rejection key changed) | [FAKTA] | `input_checks.py` → `outputs/input_checks.log` | C11–C12, C23 |
| C34 | Timing: accept vs reject decapsulation indistinguishable within 5% at N=1000 per path per set; latest committed run relative gaps +1.0755% / −1.4641% / −0.9105% (512 / 768 / 1024), 95% CIs [−81.07, 255.25] / [−372.94, 24.91] / [−526.14, 213.81] µs, all including zero. The percentages vary run to run; the stable fact is the verdict (PASS within 5%) | [FAKTA] | `timing.py` → `outputs/timing.log` | C8, C22, C28 |
| C35 | Key-mismatch probe: 16/16 secret coefficients of s₀ recovered at 2.2500 queries/coefficient (36 queries; 1.1080 queries/bit vs a 2.0306-bit Huffman bound); 8/8 crafted ciphertexts return exactly K̄ = J(z‖c) from full decapsulation, so the bare decapsulation API does not supply the plaintext-checking oracle | [FAKTA] | `key_mismatch.py` → `outputs/key_mismatch.log` | C27 |
| C36 | Full-key extrapolation: 768 secret coefficients (k·n = 768) at 2.2500 queries/coefficient ≈ 1,728 queries for a full static key, before lattice post-processing | [ESTIMASI] | `key_mismatch.py` (measured rate × key size) | C35 |
| C37 | Caller-misuse transcripts: (i) a tampered ciphertext's K̄ used as a session key differs from the peer's key and is deterministic across runs; (ii) logging outcomes writes an accept/reject oracle to disk; (iii) 3 retries of a rejected ciphertext return the identical K̄ while a fresh encapsulation succeeds | [FAKTA] | `caller_misuse.py` → `outputs/caller_misuse.log` | C8, C30 |
| C38 | Missing-FO-check detector: a correctness-only test cannot distinguish the correct implementation from the neutered one (control agrees); 3 adversarial ciphertexts (c1 bytes 0, 2, 3 flipped) decrypt to the chosen message but fail re-encryption; 3/3 separate correct (returns K̄) from neutered (returns the genuine shared secret) | [FAKTA] | `missing_fo_check.py` → `outputs/missing_fo_check.log` | C29 |
| C39 | KAT provenance: vectors generated locally from the NIST reference implementation (pq-crystals/kyber, branch `standard`, commit d5b791c0c601b543233daccbae2845c6197a9e77, 21 Aug 2024), 100 vectors per set; vendored `.rsp` SHA-256 values match the committed files; second independent cross-check (build-time only): bidirectional encaps/decaps interop with pqcrypto `ml_kem_512/768/1024` for all three sets | [FAKTA] | `spec_fidelity.py` → `outputs/spec_fidelity.log` | `docs/SOURCES.md §14` |

## E — Ledger integration (forward-looking)

| # | Claim | Label | Check | Pinned source |
|---|---|---|---|---|
| C40 | The postfiatd source tree (HEAD 24c5487d9bfc99171380960e4eeb1543a724cfae) contains no ML-KEM: 0 matches for `ml-kem|mlkem|kyber` and 0 whole-word `kem` matches anywhere in the tree | [FAKTA] | Local grep, 21 Nov 2026 | `docs/SOURCES.md §12` |
| C41 | OpenSSL is a floor-only dependency: `find_package(OpenSSL 1.1.1 REQUIRED)` (`CMakeLists.txt:88`, `cmake/RippleConfig.cmake:48`), no maximum, no pinned version anywhere in-tree; no conanfile/vcpkg manifest; no git submodules | [FAKTA] | Local manifest read | `docs/SOURCES.md §12` |
| C42 | OpenSSL 3.5.0 (8 Apr 2025) added native ML-KEM (plus ML-DSA, SLH-DSA); pre-3.5 OpenSSL has no built-in ML-KEM; the system OpenSSL on this machine is 3.0.13, which predates ML-KEM support | [FAKTA] | — | `docs/SOURCES.md §12` |
| C43 | postfiatd's TLS context (`make_SSLContext.cpp:349–365`) disables only SSLv2/SSLv3/TLS 1.0/TLS 1.1 and sets only a TLS 1.2 cipher list; no call anywhere in `src/` sets TLS 1.3 groups or ciphersuites, so TLS 1.3 groups are OpenSSL defaults | [FAKTA] | Local source read | `docs/SOURCES.md §12` |
| C44 | Correct phrasing: "no ML-KEM in source; ML-KEM reachable via default TLS 1.3 groups on OpenSSL ≥ 3.5 builds" — a deployment's ML-KEM exposure is a function of the OpenSSL version it is built against, not of postfiatd's own source | [ANALISIS] | — | C40–C43 |
| C45 | RFC 9954 (Informational, Jul 2026) defines the hybrid key-exchange framework; RFC 10024 (Standards Track, Aug 2026) defines X25519MLKEM768 (code point 0x11EC, IANA Recommended Y; SecP256r1MLKEM768 0x11EB and SecP384r1MLKEM1024 0x11ED are Recommended N); for X25519MLKEM768 the hybrid shared secret is the ML-KEM secret concatenated with the X25519 secret, ML-KEM first | [FAKTA] | — | `docs/SOURCES.md §9` |
| C46 | postfiatd's peer-TLS session binding (`src/xrpld/overlay/README.md`, lines 312–332: the two endpoints extract the TLS `Finished` messages and combine them into a fingerprint) is the key-confirmation layer a hybrid handshake must preserve | [FAKTA] | Local source read | `docs/SOURCES.md §12` |
| C47 | Peer-TLS key policy: ephemeral hybrid keys per session are not exposed to cumulative key-mismatch leakage; static (reused) keys are — so long-term validator keys must never be reused as ML-KEM decapsulation keys, and any static-key deployment needs rotation limits | [ANALISIS] | `key_mismatch.py` (C35–C36) | C21, C27 |
| C48 | Rotation/monitoring checklist derived from the cases: tail-mutation sweep on every build; input-check battery on every dependency upgrade; timing measurement on the shipped binary; rejection-rate monitoring with an alert threshold (honest failures are ~2^-165, so any cluster is corruption, interference, or attack); no logging of accept/reject outcomes; key-confirmation before any use of a decapsulated key | [ANALISIS] | `tail_mutation.py`, `input_checks.py`, `timing.py`, `caller_misuse.py` | C9, C19–C29 |

## NOT VERIFIED — claims that must not be presented as verified

| # | Claim | Label | Status | Evidence / reason |
|---|---|---|---|---|
| NV1 | "The Das paper (ePrint 2026/1682) was read directly" — and any figure attributed to the paper PDF itself | [FAKTA] | NOT VERIFIED | The ePrint paper page returned HTTP 403 on 21 Nov 2026 and was not retried. Das figures in this pack rest on the postquantum.com write-up (15 Aug 2026), the CVE records, and the ePrint 2026 listing mirror — cite those, not a direct paper read. (`docs/SOURCES.md §4`) |
| NV2 | "RFC 9954 is the successor to draft-ietf-tls-hybrid-design-14 (expired 22 Jan 2026)" | [FAKTA] | NOT VERIFIED | Not checked in this pass. The RFC 9954/10024 dates, titles, and code points are verified (C45); the draft-successor detail is not. |
| NV3 | Any claim resting on the mlkemcipher.com write-up on implicit rejection (e.g. the "systematic bug surfaces only as interop failure two layers up" framing) | [FAKTA] | NOT VERIFIED | Date and contents not independently verified in this pass. Kept only as analysis where used, never as a sourced fact. |
| NV4 | Any claim about liboqs CUDA decapsulation paths (cupqc, icicle) | [FAKTA] | NOT VERIFIED | Not inspected. Claims about liboqs cover the x86_64 / AArch64 / portable-C paths only. (`docs/SOURCES.md §10`) |
| NV5 | Any claim about the PQClean `aarch64` ML-KEM variant | [FAKTA] | NOT VERIFIED | Not line-checked. Claims about PQClean cover the `clean` implementation only. (`docs/SOURCES.md §11`) |
| NV6 | Any claim that a postfiatd system dependency's upstream source contains no ML-KEM code | [FAKTA] | NOT VERIFIED | System dependencies (gRPC, RocksDB, etc.) were checked at manifest level only; upstream sources were not individually audited. (`docs/SOURCES.md §12`) |
