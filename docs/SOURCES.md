# Sources — ML-KEM Implicit-Rejection Assessment

- [FAKTA] Access date for all web sources below: 21 November 2026.
- [FAKTA] Every substantive claim in the assessment pack that rests on a source below carries its section, page, or line reference here, so the claim can be re-checked without re-doing the search.
- Scope note: this file is technical-only. It lists primary sources and access notes only.

## 1. NIST FIPS 203, ML-KEM standard

- [FAKTA] Full citation: National Institute of Standards and Technology, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, FIPS 203, DOI 10.6028/NIST.FIPS.203.
- [FAKTA] Publication date: 13 August 2024 (title page: "Published August 13, 2024"; PDF metadata ModDate 22 Aug 2024, "[8/22/24 minor corrections]" in the subject line).
- [FAKTA] URLs: PDF https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf (1,252,341 bytes, SHA-256 fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac, 56 pages, read directly 21 Nov 2026); CSRC record https://csrc.nist.gov/pubs/fips/203/final.
- [FAKTA] Parameter sets (§3.2, Table 2 §8): ML-KEM-512 / -768 / -1024; n = 256, q = 3329 in all sets; k = 2 / 3 / 4; du = 10 / 10 / 11; dv = 4 / 4 / 5.
- [FAKTA] Sizes (§8, Table 3): encapsulation key 800 / 1,184 / 1,568 B; decapsulation key 1,632 / 2,400 / 3,168 B; ciphertext 768 / 1,088 / 1,568 B; shared secret 32 B in all three.
- [FAKTA] "NIST recommends using ML-KEM-768 as the default parameter set" (§8, text following Table 3).
- [FAKTA] Hash wrappers (§4.1, eq. 4.4–4.5): H(s) := SHA3-256(s); J(s) := SHAKE256(s, 256 bits); G(s) := SHA3-512(s), split into two 32-byte outputs (K, r).
- [FAKTA] Key generation (Algorithm 16, §6.1): dk = dkPKE ‖ ek ‖ H(ek) ‖ z, where z is a random 32-byte value used in the implicit-rejection mechanism of Algorithm 18.
- [FAKTA] Internal decapsulation (Algorithm 18, §6.3, pp. 33–34): step 1–4 parse dk into dkPKE, ekPKE, h, z = dk[768k+64 : 768k+96]; step 5 m′ ← K-PKE.Decrypt(dkPKE, c); step 6 (K′, r′) ← G(m′ ‖ h); step 7 K̄ ← J(z ‖ c); step 8 c′ ← K-PKE.Encrypt(ekPKE, m′, r′); steps 9–10 if c ≠ c′ then K′ ← K̄; step 12 return K′. No randomness is used.
- [FAKTA] Flag secrecy (§6.3, p. 33): the "implicit reject" flag computed in step 9 "shall be destroyed prior to ML-KEM.Decaps_internal terminating" and "returning the value of the flag as an output in any form is not permitted".
- [FAKTA] Decapsulation failures (§3.2, Table 1): "the key establishment procedure of ML-KEM will never explicitly fail"; failure rates 2^-138.8 (512), 2^-164.8 (768), 2^-174.8 (1024).
- [FAKTA] K-PKE (§3.2): "The scheme K-PKE is not IND-CCA2-secure and shall not be used as a stand-alone scheme."
- [FAKTA] Implementation obligations (§3.3): internal functions "should not be made available to applications other than for testing purposes"; "No floating-point arithmetic. Implementations of ML-KEM shall not use floating-point arithmetic"; intermediate values shall be destroyed as soon as no longer needed.
- [FAKTA] Input checks (§7.2, §7.3, pp. 36–37): §7.2 modulus check test ← ByteEncode12(ByteDecode12(ek[0:384k])), "ML-KEM.Encaps shall not be run with an encapsulation key that has not been checked as above"; §7.3 hash check test ← H(dk[384k : 768k+32]) compared against dk[768k+32 : 768k+64], "ML-KEM.Decaps shall not be run with a decapsulation key or a ciphertext unless both have been checked"; ciphertext checking "shall be performed with every execution of ML-KEM.Decaps".
- Verbatim (short, public-domain US government work):
  - "In either case, decapsulation outputs the resulting shared secret key K′."

## 2. NIST FIPS 203 errata spreadsheet ("Potential Updates")

- [FAKTA] Full citation: NIST, *FIPS 203 Potential Updates (Errata)*, spreadsheet linked as "Errata (potential updates)" under Documentation on https://csrc.nist.gov/pubs/fips/203/final.
- [FAKTA] File retrieved 21 Nov 2026 by direct download: https://csrc.nist.gov/files/pubs/fips/203/final/docs/fips-203-potential-updates.xlsx (23,849 bytes, SHA-256 edf899c89762449f43d7713883caeefc2e4ae9ae98d5a76b339547db22cb3ac7; one worksheet, "Sheet1", 45 rows; document properties last modified 2025-11-17T13:47:51Z, matching the CSRC Planning Note date 11/17/2025).
- [FAKTA] The spreadsheet lists exactly two issues, neither of which touches the decapsulation algorithm (Algorithm 18 / §6.3), the FO transform, or any parameter, key size, or test vector:
  1. [FAKTA] Identified 2025-03-31, location "Appendix A": "Algorithms 9 and 10 use the zeta values for i = 1, …, 127, however Appendix A also includes the value 1 (corresponding to i = 0)." Potential correction: add the sentence "The value 1, corresponding to i = 0, has been included so that i-th entry of the array would then equal ζ^BitRev_7(i)."
  2. [FAKTA] Identified 2025-10-17, location "Section 5.3": "In Algorithm 15, line 7, the comment reads 'decode plaintext m from polynomial v.' However, v is not used in the algorithm." Potential correction: the comment will read "decode plaintext m from polynomial w."
- [FAKTA] Header disclaimer in the spreadsheet: "Potential corrections DO NOT introduce new technical requirements" and "Potential corrections ARE NOT official changes, but may be corrected in a future errata update of the publication."
- [ANALISIS] Consequence for the assessment: the November 2025 Planning Note does not signal any pending change to implicit rejection, decapsulation, or the FO check; the two pending corrections are a zeta-table clarification and a one-word comment fix.

## 3. Hövelmanns & Kudinov — explicit vs. implicit rejection

- [FAKTA] Full citation: Kathrin Hövelmanns and Mikhail Kudinov, "Treating Dishonest Ciphertexts in Post-quantum KEMs — Explicit vs. Implicit Rejection in the FO Transform", Cryptology ePrint Archive, Paper 2025/062 (received 15 January 2025; approved 16 January 2025); PQCrypto 2025, Springer LNCS vol. 15578, pp. 325–350, first online 15 March 2025, DOI 10.1007/978-3-031-86602-9_12.
- [FAKTA] URLs: https://eprint.iacr.org/2025/062 ; https://doi.org/10.1007/978-3-031-86602-9_12.
- [FAKTA] Result: in the classical random-oracle model, explicit rejection is not less secure than implicit rejection "up to a rare edge case"; the proof is lifted to the quantum setting via the extractable QROM (eQROM), with an alternative indirect proof avoiding the eQROM. Prior work had proven only the opposite direction (implicit not less secure than explicit).
- [FAKTA] Context sentence from the abstract: during NIST standardisation, designers chose implicit rejection, "likely due to the availability of security proofs against quantum attackers".
- Verbatim (short, from the ePrint abstract):
  - "implicit rejection introduces complexity and can easily deteriorate into explicit rejection in practice."

## 4. Das — incomplete ciphertext comparison in ML-KEM (wolfSSL)

- [FAKTA] Full citation: Bhabani Sankar Das, "Incomplete Ciphertext Comparison in ML-KEM: From an IND-CCA2 Break to Key Recovery", Cryptology ePrint Archive, Paper 2026/1682 (posted 15 August 2026). Attack code: https://github.com/007bsd/ml-kem-key-recovery.
- [FAKTA] URLs: https://eprint.iacr.org/2026/1682 (the ePrint paper page itself returned HTTP 403 to the fetcher used here on 21 Nov 2026 and was not read directly — see the notes below); ePrint 2026 listing mirror corroborating number, title, and author: https://eprint-classic.github.io/2026.html.
- [FAKTA] Corroborating secondary write-up (figures below are confirmed through it, not from the paper PDF itself): https://postquantum.com/security-pqc/wolfssl-mlkem-key-recovery-fo-check/ (15 Aug 2026).
- [FAKTA] The bugs: wolfSSL 5.7.0–5.9.1 (NEON path 5.7.4–5.9.1); AVX2 function `mlkem_cmp_avx2` compared only 1,536 of 1,568 bytes of an ML-KEM-1024 ciphertext, skipping the final 32 bytes (CVE-2026-10097, CVSS 4.0 8.3 High, CWE-697); ARM64 NEON path used `ins` where `ext` was intended, leaving 784 of 1,568 bytes unchecked (CVE-2026-6330). Patched in wolfSSL 5.9.2, released 23 June 2026. NEON bug independently reported by Nicholas Carlini (Anthropic); AVX2 bug by Das (@007bsd).
- [FAKTA] Recovery figures (per the write-up's summary of the paper): 98.0% of the 2,048 secret coefficients recovered with 400 chosen ciphertexts (AVX2, native x86-64) and 98.5% with 600 chosen ciphertexts (NEON, ARM64 under QEMU); full recovery of all 2,048 coefficients required approximately 1,300 ciphertexts against a verified Python reference model; total budget 10^5–10^6 decapsulation queries per key.
- [FAKTA] Scope limit (same write-up): the attack requires a static (reused) key and a plaintext-checking oracle; ephemeral hybrid TLS 1.3 handshakes (fresh key per session) are not vulnerable to key recovery — there the bug is only a distinguishing break. Static-key deployments at risk: HPKE static recipients, KEMTLS long-term keys, pinned/embedded keys in IoT devices.
- [FAKTA] CVE records: CVE-2026-10097 published 25 Jun 2026 (NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-10097); Debian tracker entries for CVE-2026-10097 and CVE-2026-6330: https://tracker.debian.org/pkg/wolfssl.
- Verbatim (short, from the postquantum.com write-up):
  - "The attack recovered 98.0% of the 2,048 secret coefficients using 400 chosen ciphertexts on AVX2."

## 5. KyberSlash — secret-dependent division timing

- [FAKTA] Full citation: Daniel J. Bernstein, Karthikeyan Bhargavan, Shivam Bhasin, Anupam Chattopadhyay, Tee Kiah Chia, Matthias J. Kannwischer, Franziskus Kiefer, Thales B. Paiva, Prasanna Ravi, Goutam Tamvada, "KyberSlash: Exploiting secret-dependent division timings in Kyber implementations", IACR Transactions on Cryptographic Hardware and Embedded Systems 2025, Vol. 2, pp. 209–234, DOI 10.46586/tches.v2025.i2.209-234; ePrint 2024/1049.
- [FAKTA] URLs: https://kyberslash.cr.yp.to/papers.html (history timeline); https://er.ceres.rub.de/index.php/TCHES/article/download/12046/11890/13899 (paper PDF); https://eprint.iacr.org/2024/1049.
- [FAKTA] Findings: divisions by q = 3329 on secret-derived values (notably `poly_tomsg` during decapsulation, KyberSlash1; `poly_compress` / `polyvec_compress`, KyberSlash2) take data-dependent time on some CPUs; keys reliably recovered within minutes (KyberSlash2) and a few hours (KyberSlash1) on Raspberry Pi 2 (Arm Cortex-A7) and Arm Cortex-M4.
- [FAKTA] Patch history (pq-crystals/kyber commit history, verified via GitHub API): KyberSlash1 fixed 1 Dec 2023 (commits dda29cc6, bc8e6407, "Updated poly_tomsg to prevent a compiler from using DIV"); KyberSlash2 fixed 30 Dec 2023 (commits 272125f6, 11d00ff1, "Removed '/KYBER_Q' in poly_compress and polyvec_compress"). The KyberSlash site's history page confirms the 1 Dec 2023 patch and the 30 Dec 2023 announcement of the KyberSlash2 divisions.
- [FAKTA] Contemporary status list (as of 2 Jan 2024, via BleepingComputer's report of the KyberSlash status list): liboqs `src/kem/kyber` was "patched only for KyberSlash1" at that date; PQClean `crypto_kem/kyber/clean` and `aarch64` were unpatched at that date. This is a January 2024 snapshot, not a statement about current code.
- Verbatim (short, from the paper abstract via kyberslash.cr.yp.to):
  - "Kyber secret keys are reliably recovered within minutes for KyberSlash2 and a few hours for KyberSlash1."

## 6. RUSTSEC-2026-0585 — missing FIPS 203 input checks

- [FAKTA] Full citation: RustSec Advisory RUSTSEC-2026-0585, "ML-KEM does not perform the FIPS 203 input checks", published 20 November 2026.
- [FAKTA] URLs: https://rustsec.org/advisories/RUSTSEC-2026-0585.html ; mirror https://vdb.ai.kr/vuln/RUSTSEC-2026-0585 (timestamp 2026-11-20T12:00:00Z).
- [FAKTA] Affected package: `pqcrypto-mlkem` (all versions ≥ 0.0.0-0), which wraps PQClean's ML-KEM implementation. Encapsulation does not perform the §7.2 encapsulation-key modulus check; decapsulation does not perform the §7.3 decapsulation-key hash check.
- [FAKTA] Measured counts (Wycheproof ML-KEM vectors): 108 / 112 / 116 invalid encapsulation keys accepted (ML-KEM-512 / -768 / -1024) and 2 invalid decapsulation keys accepted per parameter set.
- [FAKTA] The advisory states this does not disclose key material; it is a FIPS 203 non-conformance, and an affected implementation "can disagree with a conforming one about which keys are valid". The crate is unmaintained (see RUSTSEC-2026-0161) and no patched version is expected; migration to a maintained implementation (e.g. the `ml-kem` crate) is recommended.
- [FAKTA] Provenance: the advisory derives from RatioLabs' Wycheproof-vector testing of 13 major libraries plus 30 other implementations (https://medium.com/@ratiolabsEU/does-your-post-quantum-library-follow-the-standard-we-ran-the-public-test-vectors-98e3f4a31a9a, Nov 2026), which also reported that liboqs 0.12.0 performed neither check (same 108/112/116 counts). That liboqs finding is version-specific to 0.12.0; current liboqs 0.16.0 does perform both checks (see §10).
- Verbatim (short, from the advisory text):
  - "This does not disclose key material. It is a FIPS 203 non-conformance."

## 7. Shao et al. — Huffman-optimal key-mismatch attacks on ML-KEM

- [FAKTA] Full citation: Mingyao Shao, Yuejun Liu, Yongbin Zhou, Rui Zhang, Yanbin Pan, Zehua Qiao, Yan Shao, Xingyang Huang, "Closing the Gap: Huffman-Optimal and Stealthy Key-Mismatch Attacks on ML-KEM", Computer Security — ESORICS 2026, Springer LNCS vol. 16969, pp. 341–362, first online 27 September 2026, DOI 10.1007/978-3-032-38695-3_17.
- [FAKTA] URL: https://link.springer.com/chapter/10.1007/978-3-032-38695-3_17.
- [FAKTA] Finding (abstract): the omission of the ciphertext hash H(c) from the shared-key derivation — a change made in the transition from CRYSTALS-Kyber to finalised ML-KEM (FIPS 203), intended to streamline performance and facilitate crypto-agility — "unintentionally re-enables a class of highly efficient key-mismatch attacks (KMAs)" via a baseline-comparison technique, achieving the information-theoretic Huffman bound for query complexity, including a profiling-free plaintext-checking-oracle variant in the CCA-secure setting.
- [FAKTA] Stealth claim (abstract): the authors' composite-ciphertext construction "evades all six detectors they evaluate" (the abstract says "evades all considered detectors") and "remains practically indistinguishable from legitimate ML-KEM traffic".
- Verbatim (short, from the Springer abstract):
  - "the omission of the ciphertext hash H(c) from the shared-key derivation … unintentionally re-enables a class of highly efficient key-mismatch attacks."

## 8. Glabush, Günther, Hövelmanns & Stebila — verifiable decapsulation

- [FAKTA] Full citation: Lewis Glabush (EPFL), Felix Günther (IBM Research Europe — Zurich), Kathrin Hövelmanns (Eindhoven University of Technology), Douglas Stebila (University of Waterloo), "Verifiable Decapsulation: Recognizing Faulty Implementations of Post-Quantum KEMs", Cryptology ePrint Archive, Paper 2025/450 (received 10 March 2025; revised 10 June 2025); CRYPTO 2025, Springer LNCS vol. 16002, pp. 543–574, DOI 10.1007/978-3-032-01881-6_17.
- [FAKTA] URLs: https://eprint.iacr.org/2025/450 ; https://eprint.iacr.org/2025/450.pdf ; https://doi.org/10.1007/978-3-032-01881-6_17 ; IBM Research record https://research.ibm.com/publications/verifiable-decapsulation-recognizing-faulty-implementations-of-post-quantum-kems.
- [FAKTA] Finding (abstract): the re-encryption check in the FO transform "is essential for security, but not for functionality. In other words, it will go unnoticed if this essential step is omitted or wrongly implemented, opening the door for key recovery attacks." The flaw was present in HQC's reference implementation and was only noticed after 19 months. The authors' modified FO transform binds re-encryption to functionality via an unpredictable confirmation code, so a faulty implementation is exposed by basic correctness tests; applied to ML-KEM and HQC "with negligible overhead".
- Verbatim (short, from the abstract):
  - "it will go unnoticed if this essential step is omitted or wrongly implemented, opening the door for key recovery attacks."

## 9. RFC 9954 and RFC 10024 — hybrid ML-KEM in TLS 1.3

- [FAKTA] Full citation: D. Stebila, S. Fluhrer, S. Gueron, "Hybrid Key Exchange in TLS 1.3", RFC 9954, Informational, July 2026, DOI 10.17487/RFC9954, https://www.rfc-editor.org/info/rfc9954/.
- [FAKTA] Full citation: K. Kwiatkowski, P. Kampanakis, B. Westerbaan, D. Stebila, "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3", RFC 10024, Standards Track, August 2026, DOI 10.17487/RFC10024, https://www.rfc-editor.org/info/rfc10024.
- [FAKTA] RFC 10024 defines three hybrid groups: X25519MLKEM768 (code point 4588, 0x11EC, IANA Recommended Y), SecP256r1MLKEM768 (4587, 0x11EB, Recommended N), SecP384r1MLKEM1024 (4589, 0x11ED, Recommended N). X25519MLKEM768 is the only one marked Recommended Y.
- [FAKTA] RFC 10024 §4.3: for X25519MLKEM768 the hybrid shared secret is the concatenation of the ML-KEM shared secret and the X25519 shared secret (ML-KEM first). RFC 9954 defines the general hybrid key-exchange framework that RFC 10024 instantiates.
- [FAKTA] Corroborating write-up: https://postquantum.com/security-pqc/rfc-10024-hybrid-mlkem-tls/ (10 Aug 2026).

## 10. liboqs 0.16.0 — ML-KEM decapsulation source (inspected)

- [FAKTA] Pinned version: liboqs release 0.16.0, published 9 July 2026; tag commit 5a1a854b0dc9f2141bdc771c555ee60c37950183. Repository: https://github.com/open-quantum-safe/liboqs.
- [FAKTA] Architecture: the OQS wrapper `src/kem/ml_kem/kem_ml_kem_768.c` (220 lines) only dispatches — `OQS_KEM_ml_kem_768_decaps` (line 190) calls `PQCP_MLKEM_NATIVE_MLKEM768_X86_64_dec` (AVX2 path), `PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_dec`, `PQCP_MLKEM_NATIVE_MLKEM768_C_dec` (portable C), or CUDA paths (cupqc/icicle). The FO logic lives in the vendored mlkem-native code.
- [FAKTA] Inspected file (portable C reference path, identical `mlk_kem_dec` in the x86_64 file): `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c` (446 lines) at tag commit 5a1a854b0dc9f2141bdc771c555ee60c37950183; the x86_64 variant `mlkem-native_ml-kem-768_x86_64/mlkem/src/kem.c` contains the same `mlk_kem_dec` (line 376).
- [FAKTA] Decapsulation `mlk_kem_dec` (kem.c, from line 376): calls `mlk_kem_check_sk(sk)` (line 396) — the §7.3 hash check — and returns an error without decapsulating if it fails; decrypts via `mlk_indcpa_dec`; computes (K′, r′) via `mlk_hash_g` over m′ ‖ h; re-encrypts via `mlk_indcpa_enc`; then line 422 `fail = mlk_ct_memcmp(ct, tmp, MLKEM_INDCCA_CIPHERTEXTBYTES)` — a constant-time comparison over the full ciphertext length (1,568 bytes for ML-KEM-1024; `MLKEM_INDCCA_CIPHERTEXTBYTES` is the parameter-set constant, so every byte is covered, including the tail); computes the rejection key with `mlk_hash_j` over z ‖ ct (tmp = last 32 bytes of sk ‖ ct); line 431 `mlk_ct_cmov_zero(ss, kr, MLKEM_SYMBYTES, fail)` copies the true key only if `fail` is 0. Buffers are zeroized on the `cleanup:` path.
- [FAKTA] Input checks in the same file: `mlk_kem_check_pk` (lines 43–74) implements the §7.2 modulus check by decoding the public key to a polynomial vector, reducing, re-encoding, and constant-time comparing against the input; it is called from `mlk_kem_enc_derand` (line 307). `mlk_kem_check_sk` (lines 76–115) implements the §7.3 hash check by recomputing H(ek) over the embedded encapsulation key and constant-time comparing against the stored hash; it is called from `mlk_kem_dec` (line 396). Both return an error on failure — an explicit input-check failure, distinct from implicit rejection.
- [FAKTA] Constant-time primitives (`mlkem/src/verify.h`): `mlk_ct_memcmp` (from line 338) accumulates `r |= a[i] ^ b[i]` over the whole array with no early exit (a second accumulator `s` prevents the compiler dropping the loop once `r` is 0xFF) and returns 0 / 0xFF; `mlk_ct_cmov_zero` (from line 388) selects byte-wise in constant time. A value barrier (`mlk_ct_opt_blocker_u64`, `verify.c`) blocks compiler range analysis that could reintroduce branches.
- [ANALISIS] Consequence: current liboqs (0.16.0, via mlkem-native) performs the full FO comparison over every ciphertext byte in constant time, computes the rejection key unconditionally, and performs both FIPS 203 §7.2/§7.3 input checks. The RatioLabs finding that liboqs "performs neither check" is specific to liboqs 0.12.0 and must not be cited against current liboqs.
- Scope limit: the CUDA decapsulation paths (`cupqc_*`, `icicle_*`) were not inspected; the x86_64 and portable C paths share the same `mlk_kem_dec`.

## 11. PQClean — ML-KEM decapsulation source (inspected)

- [FAKTA] Pinned version: PQClean commit 0586a824fc0d49df0b6b6e9179d8d15d06d0974f (HEAD as of 4 Aug 2026; "Merge pull request #614"). Repository: https://github.com/PQClean/PQClean. Note the current directory naming is hyphenated: `crypto_kem/ml-kem-1024/` (the old `mlkem1024` spelling no longer exists in the tree).
- [FAKTA] Inspected file: `crypto_kem/ml-kem-1024/clean/kem.c` (164 lines) at that commit; the 512 and 768 files are structurally identical (164 lines each). Sizes in `clean/api.h`: secret key 3,168 B, public key 1,568 B, ciphertext 1,568 B, shared secret 32 B (ML-KEM-1024).
- [FAKTA] Decapsulation `PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec` (kem.c, lines 136–164): `indcpa_dec` to recover m′; `hash_g(kr, buf, 2*KYBER_SYMBYTES)` over m′ ‖ h; `indcpa_enc` re-encryption into `cmp`; line 155 `fail = PQCLEAN_MLKEM1024_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES)` — full-length comparison over all 1,568 ciphertext bytes; line 158 `rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct)` computes the rejection key unconditionally (rkprf is `kyber_shake256_rkprf`, i.e. SHAKE256 of z ‖ ct, `symmetric-shake.c` line 62); line 161 `PQCLEAN_MLKEM1024_CLEAN_cmov(ss, kr, KYBER_SYMBYTES, (uint8_t)(1 - fail))` copies the true key only on match; always returns 0.
- [FAKTA] `verify` (verify.c, lines 17–27) is constant-time: it OR-accumulates `a[i] ^ b[i]` over the full length with no early exit and returns `(-(uint64_t)r) >> 63`. `cmov` (verify.c, lines 41–52) is mask-based and constant-time, with `PQCLEAN_PREVENT_BRANCH_HACK`.
- [FAKTA] Input checks: none present. A full read of `kem.c` finds no §7.2 modulus check in `crypto_kem_enc` / `crypto_kem_enc_derand` (lines 113–127) and no §7.3 hash check in `crypto_kem_dec` — the only `hash_h` calls store or recompute h for key derivation, never compare it. This direct source read independently confirms RUSTSEC-2026-0585's statement that PQClean's ML-KEM "does not perform the input checks required by FIPS 203".
- Scope limit: only the `clean` implementation was line-checked; the `aarch64` variant under `crypto_kem/ml-kem-1024/` was not.

## 12. postfiatd dependency tree (local checkout) and OpenSSL ML-KEM

- [FAKTA] Local checkout: `~/workspace/postfiatd-amendment/postfiatd`, HEAD 24c5487d9bfc99171380960e4eeb1543a724cfae ("Update AmendmentTable boundary tests for the 67% majority threshold"), read-only inspection 21 Nov 2026.
- [FAKTA] Repo-tree grep (already done in prep, re-confirmed): 0 matches for `ml-kem|mlkem|kyber` and 0 whole-word `kem` matches anywhere in the tree.
- [FAKTA] Build manifests checked: `CMakeLists.txt` (line 88 `find_package(OpenSSL 1.1.1 REQUIRED)` — a minimum version only, no maximum, no pinned OpenSSL version); `cmake/RippleConfig.cmake:48` (same `find_dependency(OpenSSL 1.1.1 REQUIRED)`); `conan/` contains only `global.conf` and a `profiles/default` template — there is no `conanfile.txt`/`conanfile.py` and no vcpkg manifest in the repo, so dependency versions are resolved at build time, not pinned in-tree; no `.gitmodules` file and `git submodule status` returns nothing (no submodules).
- [FAKTA] Vendored libraries: `external/secp256k1`, `external/ed25519-donna`, `external/antithesis-sdk` — classical-curve and test-instrumentation code only; no KEM code. System-linked dependencies (`find_package`): gRPC, lz4, LibArchive, SOCI, SQLite3, RocksDB, nudb, date, xxHash, Boost — none of these ships ML-KEM (checked at the manifest level; upstream sources of each were not individually audited).
- [FAKTA] No ML-KEM API use: grep for `EVP_KEM|OSSL_KEM|ML.?KEM|mlkem|kyber` over `*.cpp`/`*.h`/`*.txt`/`*.cmake` returns nothing; `EVP_PKEY` appears only in `src/libxrpl/basics/make_SSLContext.cpp` (certificate key handling, not KEM).
- [FAKTA] OpenSSL ML-KEM availability: OpenSSL 3.5.0, released 8 April 2025, added native ML-KEM, ML-DSA, and SLH-DSA (OpenSSL 3.5 release announcement as cited in the fieldguide source list, https://postquantum.com/security-pqc/openssl-3-5-pqc-default/; OpenSSL docs https://docs.openssl.org/master/man7/EVP_PKEY-MLX-KEM/ — "This functionality was added in OpenSSL 3.5"). OpenSSL versions before 3.5 have no built-in ML-KEM (PQC only via the external oqs-provider). The OpenSSL on this machine is 3.0.13 (30 Jan 2024), which predates ML-KEM support.
- [FAKTA] TLS 1.3 group configuration in postfiatd: `src/libxrpl/basics/make_SSLContext.cpp` builds a `boost::asio::ssl::context::sslv23` context (lines 349–350) disabling only SSLv2, SSLv3, TLS 1.0, and TLS 1.1 (lines 352–359) — TLS 1.2 and TLS 1.3 remain enabled — and sets a TLS 1.2 cipher list via `SSL_CTX_set_cipher_list` (line 365, default `"TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL"`). No call anywhere in `src/` sets TLS 1.3 groups or ciphersuites (`SSL_CTX_set1_groups`, `SSL_CTX_set_ciphersuites`, `SSL_CTX_set1_curves` — zero matches), and `src/xrpld/overlay/detail/Handshake.cpp` sets no group either.
- [ANALISIS] Consequence: postfiatd itself never calls any ML-KEM API, but its OpenSSL requirement is a floor (≥ 1.1.1) with no ceiling, and its peer-TLS context leaves TLS 1.3 groups at OpenSSL defaults. On a build linked against OpenSSL ≥ 3.5 — whose default supported-groups list includes and prefers the hybrid X25519MLKEM768 group — peer TLS could negotiate hybrid ML-KEM with no code change in postfiatd. The ML-KEM exposure of a postfiatd deployment is therefore a function of the OpenSSL version it is built against, not of its own source. The Finished-fingerprint session binding (`src/xrpld/overlay/README.md`, lines 312–332: the two endpoints extract the TLS `Finished` messages and combine them into a fingerprint) is the key-confirmation layer such a hybrid handshake would need to preserve.
- [FAKTA] Peer TLS is classical in the source as written: `src/xrpld/overlay/README.md:33` describes "an outgoing TLS encrypted" protocol connection; `docs/dynamic-unl/research/ResearchStatus.md:57` is the only "hybrid" mention in docs and is unrelated to cryptography ("Use OpenRouter so everyone hits the same API endpoint (hybrid approach)").

## 13. Compiler-reintroduced branch (Purnal, 2024) — corroborating note

- [FAKTA] In 2024, PQShield's Antoon Purnal reported that recent Clang versions recognised the reference implementation's `poly_frommsg` function as a bit test and generated a secret-dependent branch absent from the source: the source was constant-time; the binary was not. Reported via the pqc-forum (groups.google.com) in 2024; summarised in the postquantum.com wolfSSL analysis, 15 Aug 2026 (https://postquantum.com/security-pqc/wolfssl-mlkem-key-recovery-fo-check/, "KyberSlash Rhymes" section).
## 14. KAT vectors used by the runnable scripts (build verification)

- [FAKTA] KAT source: pq-crystals/kyber, branch `standard`, commit
  `d5b791c0c601b543233daccbae2845c6197a9e77` (21 Aug 2024).
  https://github.com/pq-crystals/kyber
  The vendored `data/PQCkemKAT_{512,768,1024}.rsp` files (100 vectors
  each) were generated locally by compiling the reference
  `ref/nistkat/PQCgenKAT_kem.c` generator with the reference code at
  this commit and running it; SHA-256 of the vendored files:
  - `data/PQCkemKAT_512.rsp`:  a30184edee53b3b009356e1e31d7f9e93ce82550e3c622d7192e387b0cc84f2e
  - `data/PQCkemKAT_768.rsp`:  729367b590637f4a93c68d5e4a4d2e2b4454842a52c9eec503e3a0d24cb66471
  - `data/PQCkemKAT_1024.rsp`: 3fba7327d0320cb6134badf2a1bcb963a5b3c0026c7dece8f00d6a6155e47b33
- [FAKTA] Cross-check: liboqs `tests/KATs/kem/kats.json`, commit
  `b6689666b934f56773d43dfdcb14e42d898d7dec` (17 Jun 2026).
  `scripts/spec_fidelity.py` recomputes the kat_kem stdout for count 0
  (`single`) and for all 100 counts (`all`) from the same 48-byte seeds
  and matches the published SHA-256 values for ML-KEM-512/768/1024.
- [FAKTA] Second independent cross-check (build-time only, never a
  runtime dependency): pqcrypto `ml_kem_512/768/1024` — bidirectional
  encaps/decaps interop with `scripts/mlkem.py` verified for all three
  parameter sets during the build.
- [FAKTA] The vectors are ML-KEM KATs, not pre-standard Kyber KATs:
  they are generated by the FIPS 203 reference implementation at the
  commit above, whose key generation samples the keypair noise with
  eta1 (FIPS 203 Algorithm 13, lines 9–14) and whose SampleNTT uses
  SHAKE128 (FIPS 203 §4.1 XOF) — both verified against the reference C
  source and the FIPS 203 PDF text during the build.

