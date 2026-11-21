# ML-KEM Implicit-Rejection Assessment

- **Scope:** the security and design assessment of ML-KEM's implicit-rejection
  decapsulation — what the mechanism is, where it has failed in the field,
  what this pack measured, and how a ledger that adopts ML-KEM should handle
  it. This is an assessment, not an audit of existing ML-KEM code: the ledger
  examined here (postfiatd) contains no ML-KEM at all (C40), so §5 is
  forward-looking integration guidance.
- **Method:** primary sources read directly and pinned in `docs/SOURCES.md`
  (FIPS 203 PDF, ePrint abstracts and listings, CVE records, the RustSec
  advisory, RFC texts, and direct source reads of liboqs 0.16.0, PQClean,
  and the postfiatd tree). Every substantive claim carries one label:
  [FAKTA] verified against a named primary source with a date, [ESTIMASI]
  a modelled/reported number, [ANALISIS] interpretation. Claim numbers
  (C1–C48, NV1–NV6) refer to `docs/CLAIMS.md` and
  `docs/claim-evidence-index.md`.
- **Access date for all web sources:** 21 November 2026.
- **Evidence base:** the seven runnable checks in `scripts/` and their
  unedited logs in `outputs/` (7/7 PASS). Every measured figure in §4 is
  quoted from those committed logs, not from memory.

## 1. The mechanism: FIPS 203 Algorithm 18

[FAKTA] FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
Standard", was published 13 August 2024 (C1). It specifies ML-KEM in three
parameter sets — ML-KEM-512 (category 1), ML-KEM-768 (category 3),
ML-KEM-1024 (category 5) — with n = 256 and q = 3329 in all sets (C2).
Parameter sizes (C3): encapsulation key 800 / 1,184 / 1,568 bytes;
decapsulation key 1,632 / 2,400 / 3,168 bytes; ciphertext 768 / 1,088 /
1,568 bytes; shared secret 32 bytes in all three. ML-KEM-768 is NIST's
recommended default.

[FAKTA] The scheme is layered: an IND-CPA-only public-key encryption core,
K-PKE, wrapped in a Fujisaki–Okamoto transform to reach IND-CCA2. K-PKE
"is not IND-CCA2-secure and shall not be used as a stand-alone scheme"
(C4). The hash wrappers are H(s) := SHA3-256(s), J(s) := SHAKE256(s, 256
bits), and G(s) := SHA3-512(s) split into two 32-byte outputs (K, r) (C5).
Key generation (Algorithm 16) builds the decapsulation key as
dk = dkPKE ‖ ek ‖ H(ek) ‖ z, where z is a random 32-byte value used in
the implicit-rejection mechanism (C6).

[FAKTA] Internal decapsulation (Algorithm 18, §6.3) runs deterministically
with no randomness. Using the standard's own step numbers (C7) — note the
research prep's paraphrase numbering was wrong on these two points and is
corrected here: step 5, m′ ← K-PKE.Decrypt(dkPKE, c); step 6,
(K′, r′) ← G(m′ ‖ h); **step 7, K̄ ← J(z ‖ c)** — the rejection key,
computed unconditionally; step 8, c′ ← K-PKE.Encrypt(ekPKE, m′, r′) —
re-encryption of the recovered message; **steps 9–10, if c ≠ c′ then
K′ ← K̄** ("implicitly reject"); step 12, return K′. Success and failure
are indistinguishable at the API boundary: in either case decapsulation
outputs a 32-byte key, and no failure is ever signalled (C7, C9).

[FAKTA] The accept/reject flag is itself secret data. §6.3 states it
"shall be destroyed prior to ML-KEM.Decaps_internal terminating" and that
"returning the value of the flag as an output in any form is not
permitted" (C8). Any API, log, error path, or timing channel that exposes
it re-opens the oracle the transform exists to close. §3.2 states "the
key establishment procedure of ML-KEM will never explicitly fail", and
gives genuine decapsulation-failure rates of 2^-138.8 (512), 2^-164.8
(768), 2^-174.8 (1024) — so a K′ ≠ K outcome in practice means
corruption, interference, or attack, not honest noise (C9). §3.3 adds the
surrounding obligations: internal (derandomized) functions are test-only,
implementations "shall not use floating-point arithmetic", and
intermediate values shall be destroyed as soon as no longer needed (C10).

[FAKTA] Input checking is mandatory, not advisory (C11, C12). §7.2
requires an encapsulation-key type check plus a modulus check,
test ← ByteEncode12(ByteDecode12(ek[0:384k])) == ek[0:384k], ensuring
every coefficient is in [0, q−1]; "ML-KEM.Encaps shall not be run with an
encapsulation key that has not been checked". §7.3 requires a ciphertext
length check (performed with *every* execution), a decapsulation-key
length check, and a hash check,
test ← H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64];
"ML-KEM.Decaps shall not be run with a decapsulation key or a ciphertext
unless both have been checked".

## 2. Implicit vs. explicit rejection

[FAKTA] Explicit rejection returns a failure symbol ⊥; implicit rejection
returns a pseudorandom key K̄ = J(z ‖ c) with output shape identical to
success (C14). During NIST standardisation, designers chose implicit
rejection, "likely due to the availability of security proofs against
quantum attackers" (Hövelmanns & Kudinov, ePrint 2025/062).

[FAKTA] Hövelmanns & Kudinov, "Treating Dishonest Ciphertexts in
Post-quantum KEMs — Explicit vs. Implicit Rejection in the FO Transform",
ePrint 2025/062, was received **15 January 2025, not 14 January** (the
research prep's date was wrong by one day; the ePrint metadata reads
received 2025-01-15, approved 2025-01-16); PQCrypto 2025, Springer LNCS
vol. 15578, pp. 325–350, first online 15 March 2025 (C15). The paper
closes the previously open direction: explicit rejection is not less
secure than implicit rejection in the classical random-oracle model "up
to a rare edge case", lifted to the quantum setting via the extractable
QROM (eQROM), with an alternative indirect proof avoiding the eQROM.
Prior work had proven only the opposite direction (C16).

[FAKTA] The same paper warns that "implicit rejection introduces
complexity and can easily deteriorate into explicit rejection in
practice" (C17). [ANALISIS] The practical reading is that the two modes
are now near-equivalent as abstract designs, so the choice between them
is an engineering decision — API shape, diagnosability, caller
obligations — not a security hierarchy (C18). An assessment should
therefore not rank the modes; it should test whether a concrete
deployment *preserves* implicit rejection end-to-end (API, timing,
logging, error handling, key confirmation) or silently converts it into
explicit rejection somewhere in the stack. That is what §4 measures.

## 3. Known failure cases

### 3.1 wolfSSL incomplete FO ciphertext comparison (2026) — partial comparison = key recovery

[FAKTA] In wolfSSL 5.7.0–5.9.1 (NEON path 5.7.4–5.9.1), hand-written SIMD
assembly for the FO comparison was incomplete: the x86-64 AVX2 function
`mlkem_cmp_avx2` compared only 1,536 of 1,568 bytes of an ML-KEM-1024
ciphertext, skipping the final 32 bytes (CVE-2026-10097, CVSS 4.0 8.3
High, CWE-697); the ARM64 NEON path used `ins` where `ext` was intended,
leaving 784 of 1,568 bytes unchecked (CVE-2026-6330). Both were patched
in wolfSSL 5.9.2, released 23 June 2026. The NEON bug was independently
reported by Nicholas Carlini (Anthropic); the AVX2 bug by Bhabani Sankar
Das (C19).

[FAKTA] Das's paper, "Incomplete Ciphertext Comparison in ML-KEM: From an
IND-CCA2 Break to Key Recovery" (IACR ePrint 2026/1682, posted 15 Aug
2026), demonstrates near-complete private-key recovery against shipped
binaries: 98.0% of the 2,048 secret coefficients recovered with 400 chosen
ciphertexts (AVX2, native x86-64) and 98.5% with 600 chosen ciphertexts
(NEON, ARM64 under QEMU); full recovery of all 2,048 coefficients needed
~1,300 ciphertexts against a reference model, at a total budget of
10^5–10^6 decapsulation queries per key (C20). Mechanism: the unchecked
bytes encode the compressed tail of the decryption noise, an exact linear
function of the secret key; varying them and observing decapsulation
output measures the noise one coordinate at a time, and ordinary least
squares solves the resulting overdetermined system — no lattice reduction
needed. (Figures rest on the postquantum.com write-up + CVE records, not
on a direct read of the Das paper PDF — see NV1.)

[FAKTA] Scope limit: the attack requires a static (reused) ML-KEM key
and a plaintext-checking oracle; ephemeral hybrid TLS 1.3 handshakes
(fresh key per session) are not vulnerable to key recovery — there the bug
is only a distinguishing break. Static-key deployments at risk: HPKE
static recipients, KEMTLS long-term keys, pinned/embedded keys in IoT
and embedded devices (C21). [ANALISIS] The lesson: "the comparison
exists" is not a check — only "the comparison covers every byte, verified
by a tail-mutation sweep" is. Das's recommended test is exactly that, and
it is Check 2 of this pack (§4.2).

### 3.2 KyberSlash: secret-dependent division timing in decapsulation (2023–2025)

[FAKTA] KyberSlash (Bernstein et al., disclosed Dec 2023; IACR TCHES
2025, Vol. 2, pp. 209–234) is a family of timing vulnerabilities in
several Kyber/ML-KEM implementations, including the official reference
code: divisions by the prime q = 3329 on secret-derived values (notably
in `poly_tomsg` during decapsulation) take data-dependent time on some
CPUs, leaking the secret key. Keys were reliably recovered within minutes
(KyberSlash2) and a few hours (KyberSlash1) on Raspberry Pi 2 (Arm
Cortex-A7) and Arm Cortex-M4. The reference implementation was patched
1 Dec 2023 (KyberSlash1) and 30 Dec 2023 (KyberSlash2); multiple
libraries were affected, including liboqs (patched for KyberSlash1 only,
per the Jan 2024 status list) (C22). [ANALISIS] KyberSlash sits adjacent
to, not inside, the implicit-rejection step — but it shows the
decapsulation path's timing surface extends beyond the FO comparison, and
that a constant-time source can still produce variable-time binaries
(see §3.5).

### 3.3 Missing FIPS 203 input checks — RUSTSEC-2026-0585, and the liboqs / PQClean asymmetry

[FAKTA] RUSTSEC-2026-0585, published 20 Nov 2026, records that
`pqcrypto-mlkem`, wrapping PQClean's ML-KEM, performs neither the FIPS
203 §7.2 encapsulation-key modulus check nor the §7.3 decapsulation-key
hash check. With Wycheproof ML-KEM vectors, 108 / 112 / 116 invalid
encapsulation keys (ML-KEM-512 / -768 / -1024) and 2 invalid
decapsulation keys per parameter set are accepted. The advisory states
this does not disclose key material — it is a FIPS 203 non-conformance,
and an affected implementation "can disagree with a conforming one about
which keys are valid". The crate is unmaintained and no patched version
is expected; migration to a maintained implementation (e.g. the `ml-kem`
crate) is recommended (C23).

[FAKTA] The source verification behind this pack found an asymmetry the
research prep did not anticipate, and the two libraries must not be
presented as equivalent (C24, C25, C26). Current liboqs 0.16.0 (tag
commit 5a1a854b0dc9f2141bdc771c555ee60c37950183, released 9 Jul 2026)
**does** both input checks and the full FO comparison: in the vendored
mlkem-native `kem.c`, `mlk_kem_check_pk` (lines 43–74, §7.2 modulus check
via decode → reduce → re-encode → constant-time compare) is called from
`mlk_kem_enc_derand` (line 307); `mlk_kem_check_sk` (lines 76–115, §7.3
hash check) is called from `mlk_kem_dec` (line 396); line 422
`fail = mlk_ct_memcmp(ct, tmp, MLKEM_INDCCA_CIPHERTEXTBYTES)` is a
constant-time comparison over the full ciphertext length; the rejection
key is computed via `mlk_hash_j` over z ‖ ct; line 431
`mlk_ct_cmov_zero` selects the true key only on match. Both checks fail
explicitly (error return) — the FIPS-required input-check failure path,
distinct from implicit rejection. PQClean (commit
0586a824fc0d49df0b6b6e9179d8d15d06d0974f), by contrast, does **neither**
check: a full read of `crypto_kem/ml-kem-1024/clean/kem.c` (164 lines)
finds no §7.2 modulus check in encaps and no §7.3 hash check in decaps —
while its FO comparison itself is full-length (line 155, `verify(ct, cmp,
KYBER_CIPHERTEXTBYTES)`) and constant-time. This direct source read
independently confirms RUSTSEC-2026-0585, and locates the gap in PQClean
itself, not only in the Rust wrapper. The RatioLabs finding that liboqs
"performs neither check" is specific to liboqs 0.12.0 and must not be
cited against current liboqs. Scope limits: liboqs CUDA paths (cupqc,
icicle) were not inspected (NV4); only PQClean's `clean` implementation
was line-checked, not its `aarch64` variant (NV5).

[ANALISIS] This is the input-check counterpart to §3.1: the FO comparison
can be perfect and the deployment still non-conformant if the keys feeding
it were never validated — and two implementations can then disagree about
validity, which is precisely the kind of silent divergence implicit
rejection is meant to prevent from mattering.

### 3.4 H(c) omitted from key derivation re-enables key-mismatch attacks — Shao et al., ESORICS 2026

[FAKTA] Shao et al., "Closing the Gap: Huffman-Optimal and Stealthy
Key-Mismatch Attacks on ML-KEM" (ESORICS 2026, Springer LNCS vol. 16969,
pp. 341–362, first online 27 Sep 2026): the omission of the ciphertext
hash H(c) from the shared-key derivation — a change made in the transition
from CRYSTALS-Kyber to finalised ML-KEM (FIPS 203), intended to streamline
performance and facilitate crypto-agility — "unintentionally re-enables a
class of highly efficient key-mismatch attacks (KMAs)" via a
baseline-comparison technique, achieving the information-theoretic Huffman
bound for query complexity, including a profiling-free
plaintext-checking-oracle variant in the CCA-secure setting. The authors
also design a stealthy composite-ciphertext construction whose traffic
evades all six detectors they evaluate and "remains practically
indistinguishable from legitimate ML-KEM traffic" (C27). [ANALISIS]
Unlike §§3.1–3.3 this is a design-level finding about the standard
itself, not an implementation bug: the question is what the standard's own
design choices cost under key reuse, and what deployment rules (key
rotation, reuse limits, mismatch monitoring) compensate. §4.5 reproduces
the probe shape against this pack's harness.

### 3.5 The compiler reintroduces the branch (Purnal, 2024)

[FAKTA] In 2024, PQShield's Antoon Purnal reported that recent Clang
versions recognised the reference implementation's `poly_frommsg`
function as a bit test and generated a secret-dependent branch absent from
the source: the source was constant-time; the binary was not (C28).
[ANALISIS] Source-level review is insufficient evidence for
implicit-rejection safety; the assessment must test the compiled artefact
(timing measurements, binary inspection), not just read the code. That is
why Check 4 (§4.4) measures timing on the running harness rather than
asserting constant-time from the source. Note the contrast with liboqs
0.16.0's defence in depth (§3.3): its `mlk_ct_memcmp` uses a second
accumulator plus a value barrier (`mlk_ct_opt_blocker_u64`) specifically
to guard against compiler optimisation reintroducing a branch.

### 3.6 A skipped re-encryption check is invisible to correctness tests — Glabush et al.

[FAKTA] "Verifiable Decapsulation: Recognizing Faulty Implementations of
Post-Quantum KEMs" (Lewis Glabush, Felix Günther, Kathrin Hövelmanns,
Douglas Stebila; IACR ePrint 2025/450, received 10 Mar 2025, revised
10 Jun 2025; CRYPTO 2025, Springer LNCS vol. 16002, pp. 543–574) shows
the re-encryption check in the FO transform "is essential for security,
but not for functionality. In other words, it will go unnoticed if this
essential step is omitted or wrongly implemented, opening the door for
key recovery attacks." The flaw was present in HQC's reference
implementation and was only noticed after 19 months. The authors propose
a modified FO transform that binds re-encryption to functionality via an
unpredictable confirmation code, so a faulty implementation is exposed by
basic correctness tests; they apply the technique to ML-KEM and HQC with
negligible overhead (C29). [ANALISIS] This is the meta-finding that
justifies this pack's method: a test pack that only checks correct
outputs cannot catch a missing FO check. The pack must include
adversarial vectors that distinguish "comparison present and complete"
from "comparison absent" — Check 7 (§4.7) does exactly that.

### 3.7 Cross-cutting misuse pattern — callers that treat rejection as success

[ANALISIS] Implicit rejection hands every caller a plausible-looking
32-byte key on failure. Any caller that (a) uses the decapsulated key
without key confirmation, (b) logs it or logs outcomes, or (c) retries
with the same ciphertext expecting a different result, converts a silent
rejection into a live vulnerability or a silent outage (C30). In TLS 1.3
hybrid handshakes the failure surfaces later at Finished/AEAD
verification, where failure is already public and carries no key
information — that layering is the correct pattern, and a ledger
integration should be judged against it: rejection must be detected at
key confirmation, never at decapsulation, and never by inspecting the key
itself. Check 6 (§4.6) demonstrates all three caller failures concretely.

## 4. What this pack measured

The harness is a clean-room ML-KEM-512/768/1024 implementation from FIPS
203 (`scripts/mlkem.py`, Python standard library only), plus seven checks
run by `scripts/run_all.sh`. KAT vectors come from the NIST reference
implementation (pq-crystals/kyber, branch `standard`, commit
d5b791c0c601b543233daccbae2845c6197a9e77, 21 Aug 2024), 100 vectors per
parameter set (C39). All seven checks passed in the committed run
(`RUN_ALL RESULT: ALL CHECKS PASSED (7/7 scripts)`).

### 4.1 Check 1 — Spec fidelity (accept + reject paths byte-exact)

[FAKTA] 100 KAT vectors per parameter set; accept path 100/100 decaps ==
ss and reject path 200/200 mutated decaps == J(z‖c′) exactly, for all
three sets (C31). Log lines, `outputs/spec_fidelity.log`:
`PASS KAT-COUNT-512 -- 100 vectors`, `PASS ACCEPT-512 -- 100/100 decaps
== ss`, `PASS REJECT-512 -- 200/200 mutated decaps == J(z||c') exactly,
!= ss` (and the same for 768 and 1024). The recomputed kat_kem stdout
hashes match liboqs `tests/KATs/kem/kats.json` (commit
b6689666b934f56773d43dfdcb14e42d898d7dec, 17 Jun 2026), single and all,
for all three sets — e.g. ML-KEM-512 single
`c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782` and all
`74b470e797cbdbd589a31d387d36c72aad5033446ab5159bf4014c24652b1173`
(the 768/1024 hashes are in the log). Verdict:
`SPEC_FIDELITY VERDICT: PASS -- accept + reject paths byte-exact for 100
vectors x 3 parameter sets; liboqs single+all hashes match`.

### 4.2 Check 2 — Tail-mutation sweep (the Das test)

[FAKTA] 3,424 byte positions tested (768 + 1,088 + 1,568), 0 acceptances;
every mutation yields exactly J(z‖c′) (C32). Log lines,
`outputs/tail_mutation.log`: `PASS TAIL-512 -- 768/768 mutations
rejected with exact Kbar`, `PASS TAIL32-512 -- final 32 bytes: 32/32
rejected` (and the same for 768 and 1024). Verdict:
`TAIL_MUTATION VERDICT: PASS -- 3424 positions tested, 0 acceptances;
every mutation yields exactly J(z||c')`. This is the test the wolfSSL
bug (§3.1) fails: a comparison covering only 1,536 of 1,568 bytes would
show 32 acceptances in the ML-KEM-1024 tail sweep.

### 4.3 Check 3 — Input-check battery (§7.2/§7.3)

[FAKTA] The checked wrappers refuse every malformed input in the battery
(C33). Log lines, `outputs/input_checks.log`: 3/3 unreduced encapsulation
keys refused per set (coefficient values 3329, 3330, 4095);
`PASS CT-LENGTH-512 -- 4/4 wrong-length ciphertexts refused (lengths (0,
32, 767, 769))` (768: lengths (0, 32, 1087, 1089); 1024: (0, 32, 1567,
1569)); decapsulation keys with tampered embedded ek or tampered stored
H(ek) refused per set. The log also records that an unchecked
`encaps_internal` with an unreduced ek proceeds — the §7.2 check is
load-bearing — and a z-tamper subtlety: tampering with z is invisible to
the §7.3 hash check (hash passes, accept-path key unchanged, rejection
key changed), because z sits outside H(ek). Verdict:
`INPUT_CHECKS VERDICT: PASS -- checked wrappers refuse every malformed
input; z-tamper behaviour recorded as specified`. Against the
RUSTSEC-2026-0585 baseline (108/112/116 invalid eks accepted by an
implementation that skipped the checks), this harness refuses 3/3 probed
unreduced eks per set.

### 4.4 Check 4 — Timing indistinguishability (accept vs. reject)

[FAKTA] Accept-path and reject-path decapsulation are timing
indistinguishable in this harness at N=1000 per path per set (C34).
Committed run, `outputs/timing.log` (means in microseconds per
decapsulation): ML-KEM-512 accept mean 8097.2, reject mean 8010.1
(difference 87.09 µs, 95% CI [−81.07, 255.25] µs); ML-KEM-768 accept mean
11886.0, reject mean 12060.0 (difference −174.02 µs, 95% CI [−372.94,
24.91] µs); ML-KEM-1024 accept mean 17151.5, reject mean 17307.7
(difference −156.16 µs, 95% CI [−526.14, 213.81] µs). Relative gaps:
+1.0755% / −1.4641% / −0.9105% for 512 / 768 / 1024; all three 95%
confidence intervals include zero. Verdict: `TIMING VERDICT: PASS --
accept/reject timing indistinguishable within 5% at N=1000 per path per
set (3 sets)`. The specific percentages are from the latest committed run
and vary run to run — the stable, reproducible fact is the verdict (PASS
within 5% at N=1000 per path per set). A fresh-copy simulation run during
this assessment's preparation returned different gaps (0.0168% /
0.7382% / 1.0768%) with the same PASS verdict, confirming the point. This
is the check that catches memcmp-style early exits and
compiler-reintroduced branches (§§3.2, 3.5).

### 4.5 Check 5 — Key-mismatch / chosen-ciphertext probe (Shao et al.)

[FAKTA] The baseline-comparison probe recovers 16/16 secret coefficients
of s₀ at 2.2500 queries/coefficient (36 oracle queries; 1.1080
queries/bit vs a 2.0306-bit Huffman bound), using a lab
plaintext-checking oracle (C35). Log lines, `outputs/key_mismatch.log`:
`PASS RECOVER-16 -- 16/16 coefficients`,
`PASS QUERIES-BOUND -- 2.2500 queries/coefficient (Huffman bound 2.0306
bits)`, `PASS CCA-NO-PC-ORACLE -- bare decaps API does not supply the
plaintext-checking oracle` — 8/8 crafted ciphertexts return exactly K̄ =
J(z‖c) from full decapsulation, because the bare decapsulation API does
not supply that oracle. [ESTIMASI] Full-key extrapolation: 768 secret
coefficients (k·n = 768) at 2.2500 queries/coefficient ≈ 1,728 queries
for a full static key, before lattice post-processing (C36). [ANALISIS]
The probe needs 36 queries against one key; a static key is exposed to
cumulative leakage, an ephemeral key (fresh per session) is not — the
policy consequence is in §5.3.

### 4.6 Check 6 — Caller-misuse scenarios

[FAKTA] Three minimal callers, runnable transcripts (C37),
`outputs/caller_misuse.log`: (i) no key confirmation — a tampered
ciphertext's K̄ (`bc655b3027d548fe…`) is used as a session key, differs
from the peer's true key (`a0e28fccceab9b5f…`), and is deterministic
across runs (`PASS MISUSE-NO-KCF`); (ii) logging outcomes writes
`REJECT`/`ACCEPT` per chosen ciphertext to a log file — a
decryption-failure oracle written to disk (`PASS MISUSE-LOGS`); (iii)
retrying a rejected ciphertext 3 times returns the identical K̄
(`84394f4492bfb2b7…`) every time, while a fresh encapsulation succeeds
(`PASS MISUSE-RETRY`). Verdict: `CALLER_MISUSE VERDICT: PASS -- all
three misuse transcripts demonstrate the concrete leak/break as
specified`.

### 4.7 Check 7 — Missing-FO-check detector (the invisible failure class)

[FAKTA] A correctness-only test cannot distinguish the correct
implementation from a deliberately neutered one (FO re-encryption check
removed): control ciphertext agrees on both (`PASS CONTROL-AGREE`) (C38).
3 adversarial ciphertexts were found (c1 bytes 0, 2, 3 flipped) that
decrypt to the chosen message but fail re-encryption; 3/3 separate
correct (returns K̄ == J(z‖c*)) from neutered (returns the genuine shared
secret K). Verdict: `MISSING_FO_CHECK VERDICT: PASS -- pack catches the
invisible failure class: 3/3 adversarial ciphertexts return Kbar on the
correct implementation and the genuine shared secret on the neutered
one`. This is the detector §3.6 calls for.

## 5. Ledger integration — forward-looking postfiatd guidance

### 5.1 What exists today: no ML-KEM anywhere in the tree

[FAKTA] The postfiatd source tree (HEAD
24c5487d9bfc99171380960e4eeb1543a724cfae, "Update AmendmentTable boundary
tests for the 67% majority threshold") contains no ML-KEM usage: 0 matches
for `ml-kem|mlkem|kyber` and 0 whole-word `kem` matches anywhere in the
tree (C40). Its cryptography is OpenSSL plus Ed25519 (bundled
ed25519-donna), and its peer links are classical TLS with
Finished-fingerprint binding (§5.2). Any ML-KEM work for this ledger is
forward-looking integration assessment, not audit of existing usage.

### 5.2 The material nuance: OpenSSL is a floor-only dependency

[FAKTA] OpenSSL is a floor-only dependency: `find_package(OpenSSL 1.1.1
REQUIRED)` (`CMakeLists.txt:88`, `cmake/RippleConfig.cmake:48`) sets a
minimum version only — no maximum, no pinned version anywhere in-tree;
there is no conanfile/vcpkg manifest, and `git submodule status` returns
nothing (no submodules) (C41). OpenSSL 3.5.0, released 8 April 2025,
added native ML-KEM (plus ML-DSA, SLH-DSA); pre-3.5 OpenSSL has no
built-in ML-KEM. The system OpenSSL on this machine is 3.0.13, which
predates ML-KEM support (C42).

[FAKTA] postfiatd's TLS context (`src/libxrpl/basics/make_SSLContext.cpp`,
lines 349–365) builds an `sslv23` context disabling only SSLv2/SSLv3/TLS
1.0/TLS 1.1, and sets only a TLS 1.2 cipher list. No call anywhere in
`src/` sets TLS 1.3 groups or ciphersuites (`SSL_CTX_set1_groups`,
`SSL_CTX_set_ciphersuites`, `SSL_CTX_set1_curves` — zero matches), so TLS
1.3 groups are OpenSSL defaults (C43). [ANALISIS] Consequence: on a build
linked against OpenSSL ≥ 3.5 — whose default supported-groups list
includes and prefers the hybrid X25519MLKEM768 group — peer TLS could
negotiate hybrid ML-KEM with zero code change in postfiatd. The correct
phrasing is therefore: **"no ML-KEM in source; ML-KEM reachable via
default TLS 1.3 groups on OpenSSL ≥ 3.5 builds"** (C44). A deployment's
ML-KEM exposure is a function of the OpenSSL version it is built against,
not of postfiatd's own source. The other system dependencies (gRPC, lz4,
LibArchive, SOCI, SQLite3, RocksDB, nudb, date, xxHash, Boost) were
checked at manifest level only; none ships ML-KEM by design, but their
upstream sources were not individually audited (NV6).

### 5.3 Hybrid peer-TLS integration guidance

[FAKTA] The integration target is hybrid X25519MLKEM768 in peer TLS.
RFC 9954, "Hybrid Key Exchange in TLS 1.3" (Informational, July 2026),
defines the general hybrid key-exchange framework; RFC 10024,
"Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS
1.3" (Standards Track, August 2026), defines X25519MLKEM768 (code point
4588, 0x11EC, IANA Recommended Y; the other two groups,
SecP256r1MLKEM768 0x11EB and SecP384r1MLKEM1024 0x11ED, are Recommended
N). For X25519MLKEM768 the hybrid shared secret is the concatenation of
the ML-KEM shared secret and the X25519 shared secret, ML-KEM first
(RFC 10024 §4.3) (C45).

[FAKTA] The key-confirmation layer already exists and must be preserved:
postfiatd's overlay binds the TLS session to node identities by
extracting the TLS `Finished` messages from both endpoints and combining
them into a fingerprint (`src/xrpld/overlay/README.md`, lines 312–332)
(C46). In a hybrid handshake, rejection of a bad ML-KEM ciphertext must
be detected at this layer (Finished/AEAD verification, where failure is
already public and carries no key information) — never at decapsulation,
and never by inspecting the decapsulated key itself (§3.7).

[ANALISIS] Static-vs-ephemeral key policy (C47): use ephemeral hybrid
keys per session for peer TLS. The wolfSSL attack (§3.1) and the Shao et
al. probe (§3.4, §4.5) both need many queries against one key; an
ephemeral key (fresh per session) is not exposed to cumulative leakage,
while a static key is. Long-term validator identity keys must never
double as ML-KEM decapsulation keys, and any static-key deployment (HPKE
static recipients, KEMTLS long-term keys, pinned/embedded keys) needs
explicit rotation limits and a mismatch-monitoring rule.

[ANALISIS] Rotation/monitoring checklist, derived from the cases (C48):
1. Run the tail-mutation sweep (Check 2) on every build — it is the test
   that catches an incomplete FO comparison before it ships.
2. Run the input-check battery (Check 3) on every dependency upgrade —
   the RUSTSEC-2026-0585 gap (§3.3) arrives through a dependency, and
   the liboqs 0.12.0 → 0.16.0 history shows the same library can gain or
   lose the checks across versions; pin and verify, do not assume.
3. Measure accept/reject timing on the shipped binary (Check 4), not on
   the source — the compiler can reintroduce a branch (§3.5).
4. Monitor the decapsulation rejection rate with an alert threshold:
   honest failures are ~2^-165 (C9), so any cluster of rejections is
   corruption, interference, or attack, not noise.
5. Never log accept/reject outcomes, decapsulation keys, or rejection
   keys (§3.7, §4.6) — the flag is secret data (C8).
6. Require key confirmation before any use of a decapsulated key, and
   never retry a rejected ciphertext — retries are deterministic and
   hand an attacker free oracle queries (§4.6).
7. Pin the OpenSSL version in the build and record it: ML-KEM reachability
   in peer TLS is a function of that version (§5.2).

## 6. Errata: the FIPS 203 "Potential Updates" spreadsheet

[FAKTA] The NIST CSRC publication page for FIPS 203 carries a Planning
Note dated 17 November 2025: an issue was identified that will be
corrected in a future update/revision, with details in the "Errata
(potential updates)" spreadsheet. The spreadsheet was retrieved by direct
download (23,849 bytes, SHA-256
edf899c89762449f43d7713883caeefc2e4ae9ae98d5a76b339547db22cb3ac7; one
worksheet, "Sheet1", 45 rows; document properties last modified
2025-11-17T13:47:51Z, matching the Planning Note date). It lists exactly
two issues, neither touching Algorithm 18 / §6.3, the FO transform, any
parameter, key size, or test vector (C13):
1. Identified 2025-03-31, Appendix A: "Algorithms 9 and 10 use the zeta
   values for i = 1, …, 127, however Appendix A also includes the value 1
   (corresponding to i = 0)." Correction: add the sentence "The value 1,
   corresponding to i = 0, has been included so that i-th entry of the
   array would then equal ζ^BitRev_7(i)."
2. Identified 2025-10-17, Section 5.3: "In Algorithm 15, line 7, the
   comment reads 'decode plaintext m from polynomial v.' However, v is
   not used in the algorithm." Correction: change the comment to "decode
   plaintext m from polynomial w."
The spreadsheet header states the corrections "DO NOT introduce new
technical requirements" and "ARE NOT official changes, but may be
corrected in a future errata update of the publication." [ANALISIS] The
Planning Note therefore signals no pending change to implicit rejection,
decapsulation, or the FO check.

## 7. NOT VERIFIED

The following items could not be verified and are not presented as
verified anywhere in this pack. Each is also listed as NV1–NV6 in
`docs/CLAIMS.md` and `docs/claim-evidence-index.md`.

- **NV1 — Das paper PDF direct read.** The ePrint paper page for
  2026/1682 returned HTTP 403 on 21 Nov 2026 and was not retried. All Das
  figures in this pack (98.0%/400, 98.5%/600, ~1,300, 10^5–10^6 queries)
  rest on the postquantum.com write-up (15 Aug 2026), the CVE records,
  and the ePrint 2026 listing mirror — cite those, not "Das paper, read
  directly".
- **NV2 — RFC 9954 "successor to draft-ietf-tls-hybrid-design-14"
  claim.** The RFC 9954/10024 dates, titles, and code points are verified
  (C45); the draft-successor detail (expired 22 Jan 2026) was not checked.
- **NV3 — mlkemcipher.com write-up.** The write-up on implicit rejection
  (date and contents) was not independently verified. Its framing (e.g.
  a systematic bug surfacing only as interop failure two layers up) is
  used only as analysis, never as a sourced fact.
- **NV4 — liboqs CUDA paths.** The cupqc and icicle decapsulation paths
  were not inspected. Claims about liboqs cover the x86_64 / AArch64 /
  portable-C paths only.
- **NV5 — PQClean aarch64 variant.** The `aarch64` ML-KEM variant was not
  line-checked. Claims about PQClean cover the `clean` implementation
  only.
- **NV6 — postfiatd system dependencies' upstream sources.** gRPC,
  RocksDB, and the other system dependencies were checked at manifest
  level only; their upstream sources were not individually audited for
  ML-KEM code. The "no dependency ships ML-KEM" claim is stated with
  that scope limit.

## Appendix — How to verify this assessment

- Run the pack: `bash scripts/run_all.sh` (Python 3.9+, standard library
  only, no network). Expect `RUN_ALL RESULT: ALL CHECKS PASSED (7/7
  scripts)`. Full procedure, expected log hashes, and the timing-log
  exception: `docs/fresh-clone-repro.md`.
- Check a claim: find its number in `docs/CLAIMS.md`, then its exact
  evidence (script + log + PASS line, or pinned source section) in
  `docs/claim-evidence-index.md`.
- Check a source: `docs/SOURCES.md` carries the full citation, URL,
  access date, and section/page/line reference for every source used.
