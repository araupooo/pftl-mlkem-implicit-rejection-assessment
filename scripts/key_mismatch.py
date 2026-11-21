#!/usr/bin/env python3
"""Check 5 -- key-mismatch probe, Shao et al. baseline-comparison shape.

[FAKTA] Shao et al., "Closing the Gap: Huffman-Optimal and Stealthy
Key-Mismatch Attacks on ML-KEM" (ESORICS 2026, first online 27 Sep
2026): the omission of H(c) from the shared-key derivation when
CRYSTALS-Kyber became final ML-KEM "unintentionally re-enables a class
of highly efficient key-mismatch attacks" via a baseline-comparison
technique, achieving the information-theoretic Huffman bound for query
complexity. Appendix A gives the construction for ML-KEM-768/512:
baseline ciphertext C0 with u = [ceil(q/16), 0, ..., 0] and
c2 = [h0, ..., h0], h0 = 3; compared ciphertext Ci sets c2[k] = h'.
The decrypted bit k is then a threshold function of s[k].

[FAKTA] The paper's CPA-secure attack assumes a plaintext-checking (PC)
oracle: the attacker observes the decrypted message. Its CCA extension
instantiates that PC oracle from power-trace side channels (Appendix C,
oscilloscope captures + clustering) -- NOT from the decapsulation return
value. This pack does not reproduce power analysis.

What this script measures, in the lab, with the harness as oracle:
  (a) CPA level: the PC oracle is K-PKE.Decrypt exposed for measurement
      (labelled as the lab oracle). Using the Appendix A construction on
      ML-KEM-768 (eta1 = 2, s coefficients in {-2..2}), recover 16
      coefficients of the first secret polynomial s_0 by threshold
      queries, and measure queries-per-coefficient and queries-per-bit
      against the Huffman bound (entropy of the eta=2 coefficient
      distribution, 2.03 bits/coefficient).
  (b) CCA level: the SAME crafted ciphertexts are fed to full
      ML-KEM.Decaps_internal. Every one must return exactly
      Kbar = J(z || c) -- the bare decapsulation API does not hand the
      attacker the PC oracle, because the FO re-encryption check rejects
      every crafted ciphertext.

[ANALISIS] Static vs ephemeral exposure: the probe needs many queries
against ONE key. A static (reused) key is exposed to cumulative
leakage; an ephemeral key (fresh per session, as in hybrid TLS 1.3
handshakes) gives the attacker one query per key, so the attack does
not apply. Full-key recovery is NOT attempted here: lab-scale recovery
of 16 coefficients plus the measured queries-per-bit, with full-key
extrapolation labelled [ESTIMASI] where stated.

Deterministic: fixed keypair; no randomness, no timestamps, no network.
"""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem

PARAMS_ID = 768
N_COEFFS = 16
H0 = 3


def _crafted_ct(params_id, k_idx, h):
    """Appendix A ciphertext: u_0[0] ~= ceil(q/16) (decompressed), all
    other u coefficients 0; v coefficients all h0 except position k_idx
    which is h. Returns the raw ciphertext bytes."""
    p = mlkem.PARAMS[params_id]
    du, dv = p["du"], p["dv"]
    # Compressed u coefficient whose decompressed value is closest to
    # ceil(q/16) = 209 from above: compress(10, 209) = 64 -> 208, so use
    # 65 -> decompress(10, 65) = 211. Thresholds are computed from the
    # ACTUAL decompressed amplitude, never assumed.
    amp = mlkem.decompress(du, 65)
    u = [[0] * 256 for _ in range(p["k"])]
    u[0][0] = 65
    c1 = b"".join(mlkem.byte_encode(du, comp) for comp in u)
    v = [H0] * 256
    v[k_idx] = h
    c2 = mlkem.byte_encode(dv, v)
    return c1 + c2, amp


def _predicted_bit(params_id, h, s_val, amp):
    """Appendix A formula: bit = compress1(decompress_dv(h) - amp*s)."""
    p = mlkem.PARAMS[params_id]
    w = (mlkem.decompress(p["dv"], h) - amp * s_val) % mlkem.Q
    return mlkem.compress(1, w)


def main():
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name
              + ((" -- " + detail) if detail else ""))
        if not cond:
            failures.append(name)

    print("== key_mismatch: Shao et al. baseline-comparison probe ==")
    print("[FAKTA] Shao et al. ESORICS 2026: H(c) omitted from ML-KEM key "
          "derivation re-enables Huffman-bound key-mismatch attacks")
    print("[FAKTA] CPA setting assumes a plaintext-checking oracle; the "
          "CCA extension instantiates it from power traces (App. C), not "
          "from the decapsulation return value")

    d = bytes([41]) * 32
    z = bytes([43]) * 32
    m = bytes([47]) * 32
    ek, dk = mlkem.keygen(d, z, PARAMS_ID)
    p = mlkem.PARAMS[PARAMS_ID]
    k = p["k"]
    dk_pke = dk[:384 * k]
    z_key = dk[768 * k + 64:768 * k + 96]
    # True secret polynomial s_0 (lab knowledge, for scoring only).
    # Coefficients are stored mod q; map to centered representatives
    # in [-2, 2] for comparison with the recovered values.
    s_hat0 = mlkem.byte_decode(12, dk_pke[:384])
    s_true = [x if x <= mlkem.Q // 2 else x - mlkem.Q
              for x in mlkem.inv_ntt(s_hat0)]
    print("-- ML-KEM-768, eta1=2, s_0 coefficients in {-2..2} --")

    # Bit windows: for each s value, the set of h' whose predicted bit is
    # 1 (Compress1(w) = 1 iff w mod q is in [q/4, 3q/4)). The windows are
    # contiguous and overlapping, so the tree below splits them:
    #   h'=5  splits {0,-1,-2} | {1,2}
    #   h'=14 isolates {2} within {1,2}
    #   h'=11 isolates {0} within {0,-1,-2}
    #   h'=2  isolates {-2} within {-1,-2}
    _, amp = _crafted_ct(PARAMS_ID, 0, H0)
    print("  decompressed u amplitude: %d (target ceil(q/16)=209)" % amp)
    windows = {}
    for s_val in (-2, -1, 0, 1, 2):
        windows[s_val] = [h for h in range(16)
                          if _predicted_bit(PARAMS_ID, h, s_val, amp) == 1]
    print("  bit-1 windows h' per s value: %s" % windows)
    check("WINDOWS-DISTINCT", len({tuple(v) for v in windows.values()}) == 5,
          "windows %s" % windows)

    # Verify the decision tree against the formula for every s value
    # before spending oracle queries.
    def tree_with(bitfn):
        bit5 = bitfn(5)
        if bit5 == 1:
            bit11 = bitfn(11)
            if bit11 == 1:
                return 0
            bit2 = bitfn(2)
            return -2 if bit2 == 1 else -1
        bit14 = bitfn(14)
        return 2 if bit14 == 1 else 1

    tree_ok = all(
        tree_with(lambda h, s=s: _predicted_bit(PARAMS_ID, h, s, amp)) == s
        for s in (-2, -1, 0, 1, 2))
    check("TREE-CORRECT", tree_ok,
          "decision tree recovers every s value from formula bits")

    # Verify the formula against the real oracle on every h' the tree
    # will use, for the first coefficient.
    queries = [0]  # query counter in a list so nested fn can mutate it
    oracle_bits = {}

    def oracle(k_idx, h):
        """Lab PC oracle: K-PKE.Decrypt of the crafted ciphertext, bit k."""
        ct, _ = _crafted_ct(PARAMS_ID, k_idx, h)
        queries[0] += 1
        m_prime = mlkem.kpke_decrypt(dk_pke, ct, PARAMS_ID)
        bits = mlkem.byte_decode(1, m_prime)
        return bits[k_idx], ct

    formula_ok = True
    for h in (5, 14, 11, 2):
        bit, _ = oracle(0, h)
        if bit != _predicted_bit(PARAMS_ID, h, s_true[0], amp):
            formula_ok = False
    check("FORMULA-AGREES", formula_ok,
          "Appendix A formula matches oracle bits at h' in {5,14,11,2}")

    def recover(k_idx):
        return tree_with(lambda h: oracle(k_idx, h)[0])

    queries[0] = 0
    recovered = []
    for idx in range(N_COEFFS):
        recovered.append(recover(idx))
    correct = sum(1 for a, b in zip(recovered, s_true[:N_COEFFS]) if a == b)
    q_per_coeff = queries[0] / float(N_COEFFS)
    # Entropy of the eta=2 CBD coefficient distribution:
    # P(0)=6/16, P(+/-1)=4/16, P(+/-2)=1/16.
    entropy = -((6.0 / 16) * math.log2(6.0 / 16)
                + 2 * (4.0 / 16) * math.log2(4.0 / 16)
                + 2 * (1.0 / 16) * math.log2(1.0 / 16))
    q_per_bit = q_per_coeff / entropy
    print("  recovered %d/%d coefficients of s_0 correctly"
          % (correct, N_COEFFS))
    print("  total oracle queries: %d" % queries[0])
    print("  measured queries per coefficient: %.4f" % q_per_coeff)
    print("  [ESTIMASI] Huffman bound: %.4f bits/coefficient "
          "(eta=2 CBD entropy); measured queries per bit: %.4f"
          % (entropy, q_per_bit))
    print("  [ESTIMASI] full-key extrapolation: %d secret coefficients "
          "(k*n = %d) at %.4f queries/coefficient ~= %.0f queries for a "
          "full static key, before lattice post-processing"
          % (k * 256, k * 256, q_per_coeff, k * 256 * q_per_coeff))
    check("RECOVER-16", correct == N_COEFFS,
          "%d/%d coefficients" % (correct, N_COEFFS))
    check("QUERIES-BOUND", q_per_coeff < 3.0,
          "%.4f queries/coefficient (Huffman bound %.4f bits)" % (q_per_coeff, entropy))

    # --- CCA level: same crafted ciphertexts through full decaps -------
    cca_checked = 0
    cca_rejected_exact = 0
    sample = []
    for k_idx in range(2):
        for h in (5, 14, 11, 2):
            ct, _ = _crafted_ct(PARAMS_ID, k_idx, h)
            sample.append(ct)
    for ct in sample:
        got = mlkem.decaps_internal(dk, ct, PARAMS_ID)
        expected_kbar = mlkem._j(z_key + ct)
        cca_checked += 1
        if got == expected_kbar:
            cca_rejected_exact += 1
    print("  [FAKTA] CCA level: %d/%d crafted ciphertexts return exactly "
          "Kbar = J(z||c) from full decaps (FO rejects all of them)"
          % (cca_rejected_exact, cca_checked))
    check("CCA-NO-PC-ORACLE", cca_rejected_exact == cca_checked,
          "bare decaps API does not supply the plaintext-checking oracle")
    print("  [ANALISIS] static vs ephemeral: this probe needs %d queries "
          "against ONE key; a static key is exposed to cumulative "
          "leakage, an ephemeral key (fresh per session) is not"
          % queries[0])

    print()
    if failures:
        print("KEY_MISMATCH VERDICT: FAIL -- %s" % ", ".join(failures))
        return 1
    print("KEY_MISMATCH VERDICT: PASS -- %d coefficients recovered at "
          "%.4f queries/coefficient (%.4f queries/bit vs %.4f-bit Huffman "
          "bound); CCA decaps rejects all crafted ciphertexts"
          % (N_COEFFS, q_per_coeff, q_per_bit, entropy))
    return 0


if __name__ == "__main__":
    sys.exit(main())
