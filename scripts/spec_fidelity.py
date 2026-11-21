#!/usr/bin/env python3
"""Check 1 -- spec fidelity: KAT verification, accept + reject paths.

[FAKTA] Verifies the clean-room implementation in mlkem.py byte-exactly
against the NIST reference-implementation KAT stream
(pq-crystals/kyber, branch `standard`, commit
d5b791c0c601b543233daccbae2845c6197a9e77), vendored as
data/PQCkemKAT_{512,768,1024}.rsp (100 vectors per parameter set,
generated locally from that reference code with its PQCgenKAT_kem
generator; SHA-256 recorded in docs/SOURCES.md). Cross-checks:
  (a) every vendored vector: decaps_internal(sk, ct) == ss (accept path);
  (b) every vendored vector, two mutated ciphertexts (first byte, last
      byte): decaps_internal(sk, ct') == J(z || ct') exactly, != ss
      (reject path, Algorithm 18 step 4/6);
  (c) liboqs tests/KATs/kem/kats.json `single` (count 0) and `all`
      (100 counts) SHA-256 hashes of the kat_kem stdout, recomputed from
      the same 48-byte seeds via mlkem.kat_vector.
Deterministic: fixed vendored vectors and fixed seeds; no randomness,
no timestamps, no network.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# liboqs tests/KATs/kem/kats.json, commit b6689666b934f56773d43dfdcb14e42d898d7dec.
LIBOQS_KATS = {
    512: {"single": "c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782",
          "all": "74b470e797cbdbd589a31d387d36c72aad5033446ab5159bf4014c24652b1173"},
    768: {"single": "5352539586b6c3df58be6158a6250aeff402bd73060b0a3de68850ac074c17c3",
          "all": "e5d6911117c708d8342702db222f66bef5ac5b0314fb8bc36eb22a536c9b34fb"},
    1024: {"single": "f580d851e5fb27e6876e5e203fa18be4cdbfd49e05d48fec3d3992c8f43a13e6",
           "all": "81d1ae0468f62154885b6f2a293c0eb48f9339645357a88bbbc186c57ab0ace0"},
}


def parse_rsp(path):
    """Parse a PQCkemKAT .rsp file into a list of dicts."""
    vectors = []
    with open(path) as fh:
        text = fh.read()
    for block in text.split("\n\n"):
        entry = {}
        for line in block.strip().splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                entry[key.strip()] = val.strip()
        if "seed" in entry:
            vectors.append(entry)
    return vectors


def kat_stdout_block(count, seed, ek, dk, c, ss):
    """One kat_kem stdout block (uppercase hex, as liboqs prints it)."""
    hx = lambda b: b.hex().upper()
    return ("count = %d\nseed = %s\npk = %s\nsk = %s\nct = %s\nss = %s\n"
            % (count, hx(seed), hx(ek), hx(dk), hx(c), hx(ss)))


def main():
    failures = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name
              + ((" -- " + detail) if detail else ""))
        if not cond:
            failures.append(name)

    print("== spec_fidelity: ML-KEM KAT verification (accept + reject) ==")
    print("[FAKTA] KAT source: pq-crystals/kyber `standard` @ "
          "d5b791c0c601b543233daccbae2845c6197a9e77, vendored data/*.rsp")

    for params_id in (512, 768, 1024):
        p = mlkem.PARAMS[params_id]
        k = p["k"]
        vectors = parse_rsp(os.path.join(ROOT, "data",
                                         "PQCkemKAT_%d.rsp" % params_id))
        print("-- ML-KEM-%d: %d vectors --" % (params_id, len(vectors)))
        check("KAT-COUNT-%d" % params_id, len(vectors) == 100,
              "%d vectors" % len(vectors))

        accept_ok = 0
        reject_ok = 0
        reject_checked = 0
        blocks = []
        for idx, vec in enumerate(vectors):
            seed = bytes.fromhex(vec["seed"])
            ek = bytes.fromhex(vec["pk"])
            dk = bytes.fromhex(vec["sk"])
            ct = bytes.fromhex(vec["ct"])
            ss = bytes.fromhex(vec["ss"])
            z = dk[768 * k + 64:768 * k + 96]
            # (a) accept path: decaps of the genuine ciphertext == ss.
            if mlkem.decaps_internal(dk, ct, params_id) == ss:
                accept_ok += 1
            # (b) reject path: two mutated ciphertexts must yield exactly
            #     Kbar = J(z || ct'), and never ss.
            for pos in (0, len(ct) - 1):
                mutated = bytearray(ct)
                mutated[pos] ^= 0x01
                mutated = bytes(mutated)
                expected_kbar = mlkem._j(z + mutated)
                got = mlkem.decaps_internal(dk, mutated, params_id)
                reject_checked += 1
                if got == expected_kbar and got != ss:
                    reject_ok += 1
            # (c) regenerate the vector from its seed for the hash check.
            rseed, rek, rdk, rct, rss = mlkem.kat_vector(seed, params_id)
            if not (rek == ek and rdk == dk and rct == ct and rss == ss):
                failures.append("KAT-REGEN-%d-%d" % (params_id, idx))
            blocks.append(kat_stdout_block(idx, rseed, rek, rdk, rct, rss))
        check("ACCEPT-%d" % params_id, accept_ok == len(vectors),
              "%d/%d decaps == ss" % (accept_ok, len(vectors)))
        check("REJECT-%d" % params_id, reject_ok == reject_checked,
              "%d/%d mutated decaps == J(z||c') exactly, != ss"
              % (reject_ok, reject_checked))
        single = hashlib.sha256(blocks[0].encode()).hexdigest()
        check("LIBOQS-SINGLE-%d" % params_id,
              single == LIBOQS_KATS[params_id]["single"],
              "sha256=%s" % single)
        all_hash = hashlib.sha256("\n".join(blocks).encode()).hexdigest()
        check("LIBOQS-ALL-%d" % params_id,
              all_hash == LIBOQS_KATS[params_id]["all"],
              "sha256=%s" % all_hash)

    print()
    if failures:
        print("SPEC_FIDELITY VERDICT: FAIL -- %d failing check(s): %s"
              % (len(failures), ", ".join(failures)))
        return 1
    print("SPEC_FIDELITY VERDICT: PASS -- accept + reject paths byte-exact "
          "for 100 vectors x 3 parameter sets; liboqs single+all hashes match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
