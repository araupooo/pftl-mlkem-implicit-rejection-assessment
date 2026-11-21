#!/usr/bin/env python3
"""Clean-room ML-KEM-512/768/1024 from FIPS 203 (August 2024).

[FAKTA] Implements K-PKE (FIPS 203 section 5) wrapped in the Fujisaki-Okamoto
transform (section 6.3, Algorithms 16-18). Parameter sizes (section 8,
Tables 2-3): ML-KEM-512 ek 800 B / dk 1632 B / ct 768 B; ML-KEM-768
1184 / 2400 / 1088; ML-KEM-1024 1568 / 3168 / 1568; shared secret 32 B.
q = 3329, n = 256 in all sets.

Hash wrappers (section 4.1): H(s) = SHA3-256(s); J(s) = SHAKE256(s, 256);
G(s) = SHA3-512(s) split into two 32-byte halves (K, r).

Algorithm 18 (internal decapsulation) runs, deterministically:
  1. parse dk into dkPKE, ek, h = H(ek), z
  2. m' = K-PKE.Decrypt(dkPKE, c)
  3. (K', r') = G(m' || h)
  4. Kbar = J(z || c) -- computed UNCONDITIONALLY
  5. c' = K-PKE.Encrypt(ek, m', r')
  6. if c != c' then K' = Kbar (implicit rejection)
  7. return K'

Python standard library only (hashlib). No randomness anywhere in this
module: every entry point takes its randomness explicitly (d, z, m) so
all outputs are byte-deterministic. Callers that need fresh randomness
must supply it; the analysis scripts use fixed seeds.

The `decaps` / `encaps` wrappers enforce the FIPS 203 section 7.2/7.3
input checks (modulus check on the encapsulation key, length checks,
decapsulation-key hash check). The `*_internal` functions are the raw
Algorithms 17/18 and are exposed for testing only, per section 3.3
("the internal (derandomized) functions should not be made available
to applications other than for testing purposes").

KAT source: the reference implementation's KAT stream is reproduced from
its 48-byte seeds using the NIST AES-256 CTR DRBG (pq-crystals/kyber,
ref/nistkat/rng.c, branch `standard`, commit
d5b791c0c601b543233daccbae2845c6197a9e77). The DRBG needs AES-256, which
is not in the standard library, so a compact AES-256 (FIPS 197) is
implemented below and used ONLY for KAT seed expansion in
scripts/spec_fidelity.py via `kat_drbg_generate`. It is not part of
ML-KEM itself. Verification target: liboqs tests/KATs/kem/kats.json
(commit b6689666b934f56773d43dfdcb14e42d898d7dec, 2026-06-17) `single`
SHA-256 hashes of the kat_kem stdout for ML-KEM-512/768/1024.
"""

import hashlib

Q = 3329
N = 256

# k, eta1, eta2, du, dv per parameter set (FIPS 203 section 8, Table 2).
PARAMS = {
    512: {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
    768: {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
    1024: {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}

EK_LEN = {512: 800, 768: 1184, 1024: 1568}
DK_LEN = {512: 1632, 768: 2400, 1024: 3168}
CT_LEN = {512: 768, 768: 1088, 1024: 1568}


def _bitrev7(i):
    """Reverse the 7-bit representation of i (FIPS 203 section 4.2)."""
    r = 0
    for _ in range(7):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


# ---------------------------------------------------------------- NTT
# Algorithms 9-11 (FIPS 203 section 4.3).

def ntt(f):
    """Algorithm 9: NTT."""
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = pow(17, _bitrev7(i), Q)
            i += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def inv_ntt(f):
    """Algorithm 10: inverse NTT (128^-1 mod q = 3303)."""
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = pow(17, _bitrev7(i), Q)
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]


def _multiply_ntts(f_hat, g_hat):
    """Algorithm 11: base-case multiplication of two NTT-domain polynomials."""
    h = [0] * N
    for i in range(128):
        gamma = pow(17, 2 * _bitrev7(i) + 1, Q)
        f0, f1 = f_hat[2 * i], f_hat[2 * i + 1]
        g0, g1 = g_hat[2 * i], g_hat[2 * i + 1]
        h[2 * i] = (f0 * g0 + f1 * g1 * gamma) % Q
        h[2 * i + 1] = (f0 * g1 + f1 * g0) % Q
    return h


def _mat_vec_ntt(mat, vec):
    """Multiply a k x k matrix of NTT polynomials by a vector of NTT polys."""
    k = len(vec)
    out = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            prod = _multiply_ntts(mat[i][j], vec[j])
            acc = [(a + b) % Q for a, b in zip(acc, prod)]
        out.append(acc)
    return out


def _vec_dot_ntt(a, b):
    """Inner product of two vectors of NTT polynomials."""
    acc = [0] * N
    for x, y in zip(a, b):
        prod = _multiply_ntts(x, y)
        acc = [(p + q_) % Q for p, q_ in zip(acc, prod)]
    return acc


# ------------------------------------------------------- byte encoding
# Algorithms 5-6 (FIPS 203 section 4.2).

def _modulus(d):
    """FIPS 203 Algorithms 5-6: values live in Z_m with m = 2^d for
    d < 12 and m = q for d = 12."""
    return Q if d == 12 else (1 << d)


def byte_encode(d, f):
    """Algorithm 5: encode 256 coefficients of d bits each, LSB-first."""
    m = _modulus(d)
    out = bytearray(32 * d)
    acc = 0
    nbits = 0
    idx = 0
    for coeff in f:
        acc |= (coeff % m) << nbits
        nbits += d
        while nbits >= 8:
            out[idx] = acc & 0xFF
            idx += 1
            acc >>= 8
            nbits -= 8
    if nbits:
        out[idx] = acc & 0xFF
    return bytes(out)


def byte_decode(d, data):
    """Algorithm 6: decode bytes into 256 coefficients; for d = 12 the
    result is reduced mod q, which is exactly what makes the FIPS 203
    section 7.2 modulus check detect unreduced coefficients."""
    if len(data) != 32 * d:
        raise ValueError("byte_decode: expected %d bytes, got %d" % (32 * d, len(data)))
    m = _modulus(d)
    f = []
    acc = 0
    nbits = 0
    idx = 0
    for _ in range(N):
        while nbits < d:
            acc |= data[idx] << nbits
            idx += 1
            nbits += 8
        f.append((acc & ((1 << d) - 1)) % m)
        acc >>= d
        nbits -= d
    return f


# ------------------------------------------------- compression / sampling
# Algorithms 3, 7, 8 (FIPS 203 sections 4.2, 4.3).

def compress(d, x):
    """Compress_d(x) = round(2^d / q * x) mod 2^d, for x in [0, q)."""
    return (((x << d) + Q // 2) // Q) % (1 << d)


def decompress(d, y):
    """Decompress_d(y) = round(q / 2^d * y)."""
    return (Q * y + (1 << (d - 1))) >> d


def sample_ntt(rho, j, i):
    """Algorithm 7: SampleNTT(rho, j, i) via SHAKE128 rejection sampling.

    [FAKTA] The XOF in FIPS 203 section 4.1 is SHAKE128 (PRF uses
    SHAKE256; J uses SHAKE256). Each 3 bytes yield up to 2 candidates;
    acceptance rate 3329/4096.
    """
    stream = hashlib.shake_128(rho + bytes([j, i]))
    got = []
    # shake .digest(n) always returns the first n bytes, so grow the
    # requested length instead of appending repeated prefixes.
    want = 1024
    while len(got) < N:
        buf = stream.digest(want)
        got = []
        for t in range(0, len(buf) - 2, 3):
            if len(got) >= N:
                break
            b0, b1, b2 = buf[t], buf[t + 1], buf[t + 2]
            d1 = b0 + 256 * (b1 % 16)
            d2 = (b1 // 16) + 16 * b2
            if d1 < Q:
                got.append(d1)
            if len(got) < N and d2 < Q:
                got.append(d2)
        want *= 2
    return got


def sample_poly_cbd(eta, buf):
    """Algorithm 8: SamplePolyCBD_eta from 64*eta bytes."""
    if len(buf) != 64 * eta:
        raise ValueError("sample_poly_cbd: expected %d bytes" % (64 * eta))
    f = []
    for i in range(N):
        x = 0
        y = 0
        for t in range(eta):
            p = 2 * i * eta + t
            x += (buf[p // 8] >> (p % 8)) & 1
            p2 = 2 * i * eta + eta + t
            y += (buf[p2 // 8] >> (p2 % 8)) & 1
        f.append((x - y) % Q)
    return f


# ---------------------------------------------------------------- hashes
# FIPS 203 section 4.1.

def _h(data):
    return hashlib.sha3_256(data).digest()


def _j(data):
    return hashlib.shake_256(data).digest(32)


def _g(data):
    out = hashlib.sha3_512(data).digest()
    return out[:32], out[32:]


def _prf(eta, s, b):
    """PRF_eta(s, b) = SHAKE256(s || b, 8*64*eta bits)."""
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


# ---------------------------------------------------------------- K-PKE
# Algorithms 12-14 (FIPS 203 section 5).

def _sample_matrix(rho, k):
    return [[sample_ntt(rho, j, i) for j in range(k)] for i in range(k)]


def kpke_keygen(d, params_id):
    """Algorithm 12: K-PKE.KeyGen(d). Returns (ek_pke, dk_pke)."""
    p = PARAMS[params_id]
    k = p["k"]
    rho, sigma = _g(d + bytes([k]))
    a_hat = _sample_matrix(rho, k)
    s = []
    e = []
    ctr = 0
    for _ in range(k):
        s.append(sample_poly_cbd(p["eta1"], _prf(p["eta1"], sigma, ctr)))
        ctr += 1
    # [FAKTA] Key generation samples BOTH s and e with eta1 (FIPS 203
    # Algorithm 12; pq-crystals indcpa_keypair_derand calls
    # poly_getnoise_eta1 for e as well). eta2 is used only for the
    # encryption noise e1, e2. The distinction is observable only for
    # ML-KEM-512, where eta1=3 != eta2=2.
    for _ in range(k):
        e.append(sample_poly_cbd(p["eta1"], _prf(p["eta1"], sigma, ctr)))
        ctr += 1
    s_hat = [ntt(x) for x in s]
    e_hat = [ntt(x) for x in e]
    t_hat = _mat_vec_ntt(a_hat, s_hat)
    t_hat = [[(a + b) % Q for a, b in zip(t, ee)] for t, ee in zip(t_hat, e_hat)]
    ek = b"".join(byte_encode(12, t) for t in t_hat) + rho
    dk = b"".join(byte_encode(12, s) for s in s_hat)
    return ek, dk


def kpke_encrypt(ek, m, r, params_id):
    """Algorithm 13: K-PKE.Encrypt(ek, m, r)."""
    p = PARAMS[params_id]
    k = p["k"]
    t_hat = [byte_decode(12, ek[384 * i:384 * (i + 1)]) for i in range(k)]
    rho = ek[384 * k:384 * k + 32]
    y = []
    e1 = []
    ctr = 0
    for _ in range(k):
        y.append(sample_poly_cbd(p["eta1"], _prf(p["eta1"], r, ctr)))
        ctr += 1
    for _ in range(k):
        e1.append(sample_poly_cbd(p["eta2"], _prf(p["eta2"], r, ctr)))
        ctr += 1
    e2 = sample_poly_cbd(p["eta2"], _prf(p["eta2"], r, ctr))
    y_hat = [ntt(x) for x in y]
    mu = [decompress(1, bit) for bit in byte_decode(1, m)]
    a_hat = _sample_matrix(rho, k)
    # u = NTT^-1(A_hat^T . y_hat) + e1
    a_t = [[a_hat[j][i] for j in range(k)] for i in range(k)]
    u = [inv_ntt(x) for x in _mat_vec_ntt(a_t, y_hat)]
    u = [[(a + b) % Q for a, b in zip(uu, ee)] for uu, ee in zip(u, e1)]
    # v = NTT^-1(t_hat^T . y_hat) + e2 + mu
    v = inv_ntt(_vec_dot_ntt(t_hat, y_hat))
    v = [(a + b + c) % Q for a, b, c in zip(v, e2, mu)]
    c1 = b"".join(byte_encode(p["du"], [compress(p["du"], x) for x in uu]) for uu in u)
    c2 = byte_encode(p["dv"], [compress(p["dv"], x) for x in v])
    return c1 + c2


def kpke_decrypt(dk_pke, c, params_id):
    """Algorithm 14: K-PKE.Decrypt(dk_pke, c)."""
    p = PARAMS[params_id]
    k = p["k"]
    du, dv = p["du"], p["dv"]
    c1_len = 32 * du * k
    c1, c2 = c[:c1_len], c[c1_len:]
    s_hat = [byte_decode(12, dk_pke[384 * i:384 * (i + 1)]) for i in range(k)]
    u = [[decompress(du, x) for x in byte_decode(du, c1[32 * du * i:32 * du * (i + 1)])]
         for i in range(k)]
    v = [decompress(dv, x) for x in byte_decode(dv, c2)]
    u_hat = [ntt(x) for x in u]
    w = [0] * N
    prod = inv_ntt(_vec_dot_ntt(s_hat, u_hat))
    w = [(a - b) % Q for a, b in zip(v, prod)]
    return byte_encode(1, [compress(1, x) for x in w])


# ------------------------------------------------------------- ML-KEM
# Algorithms 16-18 (FIPS 203 section 6).

def keygen(d, z, params_id):
    """Algorithm 16: ML-KEM.KeyGen_internal(d, z). Returns (ek, dk)."""
    p = PARAMS[params_id]
    k = p["k"]
    ek_pke, dk_pke = kpke_keygen(d, params_id)
    ek = ek_pke
    dk = dk_pke + ek + _h(ek) + z
    assert len(ek) == EK_LEN[params_id] and len(dk) == DK_LEN[params_id]
    return ek, dk


def encaps_internal(ek, m, params_id):
    """Algorithm 17: ML-KEM.Encaps_internal(ek, m). Returns (K, c)."""
    k_prime, r = _g(m + _h(ek))
    c = kpke_encrypt(ek, m, r, params_id)
    return k_prime, c


def decaps_internal(dk, c, params_id):
    """Algorithm 18: ML-KEM.Decaps_internal(dk, c).

    Computes Kbar = J(z || c) unconditionally, re-encrypts, and returns
    Kbar on any mismatch. Never signals failure.
    """
    p = PARAMS[params_id]
    k = p["k"]
    dk_pke = dk[:384 * k]
    ek = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m_prime = kpke_decrypt(dk_pke, c, params_id)
    k_prime, r_prime = _g(m_prime + h)
    k_bar = _j(z + c)
    c_prime = kpke_encrypt(ek, m_prime, r_prime, params_id)
    if c != c_prime:
        k_prime = k_bar
    return k_prime


# ------------------------------------------- section 7.2 / 7.3 checks

def check_encaps_key(ek, params_id):
    """FIPS 203 section 7.2 modulus check.

    [FAKTA] Encaps shall not run with an encapsulation key that has not
    been checked: test = ByteEncode12(ByteDecode12(ek[0:384k]))
    == ek[0:384k]. Returns True iff the check passes.
    """
    p = PARAMS[params_id]
    k = p["k"]
    if len(ek) != EK_LEN[params_id]:
        return False
    # The section 7.2 test applies per polynomial of the t_hat vector:
    # ByteEncode12(ByteDecode12(.)) must reproduce each 384-byte chunk.
    for i in range(k):
        chunk = ek[384 * i:384 * (i + 1)]
        if byte_encode(12, byte_decode(12, chunk)) != chunk:
            return False
    return True


def check_decaps_key(dk, params_id):
    """FIPS 203 section 7.3 hash check.

    [FAKTA] Decaps shall not run with a decapsulation key unless checked:
    test = H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64].
    Returns True iff length and hash checks pass.
    """
    p = PARAMS[params_id]
    k = p["k"]
    if len(dk) != DK_LEN[params_id]:
        return False
    ek = dk[384 * k:768 * k + 32]
    stored = dk[768 * k + 32:768 * k + 64]
    return _h(ek) == stored


def encaps(ek, m, params_id):
    """Checked ML-KEM.Encaps_internal: raises on an unchecked/bad ek."""
    if not check_encaps_key(ek, params_id):
        raise ValueError("encaps: encapsulation key fails section 7.2 modulus check")
    return encaps_internal(ek, m, params_id)


def decaps(dk, c, params_id):
    """Checked ML-KEM.Decaps_internal: raises on bad lengths / bad dk hash."""
    if len(c) != CT_LEN[params_id]:
        raise ValueError("decaps: ciphertext length %d, expected %d"
                         % (len(c), CT_LEN[params_id]))
    if not check_decaps_key(dk, params_id):
        raise ValueError("decaps: decapsulation key fails section 7.3 hash check")
    return decaps_internal(dk, c, params_id)


# --------------------------------------- NIST KAT DRBG (seed expansion)
# The KAT stream (pq-crystals/kyber ref/nistkat) derives every test
# vector from a 48-byte seed via the NIST AES-256 CTR DRBG in rng.c.
# AES-256 (FIPS 197) is implemented here in pure Python because the
# standard library has no AES; it is used ONLY to expand KAT seeds.

_SBOX = []
_INV_SBOX = []


def _build_sboxes():
    # Generate the AES S-box by GF(2^8) inversion + affine transform.
    def gf_mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
            b >>= 1
        return r

    def gf_inv(a):
        if a == 0:
            return 0
        for x in range(1, 256):
            if gf_mul(a, x) == 1:
                return x
        raise AssertionError("no inverse")

    def rotl8(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xFF

    for a in range(256):
        inv = gf_inv(a)
        s = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
        _SBOX.append(s & 0xFF)
    for i, s in enumerate(_SBOX):
        _INV_SBOX.append(0)
    for i, s in enumerate(_SBOX):
        _INV_SBOX[s] = i


_build_sboxes()

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _aes256_expand_key(key):
    """Expand a 32-byte key into 15 round keys of 16 bytes (FIPS 197)."""
    assert len(key) == 32
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(8)]
    for i in range(8, 60):
        temp = list(w[i - 1])
        if i % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 8 - 1]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([a ^ b for a, b in zip(w[i - 8], temp)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(15)]


def _aes256_ecb_encrypt_block(round_keys, block):
    """Encrypt one 16-byte block under the expanded key."""
    def gf_mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
            b >>= 1
        return r

    s = [[block[4 * c + r] for c in range(4)] for r in range(4)]

    def add_round_key(rnd):
        rk = round_keys[rnd]
        for r in range(4):
            for c in range(4):
                s[r][c] ^= rk[4 * c + r]

    def sub_bytes():
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]

    def shift_rows():
        for r in range(4):
            row = [s[r][(c + r) % 4] for c in range(4)]
            for c in range(4):
                s[r][c] = row[c]

    def mix_columns():
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3)
            s[3][c] = gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2)

    add_round_key(0)
    for rnd in range(1, 14):
        sub_bytes()
        shift_rows()
        mix_columns()
        add_round_key(rnd)
    sub_bytes()
    shift_rows()
    add_round_key(14)
    return bytes(s[r][c] for c in range(4) for r in range(4))


class KatDRBG:
    """NIST AES-256 CTR DRBG exactly as in pq-crystals/kyber ref/nistkat/rng.c.

    randombytes_init(seed48): Key=0, V=0, then AES256_CTR_DRBG_Update(seed).
    randombytes(n): increment V, AES-ECB blocks, then Update(NULL).
    """

    def __init__(self, entropy48):
        assert len(entropy48) == 48
        self.key = bytes(32)
        self.v = bytes(16)
        self._update(entropy48)

    def _update(self, provided_data):
        temp = b""
        v = bytearray(self.v)
        rk = _aes256_expand_key(self.key)
        for _ in range(3):
            for j in range(15, -1, -1):
                if v[j] == 0xFF:
                    v[j] = 0x00
                else:
                    v[j] += 1
                    break
            temp += _aes256_ecb_encrypt_block(rk, bytes(v))
        if provided_data is not None:
            temp = bytes(a ^ b for a, b in zip(temp, provided_data))
        self.key = temp[:32]
        self.v = temp[32:48]

    def randombytes(self, n):
        out = bytearray()
        v = bytearray(self.v)
        rk = _aes256_expand_key(self.key)
        remaining = n
        while remaining > 0:
            for j in range(15, -1, -1):
                if v[j] == 0xFF:
                    v[j] = 0x00
                else:
                    v[j] += 1
                    break
            block = _aes256_ecb_encrypt_block(rk, bytes(v))
            take = min(16, remaining)
            out += block[:take]
            remaining -= take
        self.v = bytes(v)
        self._update(None)
        return bytes(out)


def kat_seed_stream(count):
    """Reproduce the KAT request-file seeds: entropy 0..47, then `count`
    successive randombytes(48) outputs (PQCgenKAT_kem.c)."""
    drbg = KatDRBG(bytes(range(48)))
    return [drbg.randombytes(48) for _ in range(count)]


def kat_vector(seed48, params_id):
    """Full KAT vector for one 48-byte seed: randombytes_init(seed), then
    keypair consumes ONE randombytes(64) call for coins = d || z
    (crypto_kem_keypair_derand takes 2*KYBER_SYMBYTES coins), and
    encaps consumes m = randombytes(32). Returns (seed, pk, sk, ct, ss)."""
    drbg = KatDRBG(seed48)
    coins = drbg.randombytes(64)
    d, z = coins[:32], coins[32:]
    ek, dk = keygen(d, z, params_id)
    m = drbg.randombytes(32)
    k_shared, c = encaps_internal(ek, m, params_id)
    return seed48, ek, dk, c, k_shared
