#!/usr/bin/env python3
"""Deliberately NEUTERED ML-KEM decapsulation -- FO check removed.

[ANALISIS] This module exists ONLY so the pack can prove it catches the
invisible failure class of IACR ePrint 2025 "Verifiable Decapsulation":
the re-encryption check is essential for security but not for
functionality, so a missing check goes unnoticed by correctness tests.
`decaps_neutered` returns G(m' || h) unconditionally, i.e. it returns
the shared secret for ANY ciphertext that decrypts to a message, even
one that fails re-encryption. It must never be used outside
scripts/missing_fo_check.py. Everything else is imported from mlkem.py.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem


def decaps_neutered(dk, c, params_id):
    """Decapsulation with the Algorithm 18 re-encryption check REMOVED.

    Steps 1-3 of Algorithm 18 only: decrypt, derive (K', r') = G(m' || h),
    return K' without ever computing c' or comparing it to c.
    """
    p = mlkem.PARAMS[params_id]
    k = p["k"]
    dk_pke = dk[:384 * k]
    h = dk[768 * k + 32:768 * k + 64]
    m_prime = mlkem.kpke_decrypt(dk_pke, c, params_id)
    k_prime, _r_prime = mlkem._g(m_prime + h)
    return k_prime
