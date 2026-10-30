"""Envelope encryption: each label bucket has its own data key (DEK), wrapped by a key-encryption key (KEK).

KEK lives in an HSM in the real build (SoftHSM2 / YubiHSM via PKCS#11). Here a LocalKEK stands in
so the flow is testable; swap it for a PKCS#11 class with the same wrap/unwrap interface.
Chunk ciphertext binds its label as AES-GCM associated data: moving a chunk into another
label's bucket makes decryption fail.
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class LocalKEK:
    def __init__(self, key: bytes | None = None):
        self._k = AESGCM(key or AESGCM.generate_key(256))

    def wrap(self, dek: bytes, key_id: str) -> bytes:
        n = os.urandom(12)
        return n + self._k.encrypt(n, dek, key_id.encode())

    def unwrap(self, blob: bytes, key_id: str) -> bytes:
        return self._k.decrypt(blob[:12], blob[12:], key_id.encode())


class KeyRing:
    def __init__(self, kek):
        self.kek, self.wrapped = kek, {}

    def _dek(self, key_id):
        if key_id not in self.wrapped:
            self.wrapped[key_id] = self.kek.wrap(AESGCM.generate_key(256), key_id)
        return self.kek.unwrap(self.wrapped[key_id], key_id)

    def encrypt(self, key_id: str, plaintext: str) -> bytes:
        n = os.urandom(12)
        return n + AESGCM(self._dek(key_id)).encrypt(n, plaintext.encode(), key_id.encode())

    def decrypt(self, key_id: str, blob: bytes) -> str:
        return AESGCM(self._dek(key_id)).decrypt(blob[:12], blob[12:], key_id.encode()).decode()

    def destroy(self, key_id: str):
        """Crypto-shredding: drop the wrapped DEK and every chunk in that bucket is unrecoverable."""
        self.wrapped.pop(key_id, None)
