"""
core/crypto
-----------
Post-quantum cryptographic operations for Coldwire.

Implements:
- Key generation (ML-KEM-1024,  ML-DSA-87, Classic-McEliece-8192128f)
- Signature creation and verification
- One-Time Pad (OTP) encryption with padding
- Retrieving shared secrets from KEM chunks
- Secure random number generation
- OTP padding 
"""

import oqs
import secrets
from core.constants import (
    OTP_PAD_SIZE,
    OTP_MAX_RANDOM_PAD,
    OTP_SIZE_LENGTH,
    OTP_MAX_BUCKET,
    ML_KEM_1024_NAME,
    ML_KEM_1024_SK_LEN,
    ML_KEM_1024_PK_LEN,
    ML_DSA_87_NAME,
    ML_DSA_87_SK_LEN,
    ML_DSA_87_PK_LEN,
    ML_DSA_87_SIGN_LEN,
    ALGOS_BUFFER_LIMITS
)


def create_signature(algorithm: str, message: bytes, private_key: bytes) -> bytes:
    """
    Creates a digital signature for a message using a post-quantum signature scheme.

    Args:
        algorithm: PQ signature algorithm (e.g. "ML-DSA-87").
        message: Data to sign.
        private_key: Private key bytes.

    Returns:
        Signature bytes of fixed size defined by the algorithm.
    """
    with oqs.Signature(algorithm, secret_key = private_key[:ALGOS_BUFFER_LIMITS[algorithm]["SK_LEN"]]) as signer:
        return signer.sign(message)

def verify_signature(algorithm: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verifies a post-quantum signature.

    Args:
        algorithm: PQ signature algorithm (e.g. "ML-DSA-87").
        message: Original message data.
        signature: Signature to verify.
        public_key: Corresponding public key bytes.

    Returns:
        True if valid, False if invalid.
    """
    with oqs.Signature(algorithm) as verifier:
        return verifier.verify(message, signature[:ALGOS_BUFFER_LIMITS[algorithm]["SIGN_LEN"]], public_key[:ALGOS_BUFFER_LIMITS[algorithm]["PK_LEN"]])

def generate_sign_keys(algorithm: str = ML_DSA_87_NAME) -> tuple[bytes, bytes]:
    """
    Generates a new post-quantum signature keypair.

    Args:
        algorithm: PQ signature algorithm (default ML-DSA-87).

    Returns:
        (private_key, public_key) as bytes.
    """
    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return private_key, public_key

def otp_encrypt_with_padding(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts plaintext using a one-time pad with random or bucket padding.

    Process:
    - Prefixes length of message.
    - Adds random padding (0..padding_limit bytes) if message > 64 bytes
    - If 64 bytes > message, pad message up to 64 bytes, 
    - XORs with one-time pad key.

    Args:
        plaintext: Data to encrypt.
        key: OTP key (>= plaintext length + padding).

    Returns:
        Ciphertext bytes.
    """

    if len(plaintext) <= OTP_MAX_BUCKET - OTP_SIZE_LENGTH:
        pad_len = OTP_MAX_BUCKET - OTP_SIZE_LENGTH - len(plaintext)
    else:
        pad_len = secrets.randbelow(OTP_MAX_RANDOM_PAD + 1)
    
    padding = secrets.token_bytes(pad_len)

    plaintext_length_bytes = len(plaintext).to_bytes(OTP_SIZE_LENGTH, "big")

    padded_plaintext = plaintext_length_bytes + plaintext + padding

    if len(padded_plaintext) > len(key):
        raise ValueError("Padded plaintext is larger than key!")

    return one_time_pad(padded_plaintext, key)

def otp_decrypt_with_padding(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts one-time pad ciphertext that contains prefixed plaintext length.

    Args:
        ciphertext: Ciphertext bytes.
        key: OTP key (>= ciphertext length).

    Returns:
        Original plaintext bytes without padding.
    """
    plaintext_with_padding, _ = one_time_pad(ciphertext, key)

    plaintext_length = int.from_bytes(plaintext_with_padding[:OTP_SIZE_LENGTH], "big")

    if plaintext_length <= 0:
        raise ValueError(f"{plaintext_length} plaintext length, ciphertext corrupted or invalid key!")

    return plaintext_with_padding[OTP_SIZE_LENGTH : OTP_SIZE_LENGTH + plaintext_length]


def one_time_pad(plaintext: bytes, key: bytes) -> bytes:
    """
    XOR-based One-Time Pad encryption/decryption.

    Args:
        plaintext: Input data.
        key: Random key (equal or longer length).

    Returns:
        XORed result (ciphertext or plaintext).
    """
    otpd_plaintext = b''
    for index, plain_byte in enumerate(plaintext):
        key_byte = key[index]
        otpd_plaintext += bytes([plain_byte ^ key_byte])

    key = key[len(otpd_plaintext):]
    return otpd_plaintext, key

def generate_kem_keys(algorithm: str) -> tuple[bytes, bytes]:
    """
    Generates a KEM keypair.

    Args:
        algorithm: PQ KEM algorithm.

    Returns:
        (private_key, public_key) as bytes.
    """
    with oqs.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return private_key, public_key

def encap_shared_secret(public_key: bytes, algorithm: str) -> tuple[bytes, bytes]:
    """
    Derive a KEM shared secret from a public key.

    Args:
        public_key: KEM public key.
        algorithm: KEM algorithm NIST name.

    Returns:
        (KEM ciphertext, shared secret) as bytes.
    """
 
    with oqs.KeyEncapsulation(algorithm) as kem:
        return kem.encap_secret(public_key[:ALGOS_BUFFER_LIMITS[algorithm]["PK_LEN"]])
 
def decap_shared_secret(ciphertext: bytes, private_key: bytes, algorithm: str) -> bytes:
    """
    Decrypts a single KEM ciphertext to derive a shared secret.

    Args:
        ciphertext: KEM ciphertext.
        private_key: KEM private key.
        algorithm: KEM algorithm NIST name.
        size: Desired shared_secret size in bytes.

    Returns:
        Shared secret of size as bytes.
    """
    with oqs.KeyEncapsulation(algorithm, secret_key = private_key[:ALGOS_BUFFER_LIMITS[algorithm]["SK_LEN"]]) as kem:
        return kem.decap_secret(ciphertext[:ALGOS_BUFFER_LIMITS[algorithm]["CT_LEN"]])

def decrypt_shared_secrets(ciphertext_blob: bytes, private_key: bytes, algorithm: str = None, size: int = OTP_PAD_SIZE):
    """
    Decrypts concatenated KEM ciphertexts to derive shared secret.

    Args:
        ciphertext_blob: Concatenated KEM ciphertexts.
        private_key: KEM private key.
        algorithm: KEM algorithm NIST name.
        size: Desired OTP pad size in bytes.

    Returns:
        Shared secret OTP pad bytes.
    """
    cipher_size    = ALGOS_BUFFER_LIMITS[algorithm]["CT_LEN"]  # KEM ciphertext size
    shared_secrets = b''
    cursor         = 0

    with oqs.KeyEncapsulation(algorithm, secret_key=private_key[:ALGOS_BUFFER_LIMITS[algorithm]["SK_LEN"]]) as kem:
        while len(shared_secrets) < size:
            ciphertext = ciphertext_blob[cursor:cursor + cipher_size]
            if len(ciphertext) != cipher_size:
                 raise ValueError(f"Ciphertext of {algorithm} blob is malformed or incomplete ({len(ciphertext)})")

            shared_secret = kem.decap_secret(ciphertext)
            shared_secrets += shared_secret
            cursor += cipher_size

    return shared_secrets #[:otp_pad_size]

def generate_shared_secrets(public_key: bytes, algorithm: str = None, size: int = OTP_PAD_SIZE) -> tuple[bytes, bytes]:
    """
    Generates many shared secrets via `algorithm` encapsulation in chunks.

    Args:
        public_key: Recipient's KEM public key.
        algorithm: KEM algorithm NIST name.
        size: Desired shared secrets size in bytes.

    Returns:
        (ciphertexts_blob, shared_secrets) as bytes.
    """
    shared_secrets   = b''
    ciphertexts_blob = b''

    with oqs.KeyEncapsulation(algorithm) as kem:
        while len(shared_secrets) < size:
            ciphertext, shared_secret = kem.encap_secret(public_key[:ALGOS_BUFFER_LIMITS[algorithm]["PK_LEN"]])
            ciphertexts_blob += ciphertext
            shared_secrets   += shared_secret

    return ciphertexts_blob, shared_secrets # [:otp_pad_size]

def random_number_range(a: int, b: int) -> int:
    """
    Generates a secure random integer in [a, b].

    Args:
        a: Minimum value.
        b: Maximum value.

    Returns:
        Secure random integer between a and b inclusive.
    """
    return secrets.randbelow(b - a + 1) + a
