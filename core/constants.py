# app metadata
APP_NAME      = "Coldwire"
APP_VERSION   = "0.1"

# hard-coded filepaths 
ACCOUNT_FILE_PATH = "account.coldwire"

# Coldwire protocol misc (bytes)
SMP_TYPE = b"\x00"
PFS_TYPE = b"\x01"
MSG_TYPE = b"\x02"

COLDWIRE_DATA_SEP   = b"\0"
COLDWIRE_LEN_OFFSET = 3

# network defaults (seconds & bytes)
LONGPOLL_MIN  = 5
LONGPOLL_MAX  = 30  

# crypto parameters (bytes)
CHALLENGE_LEN     = 11264

OTP_PAD_SIZE        = 11264
OTP_MAX_BUCKET      = 64
OTP_MAX_RANDOM_PAD  = 16 
OTP_SIZE_LENGTH     = 2
OTP_MAX_MESSAGE_LEN = OTP_PAD_SIZE - OTP_SIZE_LENGTH

XCHACHA20POLY1305_NONCE_LEN      = 24
XCHACHA20POLY1305_SIZE_LEN       = 3
XCHACHA20POLY1305_MAX_RANODM_PAD = OTP_PAD_SIZE



SMP_NONCE_LENGTH      = 64
SMP_PROOF_LENGTH      = 64
SMP_ANSWER_OUTPUT_LEN = 64
SMP_QUESTION_MAX_LEN  = 512

KEYS_HASH_CHAIN_LEN    = 64
MESSAGE_HASH_CHAIN_LEN = 64

    

# NIST-specified key sizes (bytes) and metadata
ML_KEM_1024_NAME   = "ML-KEM-1024"
ML_KEM_1024_SK_LEN = 3168
ML_KEM_1024_PK_LEN = 1568
ML_KEM_1024_CT_LEN = 1568


ML_DSA_87_NAME     = "ML-DSA-87"  
ML_DSA_87_SK_LEN   = 4896
ML_DSA_87_PK_LEN   = 2592
ML_DSA_87_SIGN_LEN = 4627


CLASSIC_MCELIECE_8_F_NAME      = "Classic-McEliece-8192128f"
CLASSIC_MCELIECE_8_F_SK_LEN    = 14120
CLASSIC_MCELIECE_8_F_PK_LEN    = 1357824 
CLASSIC_MCELIECE_8_F_CT_LEN    = 208 

CLASSIC_MCELIECE_8_F_ROTATE_AT = 3   # Default OTP batches needed to be sent for a key rotation to occur



ALGOS_BUFFER_LIMITS   = {
    ML_KEM_1024_NAME: {
        "SK_LEN": ML_KEM_1024_SK_LEN,
        "PK_LEN": ML_KEM_1024_PK_LEN,
        "CT_LEN": ML_KEM_1024_CT_LEN 
    },
    ML_DSA_87_NAME: {
        "SK_LEN"  : ML_DSA_87_SK_LEN,
        "PK_LEN"  : ML_DSA_87_PK_LEN,
        "SIGN_LEN": ML_DSA_87_SIGN_LEN
    },
    CLASSIC_MCELIECE_8_F_NAME: {
        "SK_LEN": CLASSIC_MCELIECE_8_F_SK_LEN,
        "PK_LEN": CLASSIC_MCELIECE_8_F_PK_LEN,
        "CT_LEN": CLASSIC_MCELIECE_8_F_CT_LEN
    },
}

# hash parameters
ARGON2_MEMORY      = 256 * 1024   # MB
ARGON2_ITERS       = 3
ARGON2_OUTPUT_LEN  = 32           # bytes
ARGON2_SALT_LEN    = 16           # bytes (Must be always 16 for interoperability with implementations using libsodium.)
ARGON2_LANES       = 4
