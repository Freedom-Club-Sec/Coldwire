"""
    logic/smp.py
    ----------
    The socialist millionaire problem
    A variant of Yao's millionaire problem

    Guaranteed verification certainity IF the answer has enough entropy (for the duration of the process.)

    This is not **strictly** a SMP implementation, but it is a simplified, human-language variant
    we made for verifying a contact's long-term public-key.

"""

from core.requests import http_request
from logic.storage import save_account_data
from logic.contacts import save_contact
from logic.pfs import send_new_ephemeral_keys
from core.crypto import (
        generate_sign_keys, 
        generate_kem_keys,
        encap_shared_secret,
        decap_shared_secret,
        one_time_pad
)
from core.trad_crypto import (
        derive_key_argon2id, 
        sha3_512,
        encrypt_xchacha20poly1305,
        decrypt_xchacha20poly1305
)
from base64 import b64encode, b64decode
from core.constants import (
        SMP_TYPE,
        SMP_NONCE_LENGTH,
        SMP_PROOF_LENGTH,
        SMP_QUESTION_MAX_LEN,
        SMP_ANSWER_OUTPUT_LEN,
        ARGON2_SALT_LEN,
        ML_KEM_1024_NAME,
        ML_KEM_1024_CT_LEN,
        ML_DSA_87_PK_LEN,
        XCHACHA20POLY1305_NONCE_LEN
)
import hashlib
import secrets
import hmac
import logging
import json
import threading
import queue


logger = logging.getLogger(__name__)


def normalize_answer(s: str) -> str:
    s = s.strip()

    # lowercase the 1st character
    s = s[0].lower() + s[1:] if s else s

    return s

# This is step 1.
def initiate_smp(user_data: dict, user_data_lock: threading.Lock, contact_id: str, question: str, answer: str) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]
    
    kem_private_key, kem_public_key = generate_kem_keys(ML_KEM_1024_NAME)

    try:
        response = http_request(f"{server_url}/data/send", "POST", metadata = {
            "recipient": contact_id
        }, blob = SMP_TYPE + kem_public_key, auth_token = auth_token)
    except Exception:
        raise ValueError("Could not connect to server")

    response = json.loads(response.decode())
    if (not ("status" in response)) or response["status"] != "success":
        if "error" in response:
            raise ValueError(response["error"][:512])
        raise ValueError("Server sent malformed response")


    answer = normalize_answer(answer)

    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"] = True
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"]             = question
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["answer"]               = answer
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"]             = 3

        user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_kem_keys"]["private_key"] = b64encode(kem_private_key).decode()
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_kem_keys"]["public_key"]  = b64encode(kem_public_key).decode()



    logger.debug("Initiated SMP for %s", contact_id)
    save_account_data(user_data, user_data_lock)



def smp_step_2(user_data: dict, user_data_lock, contact_id: str, blob: bytes, ui_queue: queue.Queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]
        our_id     = user_data["user_id"]

    contact_kem_public_key = blob 

    signing_private_key, signing_public_key = generate_sign_keys()

    our_nonce = sha3_512(secrets.token_bytes(SMP_NONCE_LENGTH))[:SMP_NONCE_LENGTH]

    key_ciphertext, chacha_key = encap_shared_secret(contact_kem_public_key, ML_KEM_1024_NAME)
    chacha_key = sha3_512(chacha_key)[:32]

    our_next_strand_nonce     = sha3_512(secrets.token_bytes(XCHACHA20POLY1305_NONCE_LEN))[:XCHACHA20POLY1305_NONCE_LEN]
    contact_next_strand_nonce = sha3_512(secrets.token_bytes(XCHACHA20POLY1305_NONCE_LEN))[:XCHACHA20POLY1305_NONCE_LEN]


    ciphertext_nonce, ciphertext_blob = encrypt_xchacha20poly1305(
            chacha_key, 
            signing_public_key + our_nonce + our_next_strand_nonce + contact_next_strand_nonce, 
            counter = 2
        )

    try:
        http_request(f"{server_url}/data/send", "POST", metadata = {
                "recipient": contact_id
            }, 
            blob = SMP_TYPE + key_ciphertext + ciphertext_nonce + ciphertext_blob, 
            auth_token = auth_token
        )

    except Exception:
        logger.error("Failed to send proof request to server, either you are offline or the server is down")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return

   
    # We only update after the request is sent successfully
    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"] = True

        user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"] = b64encode(our_nonce).decode()
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["tmp_key"] = b64encode(chacha_key).decode()

        user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_kem_public_key"] = b64encode(blob).decode()
        
        user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"] = signing_private_key
        user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["public_key"]  = signing_public_key

        user_data["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] = 4
        
        user_data["contacts"][contact_id]["our_next_strand_nonce"]     = our_next_strand_nonce
        user_data["contacts"][contact_id]["contact_next_strand_nonce"] = contact_next_strand_nonce


def smp_step_3(user_data: dict, user_data_lock: threading.Lock, contact_id: str, blob: bytes, ui_queue: queue.Queue()) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]
        our_id     = user_data["user_id"]
        
        question = user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"]
        answer = user_data["contacts"][contact_id]["lt_sign_key_smp"]["answer"]

        our_kem_private_key = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_kem_keys"]["private_key"])

    key_ciphertext = blob[:ML_KEM_1024_CT_LEN]

    chacha_key = decap_shared_secret(key_ciphertext, our_kem_private_key, ML_KEM_1024_NAME)

    chacha_key = sha3_512(chacha_key)[:32]

    smp_plaintext = decrypt_xchacha20poly1305(
            chacha_key, 
            blob[ML_KEM_1024_CT_LEN : ML_KEM_1024_CT_LEN + XCHACHA20POLY1305_NONCE_LEN],
            blob[ML_KEM_1024_CT_LEN + XCHACHA20POLY1305_NONCE_LEN:]
        )

    contact_signing_public_key = smp_plaintext[:ML_DSA_87_PK_LEN]
    contact_nonce              = smp_plaintext[ML_DSA_87_PK_LEN: ML_DSA_87_PK_LEN + SMP_NONCE_LENGTH]

    contact_next_strand_nonce  = smp_plaintext[ML_DSA_87_PK_LEN + SMP_NONCE_LENGTH: ML_DSA_87_PK_LEN + SMP_NONCE_LENGTH + XCHACHA20POLY1305_NONCE_LEN]
    our_next_strand_nonce      = smp_plaintext[ML_DSA_87_PK_LEN + SMP_NONCE_LENGTH + XCHACHA20POLY1305_NONCE_LEN:]

    our_nonce = sha3_512(secrets.token_bytes(SMP_NONCE_LENGTH))[:SMP_NONCE_LENGTH]

    signing_private_key, signing_public_key = generate_sign_keys()

    contact_key_fingerprint = sha3_512(contact_signing_public_key)

    # Derive a high-entropy secret key from the low-entropy answer
    argon2id_salt = sha3_512(contact_nonce + our_nonce)[:ARGON2_SALT_LEN]
    answer_secret, _ = derive_key_argon2id(answer.encode("utf-8"), salt = argon2id_salt, output_length = SMP_ANSWER_OUTPUT_LEN)

    # Compute our proof
    our_proof = contact_nonce + our_nonce + contact_key_fingerprint
    our_proof = hmac.new(answer_secret, our_proof, hashlib.sha3_512).digest()

    logger.debug("Our proof of contact (%s) public-key fingerprint: %s", contact_id, our_proof)

    
    our_new_strand_nonce = sha3_512(secrets.token_bytes(XCHACHA20POLY1305_NONCE_LEN))[:XCHACHA20POLY1305_NONCE_LEN]
    _, ciphertext_blob = encrypt_xchacha20poly1305(
            chacha_key, 
            SMP_TYPE + our_new_strand_nonce + signing_public_key + our_nonce + our_proof + question.encode("utf-8"),
            nonce = our_next_strand_nonce
        )


    try:
       http_request(f"{server_url}/data/send", "POST", metadata = {
                "recipient": contact_id
            }, 
            blob = ciphertext_blob, 
            auth_token = auth_token
        )
    except Exception:
        logger.error("Failed to send proof request to server, either you are offline or the server is down")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return

   
    # We only update after the request is sent successfully
    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"] = contact_signing_public_key

        user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"] = b64encode(contact_nonce).decode() 
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"]     = b64encode(our_nonce).decode()
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["tmp_key"]       = b64encode(chacha_key).decode()

        user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"] = signing_private_key
        user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["public_key"]  = signing_public_key

        user_data["contacts"][contact_id]["our_next_strand_nonce"]     = our_new_strand_nonce
        user_data["contacts"][contact_id]["contact_next_strand_nonce"] = contact_next_strand_nonce


        user_data["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] = 5


def smp_step_4_request_answer(user_data, user_data_lock, contact_id, smp_plaintext, ui_queue) -> None:
    with user_data_lock:
        our_nonce = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"])


    contact_new_strand_nonce = smp_plaintext[:XCHACHA20POLY1305_NONCE_LEN]
    
    contact_signing_public_key = smp_plaintext[XCHACHA20POLY1305_NONCE_LEN : ML_DSA_87_PK_LEN + XCHACHA20POLY1305_NONCE_LEN]

    contact_nonce = b64encode(smp_plaintext[XCHACHA20POLY1305_NONCE_LEN + ML_DSA_87_PK_LEN : SMP_NONCE_LENGTH + ML_DSA_87_PK_LEN + XCHACHA20POLY1305_NONCE_LEN]).decode()

    contact_proof = b64encode(smp_plaintext[XCHACHA20POLY1305_NONCE_LEN + SMP_NONCE_LENGTH + ML_DSA_87_PK_LEN : SMP_NONCE_LENGTH + SMP_PROOF_LENGTH + ML_DSA_87_PK_LEN + XCHACHA20POLY1305_NONCE_LEN]).decode()

    question      = smp_plaintext[SMP_NONCE_LENGTH + XCHACHA20POLY1305_NONCE_LEN + SMP_PROOF_LENGTH + ML_DSA_87_PK_LEN:].decode("utf-8")

    if our_nonce == contact_nonce:
        logger.warning("SMP Verification failed at step 4: Contact nonce is the same as our nonce!")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return



    with user_data_lock: 
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"] = question
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["tmp_proof"] = contact_proof

        user_data["contacts"][contact_id]["contact_next_strand_nonce"] = contact_new_strand_nonce

        user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"] = contact_nonce
        
        user_data["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"] = contact_signing_public_key


    ui_queue.put({
        "type": "smp_question",
        "contact_id": contact_id,
        "question": question
    })


def smp_step_4_answer_provided(user_data, user_data_lock, contact_id, answer, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

        contact_signing_public_key = user_data["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]
        contact_kem_public_key     = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_kem_public_key"], validate = True)

        contact_nonce = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"], validate=True)
        contact_proof = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["tmp_proof"], validate=True)
        our_nonce     = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"], validate=True)

        our_signing_public_key = user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["public_key"]

        our_next_strand_nonce = user_data["contacts"][contact_id]["our_next_strand_nonce"]

        tmp_key = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["tmp_key"])

    answer = normalize_answer(answer)

    our_key_fingerprint = sha3_512(our_signing_public_key)

    # Derive a high-entropy secret key from the low-entropy answer
    argon2id_salt = sha3_512(our_nonce + contact_nonce)[:ARGON2_SALT_LEN]
    answer_secret, _ = derive_key_argon2id(answer.encode("utf-8"), salt = argon2id_salt, output_length = SMP_ANSWER_OUTPUT_LEN)

    # Compute our proof
    our_proof = our_nonce + contact_nonce + our_key_fingerprint
    our_proof = hmac.new(answer_secret, our_proof, hashlib.sha3_512).digest()

    logger.debug("SMP Proof sent to us: %s", contact_proof)
    logger.debug("Our compute message: %s", our_proof)


    # Verify Contact's version of our public-key fingerprint matches our actual public-key fingerprint
    # We compare using compare_digest to prevent timing analysis by avoiding content-based short circuiting behaviour
    if not hmac.compare_digest(our_proof, contact_proof):
        logger.warning("SMP Verification failed at step 4")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return


    # We compute proof for contact's public key (signing public key, and the kem public key)
    contact_key_fingerprint = sha3_512(contact_signing_public_key + contact_kem_public_key)

    our_proof = contact_nonce + our_nonce + contact_key_fingerprint
    our_proof = hmac.new(answer_secret, our_proof, hashlib.sha3_512).digest()


    our_strand_key     = sha3_512(secrets.token_bytes(32))[:32]
    contact_strand_key = sha3_512(secrets.token_bytes(32))[:32]

    our_new_strand_nonce = sha3_512(secrets.token_bytes(XCHACHA20POLY1305_NONCE_LEN))[:XCHACHA20POLY1305_NONCE_LEN]
    _, ciphertext_blob = encrypt_xchacha20poly1305(
            tmp_key, 
            SMP_TYPE + our_new_strand_nonce + our_proof + our_strand_key + contact_strand_key,
            nonce = our_next_strand_nonce
        )


    try:
        http_request(f"{server_url}/data/send", "POST", metadata = {
                "recipient": contact_id
            }, 
            blob = ciphertext_blob, 
            auth_token = auth_token
        )
    except Exception:
        logger.error("Failed to send proof request to server, either you are offline or the server is down")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return


    our_strand_key, _     = one_time_pad(sha3_512(answer_secret)[:32], our_strand_key)
    contact_strand_key, _ = one_time_pad(sha3_512(answer_secret)[:32], contact_strand_key)


    # We call smp_success at very end to ensure if the requests step fail, we don't alter our local state
    smp_success(user_data, user_data_lock, contact_id, ui_queue)

    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["answer"] = answer

        user_data["contacts"][contact_id]["our_next_strand_nonce"]     = our_new_strand_nonce

        user_data["contacts"][contact_id]["our_strand_key"]     = our_strand_key
        user_data["contacts"][contact_id]["contact_strand_key"] = contact_strand_key



def smp_step_5(user_data, user_data_lock, contact_id, smp_plaintext, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

        answer = user_data["contacts"][contact_id]["lt_sign_key_smp"]["answer"]

        our_signing_public_key = user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["public_key"]
        our_kem_public_key     = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_kem_keys"]["public_key"])

        our_nonce          = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"], validate=True)
        contact_nonce      = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"], validate=True)



    our_key_fingerprint = sha3_512(our_signing_public_key + our_kem_public_key)

    # Derive a high-entropy secret key from the low-entropy answer
    argon2id_salt = sha3_512(contact_nonce + our_nonce)[:ARGON2_SALT_LEN]
    answer_secret, _ = derive_key_argon2id(answer.encode("utf-8"), salt = argon2id_salt, output_length = SMP_ANSWER_OUTPUT_LEN)

    # Compute the proof
    our_proof = our_nonce + contact_nonce + our_key_fingerprint
    our_proof = hmac.new(answer_secret, our_proof, hashlib.sha3_512).digest()

    
    contact_new_strand_nonce = smp_plaintext[:XCHACHA20POLY1305_NONCE_LEN]

    contact_proof = smp_plaintext[XCHACHA20POLY1305_NONCE_LEN : SMP_PROOF_LENGTH + XCHACHA20POLY1305_NONCE_LEN]

    contact_strand_key = smp_plaintext[XCHACHA20POLY1305_NONCE_LEN + SMP_PROOF_LENGTH : XCHACHA20POLY1305_NONCE_LEN + SMP_PROOF_LENGTH + 32]
    our_strand_key     = smp_plaintext[XCHACHA20POLY1305_NONCE_LEN + SMP_PROOF_LENGTH + 32:] 

    logger.debug("SMP Proof sent to us: %s", contact_proof)
    logger.debug("Our compute message: %s", our_proof)



    # Verify Contact's version of our public-key fingerprint matches our actual public-key fingerprint
    if not hmac.compare_digest(our_proof, contact_proof):
        logger.warning("SMP Verification failed at step 5")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return


    our_strand_key, _     = one_time_pad(sha3_512(answer_secret)[:32], our_strand_key)
    contact_strand_key, _ = one_time_pad(sha3_512(answer_secret)[:32], contact_strand_key)

    with user_data_lock:
        user_data["contacts"][contact_id]["contact_next_strand_nonce"] = contact_new_strand_nonce

        user_data["contacts"][contact_id]["our_strand_key"]     = our_strand_key
        user_data["contacts"][contact_id]["contact_strand_key"] = contact_strand_key




    # We call smp_success at very end to ensure if the requests step fail, we don't alter our local state
    smp_success(user_data, user_data_lock, contact_id, ui_queue)


    # Attempt to automatically exchanger per-contact and ephemeral keys
    # We only attempt here and not inside of smp_success because we don't want both contact's attempting to exchange keys at the same time
    # cuz contact likely still hasnt verified us yet.. (ik its confuysing but just pretend u understand)
    #

    send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)


def smp_success(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"] = {
                "verified": True,
                "pending_verification": False,
                "question": None,
                "answer": None,
                "our_nonce": None,
                "contact_nonce": None,
                "smp_step": None,
                "tmp_proof": None,
                "tmp_key": None,
                "contact_kem_public_key": None,
                "our_kem_keys": {
                    "private_key": None,
                    "public_key": None
                }
        }


    # :32 to ensure no weird visual effects or even bufferoverflows can be exploited in underlying tkinter.
    ui_queue.put({"type": "showinfo",  "title": "Success", "message": f"Successfully verified contact ({contact_id[:32]})!"})


def smp_failure(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"] = {
                "verified": False,
                "pending_verification": False,
                "question": None,
                "answer": None,
                "our_nonce": None,
                "contact_nonce": None,
                "smp_step": None,
                "tmp_proof": None,
                "tmp_key": None,
                "contact_kem_public_key": None,
                "our_kem_keys": {
                    "private_key": None,
                    "public_key": None
                }
        }

    ui_queue.put({"type": "showerror", "title": "Error", "message": "Verification has failed! Please re-try."})


def smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

        tmp_key = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["tmp_key"])

    smp_failure(user_data, user_data_lock, contact_id, ui_queue)

    # it can be any number other than 2, we chose 7 because failure is *technically* the 7th smp step.
    ciphertext_nonce, ciphertext_blob = encrypt_xchacha20poly1305(
            tmp_key, 
            SMP_TYPE + b"failure", 
            counter = 7
        )
    try:
        http_request(f"{server_url}/data/send", "POST", metadata = {
                "recipient": contact_id
            }, 
            blob = ciphertext_nonce + ciphertext_blob, 
            auth_token = auth_token
        )
    except Exception as e:
        logger.error("Failed to send SMP failure to contact (%s), either you are offline or the server is down. Error: %s", contact_id, str(e))
        pass
  


def smp_unanswered_questions(user_data, user_data_lock, ui_queue):
    with user_data_lock:
        for contact_id in user_data["contacts"]:
            if user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"] and user_data["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] == 2:
                logger.info("We had an unanswered question from contact (%s)", contact_id)
                ui_queue.put({
                    "type": "smp_question",
                    "contact_id": contact_id,
                    "question": user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"]
                })


def smp_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, contact_id, message):

    try:
        smp_step = user_data["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"]
        if smp_step is None:
            raise Exception()
    except Exception:
        smp_step = 2



    
    if message == b"failure":
        # Delete SMP state for contact
        smp_failure(user_data, user_data_lock, contact_id, ui_queue)
        return
    

    # Check if we don't have this contact saved
    if contact_id not in user_data_copied["contacts"]:
        # We assume it has to be step 1 because the contact did not exist before
        if smp_step != 2:
            logger.error("Unknown contact sent SMP request of step (%d)", smp_step)
            return

        logger.info("We received a new SMP request for a contact (%s) we did not have saved", contact_id)

        # Save them in-memory
        save_contact(user_data, user_data_lock, contact_id)

        # Perform the next SMP step
        smp_step_2(user_data, user_data_lock, contact_id, message, ui_queue)

        logger.debug("Saved new contact: %s", contact_id)

        # Send request to UI to visually add the contact to contact list
        ui_queue.put({
                        "type": "new_contact",
                        "contact_id": contact_id
                     })

    # Same thing as above code, except that we don't fetch nor save the contact here
    # as they're already fetched and saved
    elif smp_step == 2:
        smp_step_2(user_data, user_data_lock, contact_id, message, ui_queue)
        
    elif smp_step == 3:
        if (not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"]): 
            logger.error("Contact (%s) is not pending verification, yet they sent us a SMP request. Ignoring it.", contact_id)
            return

        smp_step_3(user_data, user_data_lock, contact_id, message, ui_queue)
    elif smp_step == 4:
        if (not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"]): 
            logger.error("Contact (%s) is not pending verification, yet they sent us a SMP request. Ignoring it.", contact_id)
            return

        smp_step_4_request_answer(user_data, user_data_lock, contact_id, message, ui_queue)

    elif smp_step == 5:
        if (not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"]): 
            logger.error("Contact (%s) is not pending verification, yet they sent us a SMP request. Ignoring it.", contact_id)
            return

        smp_step_5(user_data, user_data_lock, contact_id, message, ui_queue)

    else:
        logger.error("This is an impossible condition, You may have discovered a bug in Coldwire. Skipping weird SMP step (%d)...", smp_step)
        return

    save_account_data(user_data, user_data_lock)



