from core.requests import http_request
from logic.smp import smp_unanswered_questions, smp_data_handler
from logic.pfs import pfs_data_handler, update_ephemeral_keys
from logic.message import messages_data_handler
from core.constants import (
    LONGPOLL_MIN,
    LONGPOLL_MAX,
    COLDWIRE_LEN_OFFSET,
    SMP_TYPE,
    PFS_TYPE,
    MSG_TYPE,
    XCHACHA20POLY1305_NONCE_LEN
)
from core.crypto import random_number_range
from core.trad_crypto import (
        decrypt_xchacha20poly1305
)
from base64 import b64decode
import copy
import logging

logger = logging.getLogger(__name__)


def decode_blob_stream(data: bytes) -> list:
    messages = []

    offset = 0
    while offset < len(data):
        if offset + COLDWIRE_LEN_OFFSET > len(data):
            raise ValueError("Incomplete length prefix, malformed or corrupted data.")

        msg_len = int.from_bytes(data[offset : offset + COLDWIRE_LEN_OFFSET], "big")
        offset += COLDWIRE_LEN_OFFSET
        if offset + msg_len > len(data):
            raise ValueError("Incomplete message data")

        messages.append(data[offset:offset + msg_len])
        offset += msg_len
    return messages


def parse_blobs(blobs: list[bytes]) -> dict:
    parsed_messages = []

    for raw in blobs:
        try:
            sender, blob = raw.split(b"\0", 1)
            sender = sender.decode("utf-8")
            parsed_messages.append({
                "sender": sender,
                "blob": blob
                })
        except ValueError as e:
            logger.error("Invalid message format! Error: %s", str(e))
            continue

    return parsed_messages

def background_worker(user_data, user_data_lock, ui_queue, stop_flag):
    # Incase we received a SMP question request last time right before the background worker was about to exit
    smp_unanswered_questions(user_data, user_data_lock, ui_queue)

    while not stop_flag.is_set():
        with user_data_lock:
            server_url = user_data["server_url"]
            auth_token = user_data["token"]
    
        try:
            # Random longpoll number to help obfsucate traffic against analysis
            response = http_request(
                    f"{server_url}/data/longpoll", 
                    "GET", 
                    auth_token = auth_token, 
                    longpoll = random_number_range(LONGPOLL_MIN, LONGPOLL_MAX)
                )
        except TimeoutError:
            logger.debug("Data longpoll request has timed out, retrying...")
            continue

        data = decode_blob_stream(response)
        data = parse_blobs(data)


        for message in data:
            logger.debug("Received data: %s", str(message)[:3000])

            # Sanity check universal message fields
            if (not "sender" in message):
                logger.error("Impossible condition, either you have discovered a bug in Coldwire, or the server is attempting to denial-of-service you. Skipping data message with no sender...")
                continue

            if message["sender"].isdigit() and len(message["sender"]) != 16:
                logger.error("Impossible condition, either you have discovered a bug in Coldwire, or the server is attempting to denial-of-service you. Skipping data message with malformed same-server sender (%s)...", message["sender"])
                continue
        
            if (not message["sender"].isdigit()): 
                split = message["sender"].split("@")
                if (len(split) != 2) or (not split[0].isdigit()):
                    logger.error("Impossible condition, either you have discovered a bug in Coldwire, or the server is attempting to denial-of-service you. Skipping data message with malformed federated-server sender (%s)...", message["sender"])
                    continue

            sender = message["sender"]
            blob   = message["blob"]

            with user_data_lock:
                user_data_copied = copy.deepcopy(user_data)

            # Everything from here is not validated by server

            blob_plaintext = None
            
            if sender in user_data_copied["contacts"]: 
                chacha_key = user_data["contacts"][sender]["lt_sign_key_smp"]["tmp_key"]
                contact_next_strand_nonce = user_data["contacts"][sender]["contact_next_strand_nonce"]

                if chacha_key is not None:
                    chacha_key  = b64decode(user_data["contacts"][sender]["lt_sign_key_smp"]["tmp_key"])

                    try:
                        try:
                            blob_plaintext = decrypt_xchacha20poly1305(chacha_key, blob[:XCHACHA20POLY1305_NONCE_LEN], blob[XCHACHA20POLY1305_NONCE_LEN:])
                        except Exception as e:
                            if contact_next_strand_nonce is None:
                                raise Exception("Unable to decrypt apparent SMP request due to missing contact strand nonce.")

                            logger.debug("Failed to decrypt blob from contact (%s) probably due to invalid nonce: %s, we will try decrypting using strand nonce", sender, str(e))
                            blob_plaintext = decrypt_xchacha20poly1305(chacha_key, contact_next_strand_nonce, blob)

                    except Exception as e:
                        logger.error("Failed to decrypt blob from contact (%s) with error: %s", sender, str(e))
                else:
                    chacha_key = user_data["contacts"][sender]["contact_strand_key"]

                    if (chacha_key is None) and (contact_next_strand_nonce is None):
                        # just assume at this point that it's not encrypted.
                        blob_plaintext = blob
                    else:
                        # Under known laws of physics, this should never fail. Unless the contact is acting funny on purpose / invalid implementation of Coldwire + strandlock protocol.
                        try:
                            blob_plaintext = decrypt_xchacha20poly1305(chacha_key, contact_next_strand_nonce, blob)
                        except Exception as e:
                            logger.error(
                                    "Failed to decrypt blob from contact (%s)"
                                    "We dont know what caused this except maybe a re-SMP verification. error: %s", sender, str(e)
                                )
                            blob_plaintext = blob
            else:
                logger.debug("Contact (%s) not saved.. we just gonna assume blob_plaintext = blob", sender)
                blob_plaintext = blob


            # SMP
            if bytes([blob_plaintext[0]]) == SMP_TYPE:
                smp_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, sender, blob_plaintext[1:])

            # PFS
            elif bytes([blob_plaintext[0]]) == PFS_TYPE:
                pfs_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, sender, blob_plaintext[1:])
            
            # MSG
            elif bytes([blob_plaintext[0]]) == MSG_TYPE:
                messages_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, sender, blob_plaintext[1:])

            else:
                logger.error(
                        "Skipping data with unknown data type (%d) from contact (%s)...", 
                        bytes([blob_plaintext[0]]),
                        sender
                    )

        # *Sigh* I had to put this here because if we rotate before finishing reading all of the messages
        # we would overwrite our own key.
        # TODO: We need to keep the last used key and use it when decapsulation with new key gives invalid output
        # because it might actually take some time for our keys to be uploaded to server + other servers, and to the contact.
        #
        update_ephemeral_keys(user_data, user_data_lock)

