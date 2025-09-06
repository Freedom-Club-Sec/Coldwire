"""
    logic/authentication.py
    ----------
    Implements client-side account authentication with the Coldwire server.
    Uses ML-DSA-87 signatures to sign a challenge to verify account ownership.

"""
from base64 import b64encode, b64decode
from core.requests import http_request
from core.crypto import create_signature 
from core.constants import (
        ML_DSA_87_NAME,
        CHALLENGE_LEN
)
import json

def authenticate_account(user_data: dict) -> dict:
    """
    Authenticate an account with the Coldwire server.

    Args:
        user_data (dict): Shared user account state.

    Returns:
        dict with the user_data containing:
            - "user_id" (str): Server-assigned user ID.
            - "token" (str): Session token issued by the server.

    Raises:
        ValueError: If the server cannot be reached, gives malformed responses, or if authentication fails.

    """
    url = user_data["server_url"] 

    private_key = user_data["lt_auth_sign_keys"]["private_key"]
    public_key_encoded = user_data["lt_auth_sign_keys"]["public_key"]
    public_key_encoded = b64encode(public_key_encoded).decode()
    user_id = user_data.get("user_id") or ""

    try:
        response = http_request(url + "/authenticate/init", "POST", metadata = {"public_key": public_key_encoded, "user_id": user_id })
    except Exception:
        if user_data["settings"]["proxy_info"] is not None:
            raise ValueError("Could not connect to server! Are you sure your proxy settings are valid ?")
        else:
            raise ValueError("Could not connect to server! Are you sure the URL is valid ?")
   
    try:
        response = json.loads(response.decode())
    except Exception as e:
        raise ValueError("Error while parsing server JSON response: ")

    if not 'challenge' in response:
        raise ValueError("Server did not give authenticatation challenge! Are you sure this is a Coldwire server ?")

    try:
        challenge = b64decode(response["challenge"], validate=True)
    except Exception:
        raise ValueError("Server gave a malformed challenge! Are you sure this is Coldwire server ?")


    signature = create_signature(ML_DSA_87_NAME, challenge[:CHALLENGE_LEN], private_key)

    try:
        response = http_request(url + "/authenticate/verify", "POST", metadata = {"signature": b64encode(signature).decode(), "challenge": response["challenge"]})
    except Exception:
        raise ValueError("Server gave a malformed response, your account is probably missing from the server")

    response = json.loads(response.decode())

    required_keys = ["status", "user_id", "token"]
    missing = [k for k in required_keys if k not in response]

    if missing:
        raise ValueError("Server gave a malformed response! Are you sure this is Coldwire server ?")

    if response["status"] != "success":
        if "error" in response:
            raise ValueError(response["error"])
        else:
            raise ValueError("Server gave an unknown error")

    user_data["user_id"] = response["user_id"]
    user_data["token"] = response["token"]

    return user_data
    
