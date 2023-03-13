#ignore this file (for authHeader only refer main.py file) Thanks.
import base64
import datetime
import os
import re
import json

import fire as fire
import nacl.encoding
import nacl.hash
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
from nacl.signing import SigningKey, VerifyKey

f = open(os.getenv("REQUEST_BODY_PATH", "./request_body.json"))
request_body_json = json.load(f)
datass = json.dumps(request_body_json)


def hash_message(msg: str):
    HASHER = nacl.hash.blake2b
    digest = HASHER(bytes(msg, 'utf-8'), digest_size=64, encoder=nacl.encoding.Base64Encoder)
    digest_str = digest.decode("utf-8")
    print("Digest String    " + digest_str)
    return digest_str


hashh = hash_message(datass)


def create_signing_string(digest_base64, created=None, expires=None):
    if created is None:
        created = int(datetime.datetime.now().timestamp())
    if expires is None:
        expires = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())

    signing_string = f"""(created): {created}
(expires): {expires}
digest: BLAKE-512={digest_base64}"""
    print("SigningString: ", signing_string)
    return signing_string


create_signing_string(hashh)


def sign_response(signing_key, private_key):
    private_key64 = base64.b64decode(
        "1H7dM0+PiHDhJ6Y0vzwrb2rLaJdLnWxhAqpxyAR/7rIkr947GszlkX45+kqZWfBPArV/AjprBHMXIcWUFQCcIw==")
    seed = crypto_sign_ed25519_sk_to_seed(private_key64)
    signer = SigningKey(seed)
    signed = signer.sign(bytes(
        "(created): 1664518005 (expires): 1664521605 digest: BLAKE-512=1EbRgq5f9hXV+BzfnW1Z9D2PQLVj9vruRdx5mPjhgXepTZEeDGugcZwGskUjNxEv0rt0tuVomPsThLe5e2/b6w==",
        encoding='utf8'))
    signature = base64.b64encode(signed.signature).decode()
    print("Signature    " + signature)
    return signature


# sign_response()


def verify_response():
    try:
        public_key64 = base64.b64decode("JK/eOxrM5ZF+OfpKmVnwTwK1fwI6awRzFyHFlBUAnCM=")
        VerifyKey(public_key64).verify(bytes("JK/eOxrM5ZF+OfpKmVnwTwK1fwI6awRzFyHFlBUAnCM=", 'utf8'), base64.b64decode(
            "QvNir0KID9QShJ5QEvvScnjcf3bK+1JlJ/h7BCPlGyOWnGbHWhxsWEQuWoHNNj+PMtRzbG5s+eS3k7SWdADqCA=="))
        print("verified")
        return True
    except Exception:
        return False


verify_response()


def create_authorisation_header(request_body=datass,
                                created=os.getenv("CREATED", "1641287875"),
                                expires=os.getenv("EXPIRES", "1641291475")):
    signing_key = create_signing_string(hash_message(json.dumps(request_body, separators=(',', ':'))),
                                        created=created, expires=expires)
    signature = sign_response(signing_key, os.getenv(
        "1H7dM0+PiHDhJ6Y0vzwrb2rLaJdLnWxhAqpxyAR/7rIkr947GszlkX45+kqZWfBPArV/AjprBHMXIcWUFQCcIw=="))

    subscriber_id = os.getenv("SUBSCRIBER_ID", "bybest.in")
    unique_key_id = os.getenv("UNIQUE_KEY_ID", "355")
    header = f'Signature keyId="{subscriber_id}|{unique_key_id}|ed25519",algorithm="ed25519",created=' \
             f'"{created}",expires="{expires}",headers="(created) (expires) digest",signature="{signature}"'
    print(header)
    return header


create_authorisation_header()



