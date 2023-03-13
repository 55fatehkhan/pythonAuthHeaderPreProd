from distutils.log import debug
from operator import truediv
from sys import api_version
from flask import Flask, jsonify, request
from pip import main
import base64
import datetime
import os
import re
import json
import requests
import fire as fire
import nacl.encoding
from flask import *
import nacl.hash
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
from nacl.signing import SigningKey, VerifyKey

f = open(os.getenv("REQUEST_BODY_PATH", "./request_body.json"))
request_body_json = json.load(f)
datass = json.dumps(request_body_json)

app = Flask(__name__)


# @app.route("/")
# def hello_world():
#     return "<p>Hello, World!</p>"


def hash_message(msg: str):
    HASHER = nacl.hash.blake2b
    digest = HASHER(bytes(msg, 'utf-8'), digest_size=64, encoder=nacl.encoding.Base64Encoder)
    digest_str = digest.decode("utf-8")
    print("Digest String:    " + digest_str)
    return digest_str


# hashh = hash_message(datass)


def create_signing_string(digest_base64, created=None, expires=None):
    if created is None:
        created = int(datetime.datetime.now().timestamp())
    if expires is None:
        expires = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())

    signing_string = f"""(created): {created}
(expires): {expires}
digest: BLAKE-512={digest_base64}"""
    print("SigningString:    ", signing_string)
    return signing_string


# create_signing_string(hashh)


def sign_response(signing_key, private_key):
    private_key64 = base64.b64decode(
        "4YgiOzDzlQfWv2JRnUBv0Rw5OlW3pB8nAmKFeyMWFCtBoVDZef2sXazaCukprRUARgVBClrLPIZ51aH26seB8w==")
    seed = crypto_sign_ed25519_sk_to_seed(private_key64)
    signer = SigningKey(seed)
    signed = signer.sign(bytes(signing_key, encoding='utf8'))
    signature = base64.b64encode(signed.signature).decode()
    # print("Signature:    " + signature)
    return signature


# sign_response()


def verify_response(signature, signing_key, public_key):
    try:
        public_key64 = base64.b64decode("QaFQ2Xn9rF2s2grpKa0VAEYFQQpayzyGedWh9urHgfM=")
        VerifyKey(public_key64).verify(bytes(signing_key, 'utf8'), base64.b64decode(signature))
        return True
    except Exception:
        return False


# verify_response()


@app.route('/generateHeader', methods=['POST'])
def create_authorisation_header(request_body=datass,
                                created= None,
                                expires= None):
    request_body = request.data.decode('UTF-8')
    if created is None:
        created = int(datetime.datetime.now().timestamp())
    if expires is None:
        expires = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())
    # print("RequestBody Passing:   ", request_body)
    signing_key = create_signing_string(hash_message(json.dumps(request_body, separators=(',', ':'))),
                                        created=created, expires=expires)
    signature = sign_response(signing_key, os.getenv(
        "4YgiOzDzlQfWv2JRnUBv0Rw5OlW3pB8nAmKFeyMWFCtBoVDZef2sXazaCukprRUARgVBClrLPIZ51aH26seB8w=="))
    print("Signature:  ", signature)
    verifyResponse = verify_response(signature, signing_key, "QaFQ2Xn9rF2s2grpKa0VAEYFQQpayzyGedWh9urHgfM=")
    print("Verify Response:  ", verifyResponse)

    subscriber_id = os.getenv("SUBSCRIBER_ID", "api.greenreceipt.in")
    unique_key_id = os.getenv("UNIQUE_KEY_ID", "28843C15-9764-4245-92CF-7D236B855711")
    header = f'Signature keyId="{subscriber_id}|{unique_key_id}|ed25519",algorithm="ed25519",created=' \
             f'"{created}",expires="{expires}",headers="(created) (expires) digest",signature="{signature}"'
    print("AuthHeader:   ", header)
    return header


# create_authorisation_header()

if __name__ == '__main__':
    app.run(debug=True, port=9920)
