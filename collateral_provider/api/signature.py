# This will allow a CLI key to sign data. The CLI key is a cbor encoded Ed25519
# key. So to use verify_ed25519_signature we need to do the math on the decoded
# cbor value. This is fine since python has the ecdsa module that does it for us.
#
# ECDSA in multiplicative form (Blake et al. Elliptic Curves in Cryptography - I.1.4):
#
# g is the generator for ed25519
#
# x is the secret key, sk in the code
# g^x = h, h is the verification key, vk in the code
# m is the public msg, msg in the code
#
# k is a random integer
#
# Signing:
#
# a = g^k
#
# b = (m + a * x) * k^(-1)
#
# Signature is (a, b)
#
# Verify (a, b):
#
# g^(m * b^(-1)) * h^(a * b^(-1)) ?= a
#
# This is why we pass in msg, sig, and vkey in the verify_ed25519_signature function.
#
# Proof:
# g^(m * b^(-1)) * h^(a * b^(-1)) = g^(m * b^(-1)) * g^(x * a * b^(-1)) = g^[(m + a * x)*b^(-1)] = g^(k * b^(-1) * b) = g^k = a
#

import json
import hashlib
import binascii
import cbor2
from ecdsa import (
    Ed25519,
    SigningKey,
    VerifyingKey,
)  # This module is vulnerable to side-channel attacks
from pycardano.serialization import (
    OrderedSet,
)

def get_key_from_file(file_path: str) -> str:
    """
    Reads a key from a JSON file and returns the hexadecimal key value.

    Args:
        file_path (str): The path to the JSON file containing the key.

    Returns:
        str: The 'cborHex' value (hexadecimal string) found in the JSON file,
             with the first 4 characters removed.
    """
    # Open the JSON file and load its contents
    with open(file_path, "r") as file:
        data = json.load(file)

    # Return the 'cborHex' value, starting from the 5th character
    # the first 4 is the cbor encoding
    return data.get("cborHex")[4:]


def sign(skey: str, msg: str) -> str:
    """
    Signs a message using a private key and returns the signature.

    Args:
        skey (str): The private key (signing key) in hexadecimal format.
        msg (str): The message to be signed in hexadecimal format.

    Returns:
        str: The generated signature in hexadecimal format.
    """
    # Convert the private key and message from hex to bytes
    sk_string = bytes.fromhex(skey)
    sk = SigningKey.from_string(sk_string, curve=Ed25519)
    msg = bytes.fromhex(msg)

    # Sign the message using the private key and return the signature in hex
    signature = sk.sign(msg)
    return signature.hex()


def verify(vkey: str, signature: str, msg: str) -> bool:
    """
    Verifies a signature using a public key and the message.

    Args:
        vkey (str): The public key (verifying key) in hexadecimal format.
        signature (str): The signature to verify in hexadecimal format.
        msg (str): The message that was signed in hexadecimal format.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    # Convert the public key, signature, and message from hex to bytes
    vk_string = bytes.fromhex(vkey)
    vk = VerifyingKey.from_string(vk_string, curve=Ed25519)
    signature = bytes.fromhex(signature)
    msg = bytes.fromhex(msg)

    # Verify if the signature matches the message using the public key
    return vk.verify(signature, msg)


def tx_id(tx_cbor: str) -> str:
    """
    Performs the Blake2b-256 hash on a tx body.

    Args:
        tx_cbor (str): The transaction CBOR from the API.

    Returns:
        tx_hash (str): The transaction hash in hexadecimal format.
    """
    tx_bytes = bytes.fromhex(tx_cbor)
    tx = cbor2.loads(tx_bytes)
    tx_body = tx[0]

    # we need to reorder the things that are sets

    # inputs
    tx_body[0] = OrderedSet(sorted(tx_body[0]), use_tag=True).to_primitive()
    # this may not exist
    try:
        # certificates
        tx_body[4] = OrderedSet(sorted(tx_body[4]), use_tag=True).to_primitive()
    except KeyError:
        pass
    # collateral inputs
    tx_body[13] = OrderedSet(sorted(tx_body[13]), use_tag=True).to_primitive()
    # required signers
    tx_body[14] = OrderedSet(sorted(tx_body[14]), use_tag=True).to_primitive()
    # this may not exist
    try:
        # reference inputs
        tx_body[18] = OrderedSet(sorted(tx_body[18]), use_tag=True).to_primitive()
    except KeyError:
        pass
    # this may not exist
    try:
        # proposal_procedures
        tx_body[20] = OrderedSet(sorted(tx_body[20]), use_tag=True).to_primitive()
    except KeyError:
        pass

    # all the sets are taken place so now we can dump it and hash it
    tx_body_cbor = cbor2.dumps(tx_body).hex()
    return hashlib.blake2b(binascii.unhexlify(tx_body_cbor), digest_size=32).hexdigest()


def create_witness_cbor(public_key: str, signature: str) -> str:
    """
    Creates a valid witness to a transaction in CBOR.

    Args:
        public_key (str): The public key in hexadecimal format.
        signature (str): The signature to verify in hexadecimal format.

    Returns:
        witness_cbor (str): The CBOR of a valid witness
    """
    return cbor2.dumps(
        [0, [binascii.unhexlify(public_key), binascii.unhexlify(signature)]]
    ).hex()

def witness_tx_cbor(tx_cbor: str, skey_path: str, vkey_path) -> str:
    """
    Create the witness CBOR given the tx CBOR, the skey, and the vkey paths.

    Args:
        tx_cbor (str): The transaction CBOR from the API.
        skey_path (str): The CLI secret key path.
        vkey_path (str): The CLI verification key path.

    Returns:
        witness_cbor (str): The CBOR of a valid witness
    """
    # get the keys
    sk = get_key_from_file(skey_path)
    pk = get_key_from_file(vkey_path)
    # get the has
    tx_hash = tx_id(tx_cbor)
    # sign and create the witness
    sig = sign(sk, tx_hash)
    return create_witness_cbor(pk, sig)
