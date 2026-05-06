import json
import hashlib
import binascii
import cbor2
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.encoding import RawEncoder

# CBOR tag 258 is the registered "set" tag used by Cardano (Conway era)
# for inputs, collateral inputs, certificates, required signers, reference
# inputs, and proposal procedures. We sort the contents and wrap them in
# this tag to canonicalize the body before hashing.
CARDANO_SET_TAG = 258


def _ordered_set(items):
    return cbor2.CBORTag(CARDANO_SET_TAG, sorted(items))

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
    sk_bytes = bytes.fromhex(skey)
    msg_bytes = bytes.fromhex(msg)
    signing_key = SigningKey(sk_bytes)
    sig = signing_key.sign(msg_bytes, encoder=RawEncoder).signature.hex()
    return sig


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
    vk_bytes = bytes.fromhex(vkey)
    sig_bytes = bytes.fromhex(signature)
    msg_bytes = bytes.fromhex(msg)

    verify_key = VerifyKey(vk_bytes, encoder=RawEncoder)
    try:
        verify_key.verify(msg_bytes, sig_bytes, encoder=RawEncoder)
        return True
    except BadSignatureError:
        return False


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

    # Canonicalize every set-typed body field by sorting and re-wrapping in
    # CBOR tag 258. The hash will not match what the node computes otherwise.
    SET_FIELDS = (
        0,   # inputs
        4,   # certificates (optional)
        13,  # collateral inputs
        14,  # required signers
        18,  # reference inputs (optional)
        20,  # proposal procedures (optional)
    )
    for idx in SET_FIELDS:
        if idx in tx_body:
            tx_body[idx] = _ordered_set(tx_body[idx])

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

def witness_tx_cbor(tx_cbor: str, skey_path: str, vkey_path: str) -> str:
    """
    Create the witness CBOR given the tx CBOR, the skey, and the vkey paths.

    Args:
        tx_cbor (str): The transaction CBOR from the API.
        skey_path (str): The secret key path.
        vkey_path (str): The verification key path.

    Returns:
        witness_cbor (str): The CBOR of a valid witness
    """
    # get the keys
    sk = get_key_from_file(skey_path)
    pk = get_key_from_file(vkey_path)
    # get the hash
    tx_hash = tx_id(tx_cbor)
    # sign and create the witness
    sig = sign(sk, tx_hash)
    return create_witness_cbor(pk, sig)
