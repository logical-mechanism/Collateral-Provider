//! Ed25519 signing, exact-byte transaction hashing, and witness CBOR.
//!
//! Keys are Cardano CLI JSON (`{"cborHex": "..."}`); the leading 4 hex chars
//! are the CBOR byte-string head and are stripped.

use std::collections::HashMap;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use blake2::Blake2bVar;
use digest::{Update, VariableOutput};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::cbor;
use crate::data_files::FileIdentity;

/// Ed25519 key material is a fixed 32 bytes; a Cardano key hash is 28.
const KEY_LEN: usize = 32;
const PKH_LEN: usize = 28;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("key file {0} is not valid Cardano CLI JSON")]
    Format(PathBuf),
    #[error("{0}")]
    Invalid(String),
}

impl KeyError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        KeyError::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    fn invalid(message: &str) -> Self {
        KeyError::Invalid(message.to_string())
    }
}

/// Read a Cardano-CLI-style key file and cache it by
/// `(path, mtime_ns, size, inode)`.
///
/// A key rotation (atomic write of a new skey/vkey) is picked up on the next
/// signing request without restarting the process, even if the replacement
/// preserves or backdates its mtime. The hot-path cost is one `stat` syscall.
/// Concurrent re-reads are serialized so two threads racing to load a
/// freshly-rotated key don't both parse the file.
pub struct KeyCache {
    inner: std::sync::Mutex<
        std::collections::HashMap<PathBuf, (crate::data_files::FileIdentity, String)>,
    >,
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyCache {
    pub fn new() -> Self {
        KeyCache {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// The cache is advisory, so a panic elsewhere must not turn every later
    /// signing request into a poisoned-lock failure.
    fn lock(&self) -> MutexGuard<'_, HashMap<PathBuf, (FileIdentity, String)>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Return the raw key bytes as lowercase hex (`cborHex` minus its 4-char
    /// CBOR byte-string head).
    pub fn get_key_from_file(&self, path: &Path) -> Result<String, KeyError> {
        // Python can check the cache without the lock because a dict read is
        // atomic under the GIL, and re-stats inside the lock to close the
        // race. Here the map read needs the lock regardless, so one stat
        // taken while holding it is both the fast path and the race-free
        // one — the same single syscall on a cache hit.
        let mut cache = self.lock();
        let identity =
            crate::data_files::file_identity(path).map_err(|err| KeyError::io(path, err))?;
        if let Some((cached_identity, value)) = cache.get(path) {
            if *cached_identity == identity {
                return Ok(value.clone());
            }
        }

        let mut file = File::open(path).map_err(|err| KeyError::io(path, err))?;
        // fstat the handle we actually read, not the path: an atomic
        // replacement landing between the two would otherwise cache the new
        // file's identity against the old file's contents, and the stale key
        // would then look fresh forever.
        let opened_identity =
            stat_identity(&file.metadata().map_err(|err| KeyError::io(path, err))?);
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|err| KeyError::io(path, err))?;

        let document: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| KeyError::Format(path.to_path_buf()))?;
        let cbor_hex = document
            .get("cborHex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| KeyError::Format(path.to_path_buf()))?;
        // Skip by characters rather than bytes: the same slice Python's
        // `[4:]` takes, and it cannot split a multi-byte char in a hand-edited
        // file. The value is passed through verbatim — Cardano CLI writes
        // lowercase, and re-casing it would silently change what the
        // known-hosts registry compares against.
        let value: String = cbor_hex.chars().skip(4).collect();

        tracing::debug!(target: "api", "Loaded signing key material from {}", path.display());
        cache.insert(path.to_path_buf(), (opened_identity, value.clone()));
        Ok(value)
    }

    /// Drop the in-memory cache. Test helper.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Verify that the configured signing identity is internally consistent:
    /// 32-byte skey, 32-byte vkey, 28-byte PKH, the vkey derived from the
    /// skey, and the PKH equal to Blake2b-224 of the vkey.
    pub fn validate_key_material(
        &self,
        skey_path: &Path,
        vkey_path: &Path,
        pkh: &str,
    ) -> Result<(), KeyError> {
        let skey = self.get_key_from_file(skey_path)?;
        let vkey = self.get_key_from_file(vkey_path)?;

        let (skey_bytes, vkey_bytes, pkh_bytes) =
            match (hex::decode(&skey), hex::decode(&vkey), hex::decode(pkh)) {
                (Ok(skey_bytes), Ok(vkey_bytes), Ok(pkh_bytes)) => {
                    (skey_bytes, vkey_bytes, pkh_bytes)
                }
                _ => return Err(KeyError::invalid("signing identity contains non-hex data")),
            };

        let seed = <[u8; KEY_LEN]>::try_from(skey_bytes.as_slice())
            .map_err(|_| KeyError::invalid("signing key must contain exactly 32 bytes"))?;
        if vkey_bytes.len() != KEY_LEN {
            return Err(KeyError::invalid(
                "verification key must contain exactly 32 bytes",
            ));
        }
        if pkh_bytes.len() != PKH_LEN {
            return Err(KeyError::invalid("PKH must contain exactly 28 bytes"));
        }

        let derived_vkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        if derived_vkey[..] != vkey_bytes[..] {
            return Err(KeyError::invalid(
                "verification key does not match signing key",
            ));
        }
        if blake2b(&vkey_bytes, PKH_LEN) != pkh_bytes {
            return Err(KeyError::invalid("PKH does not match verification key"));
        }
        Ok(())
    }

    /// Hash the body, sign it with the on-disk skey, and return
    /// `(witness_cbor_hex, tx_hash_hex)`.
    ///
    /// The witness public key is derived from the exact signing-key snapshot
    /// used for the signature, and its configured PKH is rechecked. Reading a
    /// separately rotated vkey here could otherwise pair a signature from one
    /// identity with the public key from another and return an unusable
    /// witness.
    ///
    /// The transaction hash is returned for internal verification and tests;
    /// the HTTP layer deliberately does not persist it alongside request
    /// metadata.
    pub fn witness_tx_cbor(
        &self,
        tx_cbor: &str,
        skey_path: &Path,
        expected_pkh: &str,
    ) -> Result<(String, String), KeyError> {
        let skey = self.get_key_from_file(skey_path)?;
        // Everything the Python `try` block covers — hex decoding of both the
        // key and the PKH, plus constructing the key — collapses to the same
        // opaque message, so a bad key never describes itself to a caller.
        let (seed, pkh) = match (hex::decode(&skey), hex::decode(expected_pkh)) {
            (Ok(skey_bytes), Ok(pkh)) => match <[u8; KEY_LEN]>::try_from(skey_bytes.as_slice()) {
                Ok(seed) => (seed, pkh),
                Err(_) => return Err(KeyError::invalid("signing identity is invalid")),
            },
            _ => return Err(KeyError::invalid("signing identity is invalid")),
        };

        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        if pkh.len() != PKH_LEN || blake2b(&public_key, PKH_LEN) != pkh {
            return Err(KeyError::invalid(
                "signing key does not match configured PKH",
            ));
        }

        // Sign the digest bytes, not their hex text: the chain verifies the
        // witness against the 32 raw bytes of blake2b(body).
        let digest = tx_body_hash(tx_cbor)?;
        let signature = signing_key.sign(&digest).to_bytes();
        Ok((
            create_witness_cbor(&public_key, &signature),
            hex::encode(digest),
        ))
    }
}

/// Hash the body's exact byte slice from the input transaction CBOR.
///
/// The chain validates vkey witnesses against `blake2b(submitted_body_bytes)`:
/// when a node receives a tx it hashes the body bytes as they appear on the
/// wire, not a re-serialization. To make our witness verify on submit we have
/// to hash the *same* bytes the client will submit. Re-emitting would only
/// round-trip cleanly when our serialization choices (definite vs indefinite
/// lengths, integer widths, map-key ordering, set-tag presence) happened to
/// coincide with the client's tx-builder, which isn't a contract we can rely
/// on. Slicing the body byte range out of the input sidesteps the problem:
/// whatever the client built, we hash that.
pub fn tx_id(tx_cbor: &str) -> Result<String, KeyError> {
    Ok(hex::encode(tx_body_hash(tx_cbor)?))
}

/// The raw 32-byte body digest behind [`tx_id`].
fn tx_body_hash(tx_cbor: &str) -> Result<Vec<u8>, KeyError> {
    // `cbor::decode_hex`, not `hex::decode`: this string already passed
    // `check_cbor_hex` under `bytes.fromhex` rules, and refusing it here would
    // deny a witness the Django service issues for the same request.
    let tx_bytes = cbor::decode_hex(tx_cbor)
        .ok_or_else(|| KeyError::invalid("transaction CBOR is not valid hex"))?;

    // `[body, witness_set, is_valid, auxiliary_data]`: step over the outer
    // array header, note the offset, walk exactly one item, note it again.
    // The difference is the body's byte span. Walking rather than decoding
    // keeps a 16 KiB body from being materialized twice per request; the
    // validators already decoded it in full before we get here.
    let mut decoder = cbor::Decoder::new(&tx_bytes);
    decoder
        .skip_array_header()
        .map_err(|err| KeyError::Invalid(err.to_string()))?;
    let body = decoder
        .skip_value()
        .map_err(|err| KeyError::Invalid(err.to_string()))?;

    Ok(blake2b(body, 32))
}

/// Build a Cardano vkey-witness CBOR: `cbor([0, [pubkey, signature]])`.
pub fn create_witness_cbor(public_key: &[u8], signature: &[u8]) -> String {
    let pair = cbor::encode_array(&[
        cbor::encode_bytes(public_key),
        cbor::encode_bytes(signature),
    ]);
    hex::encode(cbor::encode_array(&[cbor::encode_uint(0), pair]))
}

/// Ed25519-sign a hex message with a hex secret key, returning a hex signature.
pub fn sign_hex(skey_hex: &str, msg_hex: &str) -> Result<String, KeyError> {
    let skey_bytes =
        hex::decode(skey_hex).map_err(|_| KeyError::invalid("signing key is not valid hex"))?;
    let seed = <[u8; KEY_LEN]>::try_from(skey_bytes.as_slice())
        .map_err(|_| KeyError::invalid("signing key must contain exactly 32 bytes"))?;
    let msg = hex::decode(msg_hex).map_err(|_| KeyError::invalid("message is not valid hex"))?;
    Ok(hex::encode(
        SigningKey::from_bytes(&seed).sign(&msg).to_bytes(),
    ))
}

/// Ed25519-verify a hex signature against a hex message and hex public key.
pub fn verify_hex(vkey_hex: &str, signature_hex: &str, msg_hex: &str) -> bool {
    // Python raises on malformed inputs and returns False only for a genuine
    // signature mismatch. A `bool` return leaves nowhere to put that
    // distinction, and every caller treats both the same way: don't trust it.
    let (Ok(vkey_bytes), Ok(signature_bytes), Ok(msg)) = (
        hex::decode(vkey_hex),
        hex::decode(signature_hex),
        hex::decode(msg_hex),
    ) else {
        return false;
    };
    let (Ok(vkey_bytes), Ok(signature_bytes)) = (
        <[u8; KEY_LEN]>::try_from(vkey_bytes.as_slice()),
        <[u8; Signature::BYTE_SIZE]>::try_from(signature_bytes.as_slice()),
    ) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&vkey_bytes) else {
        return false;
    };
    // `verify_strict` is the variant that matches libsodium (and therefore
    // PyNaCl): it rejects small-order public keys and non-canonical points.
    verifying_key
        .verify_strict(&msg, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

/// Blake2b digest with an explicit output size, as Cardano uses it
/// (28 bytes for key hashes, 32 for transaction ids).
pub fn blake2b(data: &[u8], digest_size: usize) -> Vec<u8> {
    let Ok(mut hasher) = Blake2bVar::new(digest_size) else {
        // Only reachable from a caller asking for 0 or >64 bytes, which no
        // Cardano hash does. Return nothing rather than a wrong-length digest
        // so an equality check against a real hash cannot pass by accident.
        tracing::error!(target: "api", "Unsupported blake2b digest size {}", digest_size);
        return Vec::new();
    };
    hasher.update(data);
    let mut out = vec![0u8; digest_size];
    if hasher.finalize_variable(&mut out).is_err() {
        tracing::error!(target: "api", "Blake2b finalization failed for digest size {}", digest_size);
        return Vec::new();
    }
    out
}

/// The identity of an *already-open* file, as `data_files::file_identity`
/// computes it for a path. Python reaches this case through
/// `stat_identity(os.fstat(...))`; the Rust sibling only exposes the path
/// form, so the handle form lives here. Both must stay byte-identical or a
/// key would reload on every request.
fn stat_identity(metadata: &Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    let mtime_ns = i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec());
    (mtime_ns, metadata.size(), metadata.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, SystemTime};

    /// Repo dev keys, the identity `payment.skey` / `payment.vkey` carry.
    const DEV_VKEY: &str = "7c33cd41e4dd0742462ad136489ad034cdbbc8b064dd23a7a2d9b302c557f869";
    const DEV_PKH: &str = "6bbdaa10bda87cea060db64569c7e7b9766e896c4bdd8584e6544d71";

    /// `api/tests/test_data.valid_tx_body_cbor_with_collateral()`.
    const VALID_TX: &str = "84a900d9010282825820cb2cc3a624803cf82d85f191b33990de574b1d7286f1118b9ed85bc9e8d434f100825820cb2cc3a624803cf82d85f191b33990de574b1d7286f1118b9ed85bc9e8d434f1010dd90102818258201e0b413409dd9591b2a69bca80d7d776e8bb5130f02af0bf886e08ce5b6e183a0012d90102818258205d8a5d172c7edf3c491f418d33a69bee784e35593163eaf39853f292b81fd95c010182a300581d7047a9877e549b91e775bd40fae36dfbdac072098fb382822faf47b4df01821a0041b31aa1581c0d87a0d951d4d2b04207a8bdafa39c24876c0cb9659045c2365102cca15820b786c5adf265db88e0c6287abb5dbc25202d50ab4b504bc342734bdd24b9e50001028201d8185902d4d8799f581cf4a78bbff6d5e7e492915986abc495382247af659018451a25cec92cd8799f9f581cd858ecf3e73e18bef8383a16e856778e033cfd1c8867c70dc9b68b42581c10a20db9464d89dab407b3397e67facf83db8d442e601b627c0a351f581c121ce13907d40c7a598d182ed751d39279cf30d50decb17151b3a587ff02ffd8799f581c1e3105f23f2ac91b3fb4c35fa4fe301421028e356e114944e902005bd8799f581c8f7b0ce283a92df9a3b69ac0b8f10d8bc8bcf8fbd1fe72596ee8bd6c40ffffd8799f581ca7c1a7fa1f60a3625002664e5aade3277666f370c1456825e2aa7e16581c988fee4370c5b5855ed3c52ea3d5e1e01371b39bf479bfb0e92b7a5a581cc18afab1a36848dad72d37a6a0be5698533dff11a014026ab5521c51581c1e44710275537a2f905e369ad37754afb36e1cfedfe5ca6c198e9cc6581c3bfaa6703f4d78efdf03dbae43d88ea9b309be0f66ed38a7008c2eb1ffd8799f1a000f42401a000f42401a000f4240ff581cb2f24e2ec2bfd520646fcec685cd8c1eb3e8272da30d8311fd397678d8799f581ce4d33c4f86ac40278cdd80572abfa7e91b01fbba68d8fa258bf7ef46581c916c03c8f98c44a176de6660e6e45ac0cd59aa4fe6c332bed1e8d79d9f4444618a674445b555bd444cae2fd24457d8ea10445f3a83b8446aa8bd5d44726aaa90448be2ee9c448c4234e844d05fd9e244ecf39067440892f565440c55ccd7443d4d980744520fc569445c99b6b44463e2123b4478820b6c44a16af81444ad997a9244e7982636ff581c47f7fbe11f6d176632a4d73a5a0be81810c4918281f55df0d3485685ffd8799f581cb07d22a4dc75abdba1b8c80033a15b85305b76521a0114b17f291a87581c362e3f869c98ce971ead0e2705c56df467ddd2aecb44f6f216c3e1d54a4f7261636c6546656564581c769c4c6e9bc3ba5406b9b89fb7beb6819e638ff2e2de63f008d5bcff45744e45574d1b000000746a528800ffff82581d60f4a78bbff6d5e7e492915986abc495382247af659018451a25cec92c1a11c8a0d31082581d60f4a78bbff6d5e7e492915986abc495382247af659018451a25cec92c1a00431d9c111a00092da4021a00061e6d0ed9010285581c10a20db9464d89dab407b3397e67facf83db8d442e601b627c0a351f581c121ce13907d40c7a598d182ed751d39279cf30d50decb17151b3a587581cc59da4ec6e515c2efc8866274dee6ac9a64b5945efd365f3a999e760581cd858ecf3e73e18bef8383a16e856778e033cfd1c8867c70dc9b68b42581cf4a78bbff6d5e7e492915986abc495382247af659018451a25cec92c0b5820cc1eb6b650d646141719844845959d0e14ca1087be4663af6b63973b89688a50a105a182000082d87980821a000c4f8c1a0da69936f5f6";
    const VALID_TX_ID: &str = "671476c0d87cc6061597c9c6b536e8ebdf7c071188966d16af11d00ca85bef45";

    /// `api/tests/test_data.invalid_tx_body_missing_collateral()`.
    const OTHER_TX: &str = "84ab00d90102828258206277d223169cbe56cae912c7b4789ce55d88470b7f93475f9f8adecfb8c28230018258208174ded24eda90cdeb4f1b093e101148d9304053ff7b34a7c9478337fa00cc92020dd90102818258206277d223169cbe56cae912c7b4789ce55d88470b7f93475f9f8adecfb8c282300112d9010281825820d84783b8cdd75aa688fa4505cc6143e8b3fd9069a65629b002efe3b1aed9b641010182a300581d70e8a957100f3c633592eae6bf810c2e26d97bd92ecdb59d5e84afbc7c01821a0018dbfca1581ce8a957100f3c633592eae6bf810c2e26d97bd92ecdb59d5e84afbc7ca158205eed0e1f7361736467016277d223169cbe56cae912c7b4789ce55d88470b7f9301028201d8185868d8799f583097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb5830aac1314842462403009f917f388184f6fe8db6745cff08adb336bcd0a3c21fe27c7b4f862d7d8fea2a395dd77bf9a786ff82581d60a2d0bdf9260505f38e22ea0fb3bbedc327b7eaea628f9317bcbab9be1a0195a8ed1082581d60a2d0bdf9260505f38e22ea0fb3bbedc327b7eaea628f9317bcbab9be1a0165c671111a0005f57c021a0003f8fd0ed9010282581ca2d0bdf9260505f38e22ea0fb3bbedc327b7eaea628f9317bcbab9be581cefac7006bfd7a40966142ff2a0f4ede13da67ff35cce4166c6f4e05109a1581ce8a957100f3c633592eae6bf810c2e26d97bd92ecdb59d5e84afbc7ca158205eed0e1f7361736467016277d223169cbe56cae912c7b4789ce55d88470b7f93010b58209d923c45f20f13502ea8847057afbd9c955859a175f1767ee0c51cb607abe48c075820300f0cd73535a8137c850425ca635fce566de135890bfbe4ae43ea979e3a6722a105a182010082457361736467821a000179691a01a30740f5d90103a100a10063796573";
    const OTHER_TX_ID: &str = "6788a8ef5b561ea475d81cd97ec90cfdbc1508ee7d425c3f800fcdd6de5b5b7a";

    /// A real mainnet tx the chain accepted, paired with the id it assigned.
    /// 3.1 KiB body carrying indefinite-length encodings inside a Plutus
    /// datum — the encoding shape a re-serializing implementation gets wrong.
    const CHAIN_TX: &str = "84aa00d9010281825820e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d184000dd90102818258208a6bed6b72cfe64fb8e9531badf2cd6d199a2fcd9120057d29711fcf5f8fab150212d90102818258206eabeeda6895cf81bcf2c4feba255a6981e9d02506b8e00c46dbc9347d31b00f010182a300581d700ee28a6d25ddab3f6ec2e71334f36cbd85e2530b104dbddb92e865e501821a00bcf1a6a1581c21b5bcf6f42eeac1b00121579e1a490134b08510120be94b5c3a0c86a1582000e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d101028201d818590a26d8799f581c0ee28a6d25ddab3f6ec2e71334f36cbd85e2530b104dbddb92e865e5581c222e249ab3df32ab0f984ef1cb84d765af62b76b86a92ce12d77f31f581c4354497e77eac590093c0556cca9aac43616314b883ecc3b306f5322581c495cb46f90fd58b44eccc99b160ea4182ef17df44cb7deac48040ebad8799f182558308f9a7bae3a1e87b9fac96baee301945cc1fc70f4ecf30b72792152e6eb8a6777c1adcffc6190e7a0ba5034cff589e16a5f584083b22bc12365ee725a5aad48acc74bf63a517f1032703c8f5c52195146372adae1ec1a43a049791a08781f4ced01b2fd07e179cb1afa0cfdf96d6660049f82585820e8639948e8f478166be1142c5ed93c90b1bc273ca390c13e2c7ee7add7bbf7e9ff5f584093e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc510515820c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8ff5f5840b89093b5e68d0f7b95e1bb06712c37befe433e0550cb25e7172ec538b5fa5bce72f70742bcf531e4140d978daf1388cc019818a8312f7d2385ae83d3373538f7582032071ec7d7768b5ae71e21eeb91b088cb2c39d3078a15b15a41bfad016d590feff9f58309034c0e6bf1500b6b5109afa89c45c654deae9f244ed534756c06dcf9e3a7745a82a60dd5c7e7ffaec671a579d295c9c5830930357dea42061f4955c243ab767d74d827e471a2ffb18133fe865895b3ba8be0333a18142e2565e516d9e4e5890402958308316d8926a657be5172f2a7406adbd4d19c18f26d53d9cf245e5b821c3d80d58d93f742c191a359873d84e3e4b28ab22583084c1e64131112181c5fa24e7e15dd382bf089f7632436556c5616436fd687ee06ac53e7126b940d1d8aa0e8da3d3ee7e583084dd02d103e1a92c00fb5f4f313b8b0666e3e05886a798792b9dd6a638dcf5bfeb58e662e608c62e544573dbd0432be2583080efead39c1a5b517741bb22e4e3a15d422bed7717490362445d921f18faf4236b0ac764ed11c334293cb789b354bc8b583089a5c772103515212c0ad9b447d55795b05d1a905cef0731b7cecf7fceb4f90f95373556d2b5c1afd346a8a0685d9d465830b5f18397e0212435bd883220a16cedaf1f8de38d3ed49272887be70a9595f0233aa3fd4e34a196710cf2abb7c73062f6583095656039cb8fbe76dff2742aab2968cd5766110444c590a3e9dc4440960f106214ba4c0a965ed35278c07993c69d45455830851869167ec4e80b3828c03d0ea65e806c504f70bff128df1ce6f7a8e4353eea51821b42b263c1505c998dbe77bc36415830a67f20dcbe3a9cc31c38b634656d2b5894a08c8f13391877c52124daff1fd0239cdbed6221386e4b6fd444ca8ace14775830b577d73a73bc5a80930dda1ae1dda744e97d97d1d9e041f4e442be6c327928122a579f128b213f10ce4eb6652f4918f95830ace90e50756a9a3c3100dee14a0a107d43ea60856ce1e74e6dddf57ddcfcd6b3a4ec5ce54c089873ecc11a4e4bd8f57b58308a5e43f72debaee6e7f987f5ea99119051d22beb7856cf12334fbfdba215b8ecf81763999b44edcb0f03225606f486375830a7112c7d1e8d5a26e68f3cc4ece1e98bbe1f5118ae578d1d92ec54c086274321c8ce1e39faa5c9af2676a192f4f77a80583089c494cb71f7dae7809aba86595716cb3414a91771d7ef4741026bc011fc2be447a4916aff2f53bc68441ccdc5fa88125830a1bbcfe36ef67e38e74b208813b341ac1223ae1343e5595313fe2b0d4fffe4739207f83b57a345f3c46860c2988e89825830882f14c0b56ef12e8a5881a3b6b263967b86d218e35fb17657eb90b6b8ed8eb4ba6d4bc2d4a28843a4d87441052121f45830a9b04b988a256e62a69c751574b7251986576684a9686385d4697b1b78dbcb1ed15bd22a77ad86cdb7a1e939324e7ed558308f2a04759d63a4d75bff862fe9fb4906291597abf98c9966f4cbc383b8404bd457577566b4518e98f97c0e7b7f9f819058309451b1e07ca7bce0e338889ff6458249e541635cf5037bca7c4e38dd9965f6f3051e3ae6126f5943ffe1d3f00903e05858308b6857d9663f6d82aa9ba847a6970fd8193243b0143404d89f7b021b5e1376fe7c625f4d89461023a30c6895c3af431258308f74a1dfad802b6af3fd57334b4e2d2ec75dfdb1418504618e8ec85f93d6d681e9c00cd1b5244607efe7bf4d99ed4f8f5830b5a40db6ec975fb713b3793ef05ed2fb5e40ee126707b5006cc479bbd5547b8c8631ca668c2e95b8a1f9e559a232f3e15830b93ed02bd864e0cf2b3466b4fd9b60cda5ab73adcf4a1a9a0aabdb9d34789451aee2758076b4a97ab50d48b9a644859a58308f731c0e221a59d899d5a8b01df84d3c383d3ea8f30c48c19860a5db49d72e2c5925bd3bd277b03ad35ecd6a892e07d25830a526ac6fca866493af15127330d65807e5fa6097b6df5120dfb41d52b5613c8efe6b1bc412ec456cd2099c3356ab99955830812e232d45eda12e489d183e8cf298c9a032dfbce2ab4906ce05555a06e80494caa36102f3a304df1bfa820b2ce283165830a0afd7cf663b1fdf1c6b1fb27e11c3fd4174b20db82e679e29ac0959f94897b16e1bec6a59c481ab6a850883db9102fb5830852ce127b66c0722188278957b81377dea12b0e19c918ad1639ed65861ee4a1055dd76e6aade9cc1969c2532db3c28e85830b484f2124a4e6530e95856e605e7dc7691436e7fd8e388bdbc53dc2c1a8153a2412b93a8fcd6be5b026b488229d24a66583098d0d317c06e95c66425e5d5dc96ecdecfe1f9c379f43c32e91e6e622dce993746071eadf95506b4adfe5028a455080e5830b745b17c5aa144c82228542e89d883dff1046267dd6befdff3ffe75bbe26a8663bf4c6777463f193b9b803f8b31a26945830b87da441a37b7c4b63f576e44e4ac802e12763c8e03e76e56c25c28809021e1399dc024a8d14fbeb44887d9009e8789a5830a6c558ce9419f54a15a6fbea7b91c2ba9d2f20a1ed0b1536a6f238c9b318e2e165f03f525e9747eb2b8756c4f12462355830a4cfe9f8ac1c3b6d79286be720b5a49f5c9c29eb3115283d77c93ba738e3c7a8c7c1ffc34df2d27c9292d1c120ea3cda5830a2710e18ea203e41515dbd6b7120149b70a80a632036df4d215bb0d812e2cc4f9d0e1b24a55fb582e90fdfc76217486d583087ffd9dd456e747d0a789ba308073085b08f54e6c865b2508b206cb8b085f5368a52ae33c0c00fc6df3726f9f0d75d50ff9fd8799f5f584093e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc510515820c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8ff5f5840a8a277aa6084d9b6c398439201484885af7dc1d8dd9547b4dc398b127f7b5c8f4dabd9e5e0ddf37917326d8ec46a5a98055750730b28b047a370a9f95994be1c582099820863105d614f5975a559f0184c75af99971ff84d1925822bf4b439ad63b4ffffffffff82583900dd996ca1174aa2e32dbbad88046b440ff563a3cde0716a56865400c6b5c562bdedfb6d283af13b35a63556c0d4acc5ea01069f96e7975a6b1a006e766a1082583900dd996ca1174aa2e32dbbad88046b440ff563a3cde0716a56865400c6b5c562bdedfb6d283af13b35a63556c0d4acc5ea01069f96e7975a6b1a0043a3d8111a0008a768021a0005c4f00ed9010282581c01e7fe6f0fb975d8e24076a36e491f36896a441c4598cbd88b517056581cc47aa4f225e3492f3d9a944489c1c78b3c4637908fcb5805ce04470209a1581c21b5bcf6f42eeac1b00121579e1a490134b08510120be94b5c3a0c86a1582000e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d1010b5820d065a575eaed34c493efdd2c81592822fb33062ca6bb527c898ab77a8a3c83e1a200d9010282825820df22bae75442283e8ceb2714d1b65d77449f9ebe3f1033d0362183720891d6ef58404b1d74e0eb8fa29de622fc57c50b8cf0afdc6feac373d4852d0a34c5f7e468e7a97efa130e39a29acc067f3700554d4d5267a6ea607367491ac38b9e62ecd20e825820ddb67b71cf203e03e7adeef4c97e945d5110abc7b638daa2a5def5961f8e9b4f5840cce1b4852f5801b6be3c632e29e20e087239316db9e346bad7c4f462152d152da4bf12f4d0294a5ab5346060abd154e09be0834cc6e8422be2587448de2fdc0405a182010082d87980821a0004d14b1a05938f1af5f6";
    const CHAIN_TX_ID: &str = "b261a8123265a19cdb5c33db7f0afead6e92b93d747b3deaec3b8e0c0ae6d1c2";

    /// A second accepted tx: small body with a Plutus script in the outputs.
    const CHAIN_TX2: &str = "84a300d9010281825820613ef2c284082d666d6a9b0b309437b10d1099eaca46134f77828294ad21347600018282581d60fdd320cd9c529f021452b5b39eb3a6d854f3d1d59c329d2ed1b803951a0be79cc9a300581d60fdd320cd9c529f021452b5b39eb3a6d854f3d1d59c329d2ed1b80395011a001822ca03d81858a38203589f589d010100332229800ab9cab9a9bae0039bae0024888966002a66008921104920616c77617973206661696c203a2f00168a4d15330044911856616c696461746f722072657475726e65642066616c73650013656400c4c11e581c21b5bcf6f42eeac1b00121579e1a490134b08510120be94b5c3a0c86004c0122582000e4d20dca46f31c227666ee477770304a4f805cb2e00a4e379d243fbbc0c9d10001021a0003bf3ba100d90102818258207668cfa9f6d2de5b4b86de0dc291f26574c93a9e57bd7e6a634fdb85fe19518458401bf79ba1e08f6e1546f58f82ab04991924acfd45323656f24a390b34d232e6319657187872e55d8751a51c31390b621a60ce868a3957050bab5325581d947f0ef5f6";
    const CHAIN_TX2_ID: &str = "d633980cd09ed263782161381de7a48a6c5814ddfff0b2eef4999e851c13ce70";

    fn dev_key_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate has a parent directory")
            .join("collateral_provider/api/key")
    }

    fn decode(hex_text: &str) -> Vec<u8> {
        hex::decode(hex_text).expect("test vector is hex")
    }

    /// The exact byte span `tx_id` hashes, used to rebuild a transaction with
    /// a different envelope around the same body.
    fn body_bytes(tx_hex: &str) -> Vec<u8> {
        let bytes = decode(tx_hex);
        let mut decoder = cbor::Decoder::new(&bytes);
        decoder.skip_array_header().expect("outer array");
        decoder.skip_value().expect("body").to_vec()
    }

    fn write_key(path: &Path, value: &str) {
        fs::write(path, format!("{{\"cborHex\":\"5820{value}\"}}")).expect("write key file");
    }

    fn set_mtime(path: &Path, when: SystemTime) {
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open for utime");
        file.set_times(fs::FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    // --- hashing -----------------------------------------------------------

    #[test]
    fn blake2b_matches_hashlib_for_both_cardano_sizes() {
        assert_eq!(hex::encode(blake2b(&decode(DEV_VKEY), 28)), DEV_PKH);
        assert_eq!(
            hex::encode(blake2b(b"", 32)),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        assert_eq!(blake2b(b"", 28).len(), 28);
        // An unsupported size yields nothing rather than a wrong-length hash.
        assert!(blake2b(b"", 0).is_empty());
        assert!(blake2b(b"", 65).is_empty());
    }

    #[test]
    fn tx_id_matches_the_python_fixtures() {
        assert_eq!(tx_id(VALID_TX).expect("valid tx"), VALID_TX_ID);
        assert_eq!(tx_id(OTHER_TX).expect("other tx"), OTHER_TX_ID);
    }

    #[test]
    fn tx_id_matches_chain_for_real_submitted_txs() {
        // The only assertion proving the algorithm agrees with the ledger;
        // the synthetic fixtures only prove it stays consistent with itself.
        assert_eq!(tx_id(CHAIN_TX).expect("chain tx"), CHAIN_TX_ID);
        assert_eq!(tx_id(CHAIN_TX2).expect("chain tx 2"), CHAIN_TX2_ID);
    }

    #[test]
    fn body_hash_does_not_bind_outer_validity_or_witnesses() {
        // Vkey witnesses sign the body only. The phase-2 validity flag and
        // the witness set may change without changing the transaction id.
        let body = body_bytes(VALID_TX);
        let mut rebuilt = vec![0x84];
        rebuilt.extend_from_slice(&body);
        rebuilt.extend_from_slice(&[0xa0, 0xf4, 0xf6]);
        assert_eq!(tx_id(&hex::encode(rebuilt)).expect("rebuilt"), VALID_TX_ID);
    }

    #[test]
    fn tx_id_accepts_every_outer_array_header_encoding() {
        let body = body_bytes(VALID_TX);
        // Indefinite-length outer array, closed with a break.
        let mut indefinite = vec![0x9f];
        indefinite.extend_from_slice(&body);
        indefinite.extend_from_slice(&[0xa0, 0xf5, 0xf6, 0xff]);
        assert_eq!(
            tx_id(&hex::encode(indefinite)).expect("indefinite"),
            VALID_TX_ID
        );

        // Non-minimal one-byte-argument header for the same 4-element array.
        let mut wide = vec![0x98, 0x04];
        wide.extend_from_slice(&body);
        wide.extend_from_slice(&[0xa0, 0xf5, 0xf6]);
        assert_eq!(tx_id(&hex::encode(wide)).expect("wide header"), VALID_TX_ID);
    }

    /// The signing step is the last place the submitted hex is decoded, and it
    /// has to accept everything `check_cbor_hex` let through. `hex::decode`
    /// rejects the ASCII whitespace `bytes.fromhex` skips, so a transaction
    /// Django witnesses would have died here with "not valid hex".
    #[test]
    fn tx_id_accepts_the_whitespace_bytes_fromhex_allows() {
        let spaced: String = VALID_TX
            .as_bytes()
            .chunks(2)
            .map(|pair| format!("{} ", std::str::from_utf8(pair).expect("ascii hex")))
            .collect();
        for candidate in [
            spaced.trim_end().to_string(),
            format!("\n{VALID_TX}\t"),
            format!("\u{b}{VALID_TX}\u{c}"),
            VALID_TX.to_uppercase(),
        ] {
            assert_eq!(
                tx_id(&candidate).unwrap_or_else(|err| panic!("{err}")),
                VALID_TX_ID
            );
        }

        // And the whole witness is byte-identical to the clean form's.
        let dir = tempfile::tempdir().expect("tempdir");
        let skey = dir.path().join("payment.skey");
        write_key(&skey, &"11".repeat(32));
        let pkh = "5ae193abe694a607531e20f85d8358ade9a474a4f45ac4e15e962da1";
        let cache = KeyCache::new();
        assert_eq!(
            cache
                .witness_tx_cbor(spaced.trim_end(), &skey, pkh)
                .expect("spaced tx witnesses"),
            cache
                .witness_tx_cbor(VALID_TX, &skey, pkh)
                .expect("clean tx witnesses")
        );

        // Whitespace *inside* a byte pair is still an error, as in Python.
        assert!(tx_id(&format!("8 4{}", &VALID_TX[2..])).is_err());
    }

    #[test]
    fn tx_id_rejects_non_hex_and_non_array_input() {
        assert!(tx_id("zz").is_err());
        assert!(tx_id("").is_err());
        // A CBOR map, not the 4-element transaction array.
        assert!(tx_id("a0").is_err());
    }

    // --- signing primitives ------------------------------------------------

    #[test]
    fn verify_accepts_a_known_good_signature() {
        assert!(verify_hex(
            "7EE70C8FF8CABD12E8453C942D65D5D5B504CC658028981F5EC16664D7B0ACBD",
            "5D2190A2D12B4C7516A3D9479F860A8B68E988BA31318AB79B39ADD15E128AAF9385BDA3D7A9379DBA86A1A9092CED6B96350B1BDC0842DC93FDE785B71E6E07",
            "f620a4e949bfbefbf2892d39d0777439f3acfbf850eae9b007c6558ba8ef4db4",
        ));
    }

    #[test]
    fn verify_rejects_malformed_input_instead_of_panicking() {
        assert!(!verify_hex("nothex", "00", "00"));
        assert!(!verify_hex(&"00".repeat(31), &"00".repeat(64), "acab"));
        assert!(!verify_hex(&"00".repeat(32), &"00".repeat(63), "acab"));
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let sk = "abffdc040fd4c5d3eb6ce962a968f57995edfb33c78a11a466446a649f3ed82c";
        let pk = "51c20cf4a8ed0e13cd65026625fe59d7ee8f8ef274a3d5575f8c30f9732cb3ed";
        let signature = sign_hex(sk, "acab").expect("signs");
        assert!(verify_hex(pk, &signature, "acab"));
        assert!(!verify_hex(pk, &signature, "acad"));
    }

    #[test]
    fn create_witness_cbor_matches_the_python_vector() {
        let public_key = decode("FA2025E788FAE01CE10DEFFFF386F992F62A311758819E4E3792887396C171BA");
        let signature = decode("F79613A21B87E80F8FFF4FA6E878C58186381BA10C46F7B4569A9183EF9FD077AD844F88DDBBE9285FAA9FEBBF3EACBB41338B9889FF82B6252139279FB53C07");
        assert_eq!(
            create_witness_cbor(&public_key, &signature),
            "8200825820fa2025e788fae01ce10deffff386f992f62a311758819e4e3792887396c171ba5840f79613a21b87e80f8fff4fa6e878c58186381ba10c46f7b4569a9183ef9fd077ad844f88ddbbe9285faa9febbf3eacbb41338b9889ff82b6252139279fb53c07"
        );
    }

    #[test]
    fn signing_the_body_hash_reproduces_the_python_witness() {
        // End-to-end vector: body hash, Ed25519 signature, witness CBOR.
        let tx_hash = tx_id(VALID_TX).expect("valid tx");
        let signature = sign_hex(
            "abffdc040fd4c5d3eb6ce962a968f57995edfb33c78a11a466446a649f3ed82c",
            &tx_hash,
        )
        .expect("signs");
        let public_key = decode("51c20cf4a8ed0e13cd65026625fe59d7ee8f8ef274a3d5575f8c30f9732cb3ed");
        assert_eq!(
            create_witness_cbor(&public_key, &decode(&signature)),
            "820082582051c20cf4a8ed0e13cd65026625fe59d7ee8f8ef274a3d5575f8c30f9732cb3ed584077589916b53ea6abfb4e9793770bf5fbb0bbe153046e12b91365832f2c1558aec34dcf8544b15fbdd1946b32b10b38dfa70defaeb827d98a4f959539000df502"
        );
    }

    // --- key material ------------------------------------------------------

    #[test]
    fn repo_dev_keys_are_a_consistent_identity() {
        let cache = KeyCache::new();
        let dir = dev_key_dir();
        assert_eq!(
            cache
                .get_key_from_file(&dir.join("payment.vkey"))
                .expect("dev vkey"),
            DEV_VKEY
        );
        cache
            .validate_key_material(
                &dir.join("payment.skey"),
                &dir.join("payment.vkey"),
                DEV_PKH,
            )
            .expect("dev identity is consistent");
    }

    #[test]
    fn strips_the_cbor_byte_string_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payment.skey");
        write_key(&path, &"ab".repeat(32));
        let cache = KeyCache::new();
        let key = cache.get_key_from_file(&path).expect("reads");
        assert_eq!(key, "ab".repeat(32));
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn missing_or_malformed_files_are_distinguishable_errors() {
        let cache = KeyCache::new();
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            cache.get_key_from_file(&dir.path().join("nope.skey")),
            Err(KeyError::Io { .. })
        ));

        let not_json = dir.path().join("garbage.skey");
        fs::write(&not_json, "not json at all").expect("write");
        assert!(matches!(
            cache.get_key_from_file(&not_json),
            Err(KeyError::Format(_))
        ));

        let wrong_shape = dir.path().join("wrong.skey");
        fs::write(
            &wrong_shape,
            "{\"type\": \"PaymentSigningKeyShelley_ed25519\"}",
        )
        .expect("write");
        assert!(matches!(
            cache.get_key_from_file(&wrong_shape),
            Err(KeyError::Format(_))
        ));
    }

    #[test]
    fn validate_key_material_reports_each_inconsistency() {
        let dir = tempfile::tempdir().expect("tempdir");
        let skey = dir.path().join("payment.skey");
        let vkey = dir.path().join("payment.vkey");
        let cache = KeyCache::new();

        let zero_vkey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
        let zero_pkh = "cb9358529df4729c3246a2a033cb9821abbfd16de4888005904abc41";
        write_key(&skey, &"00".repeat(32));
        write_key(&vkey, zero_vkey);
        cache
            .validate_key_material(&skey, &vkey, zero_pkh)
            .expect("consistent identity");

        // PKH that does not hash from the vkey.
        cache.clear();
        let err = cache
            .validate_key_material(&skey, &vkey, &"00".repeat(28))
            .expect_err("pkh mismatch");
        assert_eq!(err.to_string(), "PKH does not match verification key");

        // vkey that is not the skey's public key.
        cache.clear();
        write_key(&vkey, &"00".repeat(32));
        let err = cache
            .validate_key_material(&skey, &vkey, &"00".repeat(28))
            .expect_err("vkey mismatch");
        assert_eq!(
            err.to_string(),
            "verification key does not match signing key"
        );

        // Wrong lengths and non-hex content.
        cache.clear();
        write_key(&vkey, zero_vkey);
        let err = cache
            .validate_key_material(&skey, &vkey, &"00".repeat(27))
            .expect_err("short pkh");
        assert_eq!(err.to_string(), "PKH must contain exactly 28 bytes");

        cache.clear();
        write_key(&vkey, &"00".repeat(31));
        let err = cache
            .validate_key_material(&skey, &vkey, zero_pkh)
            .expect_err("short vkey");
        assert_eq!(
            err.to_string(),
            "verification key must contain exactly 32 bytes"
        );

        cache.clear();
        write_key(&skey, &"00".repeat(31));
        write_key(&vkey, zero_vkey);
        let err = cache
            .validate_key_material(&skey, &vkey, zero_pkh)
            .expect_err("short skey");
        assert_eq!(err.to_string(), "signing key must contain exactly 32 bytes");

        cache.clear();
        write_key(&skey, &"zz".repeat(32));
        let err = cache
            .validate_key_material(&skey, &vkey, zero_pkh)
            .expect_err("non-hex skey");
        assert_eq!(err.to_string(), "signing identity contains non-hex data");
    }

    // --- witness -----------------------------------------------------------

    #[test]
    fn witness_verifies_against_the_body_hash_under_the_returned_key() {
        // The composition that is the entire product: a witness that does not
        // verify is silently useless to every caller.
        let dir = tempfile::tempdir().expect("tempdir");
        let skey = dir.path().join("payment.skey");
        write_key(&skey, &"11".repeat(32));
        let public_key = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let pkh = "5ae193abe694a607531e20f85d8358ade9a474a4f45ac4e15e962da1";

        let cache = KeyCache::new();
        let (witness, tx_hash) = cache
            .witness_tx_cbor(VALID_TX, &skey, pkh)
            .expect("witnesses");
        assert_eq!(tx_hash, VALID_TX_ID);

        let decoded = cbor::decode_exact(&decode(&witness)).expect("witness is CBOR");
        let items = decoded.as_array().expect("witness is an array");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_int(), Some(0));
        let pair = items[1].as_array().expect("[pubkey, signature]");
        let emitted_key = pair[0].as_bytes().expect("pubkey bytes");
        let signature = pair[1].as_bytes().expect("signature bytes");
        assert_eq!(hex::encode(emitted_key), public_key);
        assert_eq!(signature.len(), 64);

        assert!(verify_hex(public_key, &hex::encode(signature), &tx_hash));
        // A witness for one body must not verify against another.
        let other = tx_id(OTHER_TX).expect("other tx");
        assert!(!verify_hex(public_key, &hex::encode(signature), &other));
    }

    #[test]
    fn witness_refuses_a_key_that_does_not_match_the_configured_pkh() {
        let dir = tempfile::tempdir().expect("tempdir");
        let skey = dir.path().join("payment.skey");
        write_key(&skey, &"11".repeat(32));
        let cache = KeyCache::new();

        let err = cache
            .witness_tx_cbor(VALID_TX, &skey, &"ab".repeat(28))
            .expect_err("pkh mismatch");
        assert_eq!(err.to_string(), "signing key does not match configured PKH");

        // A PKH of the wrong length is a mismatch, not a length complaint.
        let err = cache
            .witness_tx_cbor(VALID_TX, &skey, &"ab".repeat(27))
            .expect_err("short pkh");
        assert_eq!(err.to_string(), "signing key does not match configured PKH");

        // Non-hex inputs never describe themselves to a caller.
        let err = cache
            .witness_tx_cbor(VALID_TX, &skey, "not hex")
            .expect_err("non-hex pkh");
        assert_eq!(err.to_string(), "signing identity is invalid");
    }

    // --- cache identity ----------------------------------------------------

    #[test]
    fn caches_while_the_stat_identity_is_unchanged() {
        // The hot path must not re-open and re-parse the skey on every
        // signing request. Rewrite the same-length content in place and put
        // the mtime back: the cached value must still be served.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payment.skey");
        write_key(&path, &"cd".repeat(32));
        let cache = KeyCache::new();
        assert_eq!(
            cache.get_key_from_file(&path).expect("first"),
            "cd".repeat(32)
        );

        let modified = fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime");
        write_key(&path, &"ef".repeat(32));
        set_mtime(&path, modified);

        assert_eq!(
            cache.get_key_from_file(&path).expect("second"),
            "cd".repeat(32)
        );
        cache.clear();
        assert_eq!(
            cache.get_key_from_file(&path).expect("after clear"),
            "ef".repeat(32)
        );
    }

    #[test]
    fn reloads_when_the_mtime_advances() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payment.skey");
        write_key(&path, &"11".repeat(32));
        let cache = KeyCache::new();
        assert_eq!(
            cache.get_key_from_file(&path).expect("first"),
            "11".repeat(32)
        );

        let modified = fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime");
        write_key(&path, &"22".repeat(32));
        set_mtime(&path, modified + Duration::from_secs(5));
        assert_eq!(
            cache.get_key_from_file(&path).expect("second"),
            "22".repeat(32)
        );
    }

    #[test]
    fn reloads_after_an_atomic_replacement_with_an_equal_or_backdated_mtime() {
        // The rotation workflow operators actually use: write a temp file in
        // the same directory and rename it over the key. `cp -p` and restores
        // from backup can hand back a timestamp that is equal to or older
        // than the file being replaced, so mtime alone is not enough.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payment.skey");
        write_key(&path, &"11".repeat(32));
        let cache = KeyCache::new();
        assert_eq!(
            cache.get_key_from_file(&path).expect("first"),
            "11".repeat(32)
        );
        let original = fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime");

        for (value, when) in [
            ("22".repeat(32), original),
            ("33".repeat(32), original - Duration::from_secs(3600)),
        ] {
            let replacement = dir.path().join("payment.skey.tmp");
            write_key(&replacement, &value);
            set_mtime(&replacement, when);
            fs::rename(&replacement, &path).expect("atomic replace");
            assert_eq!(cache.get_key_from_file(&path).expect("reloads"), value);
        }
    }
}
