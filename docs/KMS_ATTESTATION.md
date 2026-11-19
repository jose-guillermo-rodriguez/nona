# AWS Nitro Enclave & KMS Recipient Key-Release Architecture

**Specification Version:** 1.0.1-HARDENING  
**Classification:** Authoritative Cryptographic Attestation & Key-Release Protocol  
**Target Environments:** AWS Nitro Enclaves (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) | `#![no_std]` Core  

---

## 1. Zero-Trust Host Relay Model & Security Objective

In AWS Nitro Enclave deployments, the parent EC2 instance (`proxy_bridge`) possesses external network connectivity to AWS Key Management Service (AWS KMS) while the isolated enclave has zero direct external NIC access and communicates exclusively over `AF_VSOCK`. Under Nona's zero-trust host adversary model (`docs/THREAT_MODEL.md`), the parent EC2 operating system and `proxy_bridge` are actively untrusted intermediaries.

AWS KMS `Recipient` attestation key release (`kms:Decrypt` and `kms:GenerateDataKey` with the `Recipient` parameter) solves the key-brokerage problem without trusting the parent host:

1. **Zero Plaintext Exposure to Parent Host:** AWS KMS verifies the hardware-signed `/dev/nsm` `COSE_Sign1` attestation document, enforces IAM and KMS key-policy conditions against `kms:RecipientAttestation:PCR0`, `kms:RecipientAttestation:PCR1`, `kms:RecipientAttestation:PCR2`, and `kms:RecipientAttestation:ImageSha384`, and encrypts the released plaintext key material specifically to the enclave's ephemeral public key inside `CiphertextForRecipient`.
2. **Untrusted Ciphertext Brokerage:** The parent EC2 host (`proxy_bridge`) relays the opaque `COSE_Sign1` attestation document to AWS KMS and relays the returned `CiphertextForRecipient` envelope back over `AF_VSOCK`. Because the envelope is encrypted to the enclave's ephemeral private key—which never leaves enclave DRAM—the parent host cannot decrypt, forge, or alter the released blinding secret.
3. **Ephemeral Temporal Dwell Collapse:** Immediately upon unwrapping and authenticating the session blinding secret inside enclave memory, the enclave destroys the ephemeral private key using volatile memory writes (`core::ptr::write_volatile`) and a full compiler memory fence (`Ordering::SeqCst`), collapsing the temporal dwell window of key-transport material to microseconds.

---

## 2. End-to-End Protocol Sequence

```text
+------------------------+          +---------------------------+          +---------------------+
|  NONA ENCLAVE          |          |  UNTRUSTED PARENT HOST    |          |  AWS KMS            |
|  (Isolated vCPU/DRAM)  |          |  (proxy_bridge / vsock)   |          |  (Nitro Enclave CA) |
+-----------+------------+          +-------------+-------------+          +----------+----------+
            |                                     |                                   |
            |  1. CMD_ATTEST (challenge_nonce)    |                                   |
            | <-----------------------------------+                                   |
            |  2. /dev/nsm GetRandom -> k_eph     |                                   |
            |     P_eph = [k_eph]G (secp256k1)    |                                   |
            |     user_data = SHA-512(P_eph)      |                                   |
            |     /dev/nsm Attestation -> Doc     |                                   |
            |  3. P_eph || COSE_Sign1(Doc)        |                                   |
            | ----------------------------------> |                                   |
            |                                     |  4. kms:Decrypt / GenerateDataKey |
            |                                     |     Recipient = {                 |
            |                                     |       KeyEncryptionAlgorithm,     |
            |                                     |       AttestationDocument: Doc    |
            |                                     |     }                             |
            |                                     | --------------------------------> |
            |                                     |  5. Verify Nitro Root CA, ES384,  |
            |                                     |     PCR0/PCR1/PCR2 policy,        |
            |                                     |     wrap r under P_eph            |
            |                                     |  6. CiphertextForRecipient        |
            |                                     | <-------------------------------- |
            |  7. CMD_KMS_RECIPIENT_UNWRAP        |                                   |
            |     (AttestedKeyEnvelope)           |                                   |
            | <-----------------------------------+                                   |
            |  8. Verify PCR0/1/2 + single-use    |                                   |
            |     challenge nonce + MAC tag       |                                   |
            |     ECDH(k_eph, E_kms) -> KEK       |                                   |
            |     Unwrap session blinding seed r  |                                   |
            |     ct_zeroize(k_eph) + SeqCst      |                                   |
            |  9. Opaque ACK (status = 0)         |                                   |
            | ----------------------------------> |                                   |
            | 10. CMD_BLIND_PHASE1 / Phase 2 PSI  |                                   |
            |     using unwrapped session secret r|                                   |
            | <=================================> |                                   |
```

---

## 3. Ephemeral Keypair & NSM Attestation Document Binding

### 3.1 Exclusive `/dev/nsm` Hardware Entropy Seeding
- Ephemeral private scalars (`k_eph`, 32 bytes) are generated strictly inside enclave memory via direct `/dev/nsm` `GetRandom` IOCTLs (`fill_nsm_entropy_or_abort` in `src/attestation.rs`).
- OS or CPU fallback RNGs (`getrandom`, `getentropy`, `RDRAND`) are prohibited by build-time hygiene checks; any `/dev/nsm` failure triggers immediate volatile memory scrubbing and hardware abort (`zeroize_and_abort`).
- `k_eph` is validated to be non-zero and strictly canonical ($1 \le k_{	ext{eph}} < q$, where $q$ is the `secp256k1` prime group order) and stored in a 64-byte cache-aligned `AlignedKeyBuffer` with `Drop` zeroization.

### 3.2 Cryptographic Binding into `/dev/nsm` Attestation Claims
- The enclave computes the 33-byte SEC 1 compressed public key $P_{	ext{eph}} = [k_{	ext{eph}}]G$ (`derive_compressed_public_key`) and binds $	ext{SHA-512}(P_{	ext{eph}})$ into the NSM `user_data` field alongside the single-use 256-bit `challenge_nonce` in the NSM `nonce` field and hardware-measured `PCR0`, `PCR1`, and `PCR2` registers.
- In production AWS KMS `Recipient` configurations (RSA-OAEP-SHA-256 SPKI `public_key` or `secp256k1` ECIES `user_data` binding), the Nitro Security Module signs the CBOR payload with its hardware-protected ECDSA-P384 attestation key (`COSE_Sign1` / ES384), chaining to the pinned AWS Nitro Enclaves Root CA (`src/aws_root_ca.rs`).

---

## 4. `AttestedKeyEnvelope` Wire Format & In-Enclave Authentication

When `proxy_bridge` relays `CiphertextForRecipient` back to the enclave via `CMD_KMS_RECIPIENT_UNWRAP` (`0x0007`), the enclave parses the fixed-size, zero-heap `AttestedKeyEnvelope` (258 bytes):

| Offset | Length | Field | Description |
| :--- | :--- | :--- | :--- |
| `0` | `32` | `challenge_nonce` | Single-use 256-bit challenge nonce bound to the active session. |
| `32` | `48` | `pcr0` | Expected/measured SHA-384 `PCR0` (Enclave Image File digest). |
| `80` | `48` | `pcr1` | Expected/measured SHA-384 `PCR1` (Linux kernel & bootstrap digest). |
| `128` | `48` | `pcr2` | Expected/measured SHA-384 `PCR2` (Application binary & metadata digest). |
| `176` | `33` | `sender_ephemeral_pubkey` | Sender/KMS 33-byte SEC 1 compressed `secp256k1` ephemeral public key $E_{	ext{kms}}$. |
| `209` | `32` | `wrapped_key` | Stream-encrypted 32-byte session blinding seed $r \oplus K_{	ext{enc}}$. |
| `241` | `16` | `auth_tag` | Truncated 128-bit SHA-512 keyed MAC tag over domain separator, recipient $P_{	ext{eph}}$, nonce, PCR0..2, $E_{	ext{kms}}$, and `wrapped_key`. |
| `257` | `1` | `key_len` | Plaintext secret byte length (must equal `32`). |

### 4.1 Constant-Time Key Derivation & EtM Authentication
1. **Curve Point Validation:** The enclave decodes $E_{	ext{kms}}$ (`ProjectivePoint::from_compressed_sec1`), enforcing prefix `0x02`/`0x03`, canonical coordinate $x < p$, quadratic residue existence $y^2 \equiv x^3 + 7 \pmod p$, and non-infinity.
2. **ECDH Shared Secret:** The enclave evaluates $S = [k_{	ext{eph}}]E_{	ext{kms}}$ using the constant-time 256-step Montgomery ladder (`ProjectivePoint::scalar_mul`), extracting the canonical 32-byte affine $x$-coordinate $Z_{	ext{ecdh}}$.
3. **Domain-Separated Key Derivation:**
   - Encryption key: $K_{	ext{enc}} = 	ext{SHA-512}(	ext{"NONA-KMS-RECIPIENT-ENC-V1"} \parallel Z_{	ext{ecdh}} \parallel P_{	ext{eph}} \parallel E_{	ext{kms}})[0..32]$
   - Authentication key: $K_{	ext{mac}} = 	ext{SHA-512}(	ext{"NONA-KMS-RECIPIENT-MAC-V1"} \parallel Z_{	ext{ecdh}} \parallel P_{	ext{eph}} \parallel E_{	ext{kms}})[0..32]$
4. **Encrypt-then-MAC Verification:** Before decrypting or storing any key material, the enclave computes $T' = 	ext{SHA-512}(K_{	ext{mac}} \parallel 	ext{"NONA-KMS-RECIPIENT-TAG-V1"} \parallel P_{	ext{eph}} \parallel 	ext{nonce} \parallel 	ext{PCR0} \parallel 	ext{PCR1} \parallel 	ext{PCR2} \parallel E_{	ext{kms}} \parallel 	ext{wrapped\_key})[0..16]$ and verifies $T' \stackrel{?}{=} 	ext{auth\_tag}$ in constant time (`ct_eq_16_bytes`).
5. **Scalar Canonicity Check:** The unwrapped 32-byte secret $r$ is validated as a non-zero canonical `secp256k1` scalar ($1 \le r < q$).

---

## 5. Replay Defense, Measurement Pinning & Immediate Ephemeral Key Zeroization

- **Single-Use Challenge Nonce & Replay Rejection:** Each `VsockSessionState` binds a fresh 256-bit challenge nonce during `CMD_ATTEST` and tracks consumed nonces in a bounded single-use replay table (`CONSUMED_NONCES`). Any `CMD_KMS_RECIPIENT_UNWRAP` frame carrying a mismatched, all-zero, or previously consumed nonce fails closed, purges all staging buffers, and transitions the session to `ClosedZeroized`.
- **Strict `PCR0`/`PCR1`/`PCR2` Policy Enforcement:** Enclave runtime policy pins expected `PCR0`, `PCR1`, and `PCR2` SHA-384 digests (`EXPECTED_PCR_POLICY`). Any single-bit deviation in `PCR0`, `PCR1`, or `PCR2` rejects the envelope and destroys session state.
- **Immediate Ephemeral Private Key Destruction (`write_volatile` + `SeqCst`):** Both `unwrap_attested_recipient_envelope` and the enclave session key release path execute `ct_zeroize` (`core::ptr::write_volatile` byte-by-byte overwrite followed by `core::sync::atomic::compiler_fence(Ordering::SeqCst)`) on the ephemeral private key buffer immediately upon unwrapping—and unconditionally on every error or teardown path—ensuring zero residual key-transport entropy in DRAM ($H(R) = 0$).
