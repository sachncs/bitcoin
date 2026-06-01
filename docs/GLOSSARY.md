# Glossary

## A

**α (Alpha)** — Linear coefficient `α = s · r⁻¹ (mod n)` in the linearized ECDSA identity `d ≡ α·k − β`.

## B

**β (Beta)** — Linear coefficient `β = z · r⁻¹ (mod n)`.

## D

**DER** — Distinguished Encoding Rules (X.690). Strict BIP-66 DER is used for ECDSA signature encoding.

## E

**ECDSA** — Elliptic Curve Digital Signature Algorithm, as used by Bitcoin over the secp256k1 curve.

## G

**GENERATOR** — The secp256k1 generator point, a constant in `curve/params.py`.

## K

**k** — The ephemeral nonce used in ECDSA signing. Must be unique per signature. Reuse leaks the private key via `recover_from_nonce_reuse`.

## L

**Linear Coefficient** — Pair `(α, β)` derived from `(r, s, z)` that linearly relates the private key `d` to the nonce `k`: `d ≡ α·k − β (mod n)`.

**LinearCoefficientCollection** — Collection of `LinearCoefficientRecord` instances, used for nonce-reuse detection.

## M

**MAST** — Merklized Abstract Syntax Tree. Allows spending conditions in Taproot to be revealed only when used. See BIP-341.

## N

**n** — The order of the secp256k1 curve, a 256-bit prime.

**Nonce** — Cryptographic "number used once". In ECDSA, the value `k` in signing.

**NonceReuseGroup** — Dataclass grouping signatures that share the same `r` value.

## O

**OutPoint** — Reference to a previous transaction output: `(txid, vout)`.

**OP_RETURN** — Script opcode marking provably unspendable outputs. Classified via `is_op_return()`.

## P

**P2PK** — Pay to Public Key (obsolete, but still supported).

**P2PKH** — Pay to Public Key Hash.

**P2SH** — Pay to Script Hash.

**P2WPKH** — Pay to Witness Public Key Hash (SegWit v0).

**P2WSH** — Pay to Witness Script Hash (SegWit v0).

**P2TR** — Pay to Taproot (SegWit v1, BIP-341).

**PSBT** — Partially Signed Bitcoin Transaction (BIP-174).

## R

**r** — The x-coordinate of `R = k·G`, the first component of an ECDSA signature.

**Record** — Frozen dataclass holding a single extracted signature result with txid, vin, sig, public key, script type, and sighash flag.

**RecoveredKey** — Dataclass holding the recovered private key and nonce from a nonce-reuse attack.

## S

**s** — The second component of an ECDSA signature: `s = k⁻¹(z + r·d)`.

**Schnorr** — Schnorr signature algorithm (BIP-340), used in Taproot.

**SEC** — Standard for Efficient Cryptography. Used for public key encoding (compressed/uncompressed).

**Script classification** — Categorizing output scripts into known types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, etc.).

**ScriptPath** — A spending condition in Taproot, revealed as a script + control block in the witness.

**Sighash** — The hash that is signed for a given transaction input.

## T

**Taproot** — SegWit version 1 (BIP-341). Supports key-path and script-path spending.

**Tx** — Frozen dataclass representing a parsed Bitcoin transaction.

**TxIn** — Transaction input.

**TxOut** — Transaction output.

## W

**Witness** — SegWit witness data, consisting of a stack of byte vectors.

## X

**x-only pubkey** — A 32-byte compressed public key without the sign byte, used in Schnorr/Taproot (BIP-340).

## Z

**z** — The message hash (sighash) in bytes. Signed as an integer `z = bytes_to_int(hash)`.
