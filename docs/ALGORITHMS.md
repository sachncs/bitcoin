# Algorithms

## DER Signature Parsing — `bitcoin/der.py`

**Purpose**: Parse DER-encoded ECDSA signatures with a trailing sighash byte.

**Implementation**: `parse_der_signature(signature: bytes) → ParsedSignature`

The parser follows strict DER encoding rules (BIP-66):

| Check | Condition | Error |
|-------|-----------|-------|
| Length | `9 ≤ len(signature) ≤ 73` | `InvalidDerSignatureError` |
| Sequence tag | `signature[0] == 0x30` | Missing sequence tag |
| Sequence length | `signature[1] == len(der) - 2` | Inconsistent length |
| R integer tag | `signature[2] == 0x02` | Missing R tag |
| S integer tag | `signature[rend] == 0x02` | Missing S tag |
| No leading zeros | `not (len > 1 and value[0] == 0 and value[1] < 0x80)` | Leading zero |
| Non-negative | `value[0] & 0x80 == 0` | Negative integer |
| Non-empty | `len(value) > 0` | Empty integer |

**Complexity**: O(n) where n is signature length (max 73 bytes).

**Edge cases**:
- Empty or single-byte signatures → caught by minimum length check
- Non-canonical encodings with extra leading zeros → caught by `validate_der_integer`
- Sighash byte extracted as `signature[-1]`, DER body is `signature[:-1]`

---

## Sighash Computation — `bitcoin/sighash.py`

### Legacy Sighash (pre-SegWit)

**Implementation**: `legacy_sighash(transaction, input_index, script_code, sighash_flag) → bytes`

Computes `sha256(sha256(payload))` where payload includes version, serialized inputs (with script_code substituted at `input_index`), serialized outputs, locktime, and sighash flag.

**SINGLE consensus rule**: If `base_type == SINGLE` and `input_index >= len(transaction.outputs)`, return `int_to_little_endian_bytes(1, 32)` (the Bitcoin consensus-required sentinel). This is logged at WARNING level.

### SegWit v0 Sighash (BIP-143)

**Implementation**: `segwit_sighash(transaction, input_index, script_code, amount, sighash_flag) → bytes`

Differs from legacy by:
- Amount is serialized in the payload (prevents fee theft)
- `hash_prevouts`, `hash_sequence`, `hash_outputs` are pre-computed
- Anyone-can-pay flips `hash_prevouts` and `hash_sequence` to `0x00...00`

**Edge cases**:
- `amount is None` → raises `MissingInputValueError` (logged at ERROR)
- `FLAG_SINGLE` with no matching output → `hash_outputs = b"\x00" * 32`
- `FLAG_NONE` → `hash_outputs = b"\x00" * 32`
- Anyone-can-pay with SINGLE or NONE → `hash_sequence = b"\x00" * 32`

### Taproot Sighash (BIP-341)

**Implementation**: `taproot_sighash(transaction, input_index, script_code, amount, sighash_flag, script_pubkeys, spend_type, annex) → bytes`

Uses tagged hashes (`SHA256(SHA256(tag) || SHA256(tag) || data)`) instead of double-SHA256.

Validates that all `input_values` in `transaction.context.input_values` are non-None before iteration (raises `MissingInputValueError` otherwise).

---

## ECC Point Arithmetic — `bitcoin/ecc.py`

### Point Negation — `point_negate_py`

```
-P = (x, -y mod p) for P = (x, y)
```

### Point Addition — `point_add_py`

Uses the standard affine addition formula:
```
m = (y₂ - y₁) / (x₂ - x₁) mod p
x₃ = m² - x₁ - x₂ mod p
y₃ = m(x₁ - x₃) - y₁ mod p
```

**Edge cases**:
- Either point is infinity → return the other point
- Points are inverses (x₁ = x₂, y₁ = -y₂) → return infinity
- Points are equal (x₁ = x₂, y₁ = y₂) → double instead

### Point Doubling — `point_double_py`

```
m = (3x₁² + a) / (2y₁) mod p
x₃ = m² - 2x₁ mod p
y₃ = m(x₁ - x₃) - y₁ mod p
```

Where `a = 0` for secp256k1.

### Scalar Multiplication — `_scalar_multiply_py`

Montgomery ladder (constant-time in iterations, not in memory access):

```
R0 = infinity
R1 = P
for each bit of scalar (MSB to LSB):
    if bit == 0:
        R1 = R0 + R1
        R0 = 2 * R0
    else:
        R0 = R0 + R1
        R1 = 2 * R1
return R0
```

**Edge cases**: scalar 0 or infinity point → returns infinity. Scalar is reduced modulo `SECP256K1_ORDER` first.

### Backend Dispatch

All point operations check `get_backend()` first:
- If a backend is active → dispatch to backend
- If `None` → fall back to pure Python `_py` functions
- Fallback is logged at DEBUG level

---

## Modular Inverse — `bitcoin/arithmetic.py`

**Implementation**: `inverse_mod(value, modulus)` (extended Euclidean algorithm)

```
old_r, r = modulus, value
old_t, t = 0, 1
while r != 0:
    quotient = old_r // r
    old_r, r = r, old_r - quotient * r
    old_t, t = t, old_t - quotient * t
if old_r != 1: raise NotInvertibleError
return old_t % modulus
```

**Input validation**:
- `type(value) is not int` → TypeError (rejects bool)
- `type(modulus) is not int` → TypeError (via `isinstance`)
- `modulus <= 1` → ValueError
- `value < 0` → ValueError
- `value == 0` → NotInvertibleError
- GCD(value, modulus) != 1 → NotInvertibleError

**Complexity**: O(log(min(value, modulus))) iterations.

---

## Linear Coefficient Derivation — `bitcoin/linear.py`

**Implementation**: `derive_linear_coefficients(signature_record) → LinearCoefficientRecord`

Given extracted `(r, s, z)` from an ECDSA signature:

```
α ≡ s · r⁻¹ (mod n)
β ≡ z · r⁻¹ (mod n)
```

Where `n` is `SECP256K1_ORDER`.

**The derived relation**:
```
d' ≡ αk (mod n)
```
Where `d' = d + β` is the transformed private key.

**Input validation**:
- `r` must be non-zero and < n
- `s` must be non-zero and < n
- `z` must be non-negative and < n (not strictly required by formula, but validated)
- All values must be valid hex strings (may start with `0x`)

---

## SEC Public Key Parsing — `bitcoin/ecc.py`

### Compressed SEC (33 bytes, prefix 0x02/0x03)

```
x = int.from_bytes(data[1:33], "big")
y = sqrt(x³ + 7 mod p)  # via field_sqrt_py
if (y % 2) != expected_parity:
    y = (-y) % p
```

### Uncompressed SEC (65 bytes, prefix 0x04)

```
x = int.from_bytes(data[1:33], "big")
y = int.from_bytes(data[33:], "big")
return Secp256k1Point(x=x, y=y)
```

### SEC Serialization — `serialize_sec_py`

Compressed: `0x02/0x03 || x.to_bytes(32, "big")`
Uncompressed: `0x04 || x.to_bytes(32, "big") || y.to_bytes(32, "big")`

Infinity point raises `InvalidSecPublicKeyError`.

---

## Field Square Root — `bitcoin/ecc.py`

**Implementation**: `field_sqrt_py(value)` (Tonelli-Shanks specialization for p ≡ 3 mod 4)

```
root = value^((p + 1) / 4) mod p
if root² mod p != value mod p:
    raise InvalidSecp256k1PointError("No square root")
return root
```

This works because secp256k1's field prime `p = 2²⁵⁶ - 2³² - 977` satisfies `p ≡ 3 (mod 4)`.
