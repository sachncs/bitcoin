"""Test vectors from BIP-143 (SegWit) — real mainnet test data."""

from __future__ import annotations

from bitcoin.curve import GENERATOR, Point, multiply, add
from bitcoin.curve.params import CURVE_ORDER
from bitcoin.encoding.der import decode_der
from bitcoin.encoding.hex import decode_hex
from bitcoin.script.builder import build_p2tr
from bitcoin.script.classifier import P2PK, P2WPKH, P2TR
from bitcoin.script.opcodes import OP_CHECKSIG
from bitcoin.script.parser import serialize_script
from bitcoin.signature import extract_signatures
from bitcoin.transaction.models import Tx, TxIn, TxOut, OutPoint, Witness
from bitcoin.transaction.parser import parse_tx
from bitcoin.services.serializer import serialize_tx
from bitcoin.encoding.hasher import tagged_hash


def _point_to_xonly(p: Point) -> bytes:
    """Convert a Point to 32-byte x-only representation."""
    if p.x is None:
        return b"\x00" * 32
    return int.to_bytes(p.x, 32, "big")


# ── Helper ───────────────────────────────────────────────────────────────


def _parse_tx(hex_str: str) -> Tx:
    tx, _ = parse_tx(decode_hex(hex_str.strip()))
    return tx


# ═══════════════════════════════════════════════════════════════════════════
# BIP-143: Native P2WPKH
# ═══════════════════════════════════════════════════════════════════════════

BIP143_P2WPKH_SIGNED = (
    "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad9"
    "69f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d"
    "114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc6"
    "18ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b9"
    "0ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95"
    "a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f016"
    "7faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12f"
    "b1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02d"
    "e67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6"
    "35711000000")

BIP143_P2WPKH_UTXO_SCRIPTS = [
    decode_hex(
        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"
    ),
    decode_hex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"),
]
BIP143_P2WPKH_UTXO_VALUES = [625_000_000, 600_000_000]

# ═══════════════════════════════════════════════════════════════════════════
# BIP-143: P2SH-P2WPKH
# ═══════════════════════════════════════════════════════════════════════════

BIP143_P2SH_P2WPKH_SIGNED = (
    "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5"
    "477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb"
    "0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f0000"
    "00001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e8"
    "78352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae9"
    "03c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74"
    "d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000")

BIP143_P2SH_P2WPKH_UTXO_SCRIPTS = [
    decode_hex("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"),
]
BIP143_P2SH_P2WPKH_UTXO_VALUES = [10_0000_0000]

# ═══════════════════════════════════════════════════════════════════════════
# Synthesised Taproot key-path spend
# ═══════════════════════════════════════════════════════════════════════════


def build_taproot_keypath_tx() -> tuple[Tx, bytes]:
    """Build a Taproot key-path spending transaction (mock Schnorr sig)."""
    priv = 42
    pub = multiply(priv, GENERATOR)
    xonly = _point_to_xonly(pub)
    script_pubkey = build_p2tr(xonly)

    mock_schnorr_sig = b"\x01" * 64
    txin = TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF,
                Witness((mock_schnorr_sig,)))
    txout = TxOut(100_000_000, script_pubkey)
    tx = Tx(2, (txin,), (txout,), 0)
    return tx, script_pubkey


# ═══════════════════════════════════════════════════════════════════════════
# Synthesised Taproot script-path spend
# ═══════════════════════════════════════════════════════════════════════════


def build_taproot_scriptpath_tx() -> tuple[Tx, bytes]:
    """Build a Taproot script-path spending transaction (mock Schnorr sig)."""
    priv = 42
    pub = multiply(priv, GENERATOR)
    xonly = _point_to_xonly(pub)

    script = serialize_script([xonly, OP_CHECKSIG])
    leaf_version = 0xC0

    leaf_hash = tagged_hash(
        "TapLeaf",
        bytes([leaf_version]) + bytes([len(script)]) + script,
    )

    tweak = tagged_hash("TapTweak", xonly + leaf_hash)
    tweak_int = int.from_bytes(tweak, "big")
    if tweak_int >= CURVE_ORDER:
        tweak_int = 1
    Q = add(pub, multiply(tweak_int, GENERATOR))
    q_xonly = _point_to_xonly(Q)
    script_pubkey = build_p2tr(q_xonly)

    mock_schnorr_sig = b"\x02" * 64
    control_block = bytes([leaf_version | 0]) + xonly
    witness_items = (mock_schnorr_sig, script, control_block)
    txin = TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF,
                Witness(witness_items))
    txout = TxOut(100_000_000, script_pubkey)
    tx = Tx(2, (txin,), (txout,), 0)
    return tx, script_pubkey


# ═══════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestBip143P2WPKH:
    """BIP-143 Native P2WPKH test vector — real signed SegWit transaction."""

    def test_parse_signed(self) -> None:
        tx = _parse_tx(BIP143_P2WPKH_SIGNED)
        assert tx.version == 1
        assert len(tx.inputs) == 2
        assert len(tx.outputs) == 2
        assert tx.is_segwit()

    def test_extract_signatures(self) -> None:
        tx = _parse_tx(BIP143_P2WPKH_SIGNED)
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=BIP143_P2WPKH_UTXO_SCRIPTS,
            utxo_values=BIP143_P2WPKH_UTXO_VALUES,
        )
        assert len(records) == 2
        script_types = {r.script_type for r in records}
        assert P2PK in script_types
        assert P2WPKH in script_types
        for r in records:
            assert not r.public_key.infinity, f"Pubkey recovery failed for vin={r.vin}"

    def test_signatures_parse_correctly(self) -> None:
        tx = _parse_tx(BIP143_P2WPKH_SIGNED)
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=BIP143_P2WPKH_UTXO_SCRIPTS,
            utxo_values=BIP143_P2WPKH_UTXO_VALUES,
        )
        for r in records:
            r_int, s_int = decode_der(r.sig)
            assert r_int > 0
            assert s_int > 0


class TestBip143P2SHP2WPKH:
    """BIP-143 P2SH-P2WPKH test vector."""

    def test_parse_signed(self) -> None:
        tx = _parse_tx(BIP143_P2SH_P2WPKH_SIGNED)
        assert tx.version == 1
        assert len(tx.inputs) == 1
        assert tx.is_segwit()

    def test_extract_signatures(self) -> None:
        tx = _parse_tx(BIP143_P2SH_P2WPKH_SIGNED)
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=BIP143_P2SH_P2WPKH_UTXO_SCRIPTS,
            utxo_values=BIP143_P2SH_P2WPKH_UTXO_VALUES,
        )
        assert len(records) == 1
        r = records[0]
        assert not r.public_key.infinity
        assert r.script_type == "p2sh_p2wpkh"
        assert r.amount == BIP143_P2SH_P2WPKH_UTXO_VALUES[0]


class TestTaprootKeyPathSpend:
    """Synthesised Taproot key-path spend — extracted via the library."""

    def test_build_and_extract(self) -> None:
        tx, script_pubkey = build_taproot_keypath_tx()
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=[script_pubkey],
            utxo_values=[100_000_000],
        )
        assert len(records) == 1
        r = records[0]
        assert r.script_type == P2TR
        assert len(r.sig) in (64, 65)
        assert not r.public_key.infinity

    def test_parse_roundtrip(self) -> None:
        tx, script_pubkey = build_taproot_keypath_tx()
        raw = serialize_tx(tx)
        tx2, _ = parse_tx(raw)
        assert len(tx2.inputs) == 1
        assert tx2.is_segwit()
        assert tx2.inputs[0].witness.items


class TestTaprootScriptPathSpend:
    """Synthesised Taproot script-path spend — verifies extraction can identify it."""

    def test_build_and_parse(self) -> None:
        tx, script_pubkey = build_taproot_scriptpath_tx()
        raw = serialize_tx(tx)
        tx2, _ = parse_tx(raw)
        assert len(tx2.inputs) == 1
        assert tx2.is_segwit()
        items = tx2.inputs[0].witness.items
        assert len(items) >= 3  # sig, script, control_block

    def test_extract_script_path_signature(self) -> None:
        tx, script_pubkey = build_taproot_scriptpath_tx()
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=[script_pubkey],
            utxo_values=[100_000_000],
        )
        assert len(records) == 1
        r = records[0]
        assert r.script_type == P2TR
        assert len(r.sig) in (64, 65)
