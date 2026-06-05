"""Test against a known-good real Bitcoin mainnet transaction (Pizza Transaction)."""

import os

from bitcoin.transaction.parser import parse_tx
from bitcoin.services.serializer import serialize_tx
from bitcoin.sighash.legacy import sighash_legacy
from bitcoin.sighash.flag import SIGHASH_ALL
from bitcoin.signature.check import verify_sig
from bitcoin.encoding.sec import serialize_sec, parse_sec
from bitcoin.encoding.hasher import hash160

EXPECTED_TXID = "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
PIZZA_HEX_PATH = os.path.join(DATA_DIR, "pizza_tx.hex")


def load_pizza_tx() -> bytes:
    with open(PIZZA_HEX_PATH) as f:
        return bytes.fromhex(f.read().strip())


class TestPizzaTransaction:
    def test_parse_and_txid(self) -> None:
        raw = load_pizza_tx()
        tx, _ = parse_tx(raw)
        assert tx.txid()[::-1].hex() == EXPECTED_TXID

    def test_serialize_roundtrip(self) -> None:
        raw = load_pizza_tx()
        tx, _ = parse_tx(raw)
        assert serialize_tx(tx) == raw

    def test_first_input_sighash_and_verify(self) -> None:
        raw = load_pizza_tx()
        tx, _ = parse_tx(raw)

        script_sig = tx.inputs[0].script_sig
        sig_push_len = script_sig[0]
        sig_plus_flag = script_sig[1 : 1 + sig_push_len]
        der_sig = sig_plus_flag[:-1]
        sig_flag = sig_plus_flag[-1]
        pubkey_push_len = script_sig[1 + sig_push_len]
        pubkey_bytes = script_sig[2 + sig_push_len : 2 + sig_push_len + pubkey_push_len]

        assert sig_flag == SIGHASH_ALL

        pubkey_hash = hash160(pubkey_bytes)
        script_pubkey = bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])

        z = sighash_legacy(tx, 0, script_pubkey, sig_flag)
        assert len(z) == 32

        pubkey_point = parse_sec(pubkey_bytes)
        assert verify_sig(z, der_sig, pubkey_point)

    def test_serialize_sec(self) -> None:
        raw = load_pizza_tx()
        tx, _ = parse_tx(raw)

        script_sig = tx.inputs[0].script_sig
        sig_push_len = script_sig[0]
        pubkey_push_len = script_sig[1 + sig_push_len]
        pubkey_bytes = script_sig[2 + sig_push_len : 2 + sig_push_len + pubkey_push_len]

        pubkey_point = parse_sec(pubkey_bytes)
        assert serialize_sec(pubkey_point, compressed=False) == pubkey_bytes
        compressed = serialize_sec(pubkey_point, compressed=True)
        assert len(compressed) == 33
        assert compressed[0] in (0x02, 0x03)
