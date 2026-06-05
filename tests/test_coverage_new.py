"""Coverage tests for low-coverage modules and new features."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from bitcoin.curve import GENERATOR, multiply
from bitcoin.curve.params import FIELD_PRIME
from bitcoin.encoding.der import encode_der
from bitcoin.encoding.hasher import hash256, sha256
from bitcoin.script import (
    build_p2pkh,
    build_p2wpkh,
)
from bitcoin.script.classifier import (
    P2PK,
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    NON_STANDARD,
    MULTISIG,
    TIMELOCK,
    classify_script_pubkey,
    classify_script_sig,
    classify_detailed,
    is_p2sh,
    is_op_return,
    is_bare_multisig,
    has_timelocks,
    parse_p2pkh_script_sig,
)
from bitcoin.script.taproot import (
    TaprootScriptPath,
    parse_taproot_witness_stack,
    extract_taproot_scripts,
    get_x_only_pubkey,
)
from bitcoin.signature import (
    Record,
    batch_extract,
    batch_extract_from_file,
    correlate_across_transactions,
    merge_records,
    sign,
    sign_tx_input,
    verify_sig,
)
from bitcoin.signature.batch_verify import batch_verify
from bitcoin.signature.extraction.plugins import (
    ExtractorPlugin,
    register_plugin,
    unregister_plugin,
    get_plugin,
    list_plugins,
)
from bitcoin.signature.pipeline import BatchResult
from bitcoin.services.blockchain import (
    BlockstreamProvider,
    BlockchainInfoProvider,
    MempoolSpaceProvider,
    enrich_transaction,
    fetch_and_extract,
    fetch_text,
)
from bitcoin.transaction import (
    Tx,
    TxIn,
    TxOut,
    OutPoint,
    Witness,
    TransactionBuilder,
    tx_from_dict,
    make_tx,
    is_opt_in_rbf,
    has_sequence_lock,
)
from bitcoin.transaction.models import EMPTY_WITNESS
from bitcoin.psbt import Psbt, PsbtInput, PsbtOutput, PsbtEditor
from bitcoin.psbt.editor import MutableInput, MutableOutput
from bitcoin.services.serializer import serialize_legacy_tx, serialize_tx
from bitcoin.sighash.flag import SIGHASH_ALL

# ── helpers ────────────────────────────────────────────────────────

TEST_PUB = multiply(1, GENERATOR)
TEST_PUB_SEC = TEST_PUB.to_sec_compressed()
TEST_PUB_HASH = hash256(TEST_PUB_SEC)[:20]


def make_test_tx() -> Tx:
    return Tx(
        version=2,
        inputs=(
            TxIn(
                previous_output=OutPoint(txid=b"\x01" * 32, vout=0),
                script_sig=b"",
                sequence=0xFFFFFFFF,
                witness=EMPTY_WITNESS,
            ),
        ),
        outputs=(
            TxOut(value=10000, script_pubkey=build_p2pkh(TEST_PUB_HASH)),
        ),
        lock_time=0,
    )


# ===================================================================
# plugins.py (0 % coverage)
# ===================================================================

class DummyPlugin:
    name = "dummy"

    def can_handle(self, script_type: str, is_segwit: bool) -> bool:
        return script_type == "dummy"

    def extract(
        self, tx: Tx, vin: int, txin: TxIn,
        script_pubkey: bytes, value: int,
    ) -> list[Record]:
        return []


class TestPluginRegistry:
    def test_register_and_list(self) -> None:
        register_plugin(DummyPlugin())
        assert "dummy" in list_plugins()
        unregister_plugin("dummy")
        assert "dummy" not in list_plugins()

    def test_get_plugin(self) -> None:
        register_plugin(DummyPlugin())
        p = get_plugin("dummy")
        assert p is not None
        assert p.name == "dummy"
        unregister_plugin("dummy")

    def test_unregister_nonexistent(self) -> None:
        unregister_plugin("nonexistent")

    def test_get_nonexistent(self) -> None:
        assert get_plugin("nonexistent") is None

    def test_runtime_checkable(self) -> None:
        assert isinstance(DummyPlugin(), ExtractorPlugin)


# ===================================================================
# builder.py (10 % coverage)
# ===================================================================

class TestTransactionBuilder:
    def test_basic_build(self) -> None:
        tx = (
            TransactionBuilder()
            .add_input(txid=b"\x01" * 32, vout=0)
            .add_output(
                value=50000,
                script_pubkey=b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac",
            )
            .build()
        )
        assert len(tx.inputs) == 1
        assert len(tx.outputs) == 1
        assert tx.version == 2

    def test_custom_version(self) -> None:
        tx = (
            TransactionBuilder(version=1)
            .add_input(txid=b"\x02" * 32, vout=1)
            .add_output(value=1000, script_pubkey=b"\x00" * 25)
            .build()
        )
        assert tx.version == 1

    def test_negative_version(self) -> None:
        with pytest.raises(ValueError, match="Version must be non-negative"):
            TransactionBuilder(version=-1)

    def test_add_output_chaining(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid=b"\x01" * 32, vout=0)
        b.add_output(value=100, script_pubkey=b"\x00" * 25)
        b.add_output(value=200, script_pubkey=b"\x01" * 25)
        tx = b.build()
        assert len(tx.outputs) == 2

    def test_set_lock_time(self) -> None:
        tx = (
            TransactionBuilder()
            .add_input(txid=b"\x01" * 32, vout=0)
            .add_output(value=1000, script_pubkey=b"\x00" * 25)
            .set_lock_time(500000)
            .build()
        )
        assert tx.lock_time == 500000

    def test_set_lock_time_negative(self) -> None:
        with pytest.raises(ValueError, match="Lock time must be non-negative"):
            TransactionBuilder().set_lock_time(-1)

    def test_build_no_inputs(self) -> None:
        with pytest.raises(ValueError, match="At least one input"):
            (
                TransactionBuilder()
                .add_output(value=100, script_pubkey=b"\x00" * 25)
                .build()
            )

    def test_build_no_outputs(self) -> None:
        with pytest.raises(ValueError, match="At least one output"):
            TransactionBuilder().add_input(txid=b"\x01" * 32, vout=0).build()

    def test_witness_input(self) -> None:
        tx = (
            TransactionBuilder()
            .add_input(
                txid=b"\x03" * 32, vout=0, witness=(b"\x00" * 64, b"\x01" * 33),
            )
            .add_output(value=1000, script_pubkey=b"\x00" * 25)
            .build()
        )
        assert len(tx.inputs[0].witness.items) == 2

    def test_bad_txid_type(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid="not_bytes", vout=0)  # type: ignore[arg-type]
        b.add_output(value=100, script_pubkey=b"\x00" * 25)
        with pytest.raises(ValueError, match="txid must be bytes"):
            b.build()

    def test_bad_vout_type(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid=b"\x01" * 32, vout="zero")  # type: ignore[arg-type]
        b.add_output(value=100, script_pubkey=b"\x00" * 25)
        with pytest.raises(ValueError, match="vout must be int"):
            b.build()

    def test_bad_script_sig_type(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid=b"\x01" * 32, vout=0, script_sig=123)  # type: ignore[arg-type]
        b.add_output(value=100, script_pubkey=b"\x00" * 25)
        with pytest.raises(ValueError, match="script_sig must be bytes"):
            b.build()

    def test_bad_sequence_type(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid=b"\x01" * 32, vout=0, sequence="max")  # type: ignore[arg-type]
        b.add_output(value=100, script_pubkey=b"\x00" * 25)
        with pytest.raises(ValueError, match="sequence must be int"):
            b.build()

    def test_bad_witness_type(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid=b"\x01" * 32, vout=0, witness=[b"x"])  # type: ignore[arg-type]
        b.add_output(value=100, script_pubkey=b"\x00" * 25)
        with pytest.raises(ValueError, match="witness must be a tuple"):
            b.build()

    def test_bad_witness_item_type(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid=b"\x01" * 32, vout=0, witness=(123,))  # type: ignore[arg-type]
        b.add_output(value=100, script_pubkey=b"\x00" * 25)
        with pytest.raises(ValueError, match="witness items must be bytes"):
            b.build()

    def test_bad_output_value_type(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid=b"\x01" * 32, vout=0)
        b.add_output(value="lots", script_pubkey=b"\x00" * 25)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="value must be int"):
            b.build()

    def test_bad_output_script_type(self) -> None:
        b = TransactionBuilder()
        b.add_input(txid=b"\x01" * 32, vout=0)
        b.add_output(value=100, script_pubkey=123)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="script_pubkey must be bytes"):
            b.build()


class TestTxFromDict:
    def test_basic(self) -> None:
        tx = tx_from_dict({
            "version": 2,
            "inputs": [{"txid": b"\x01" * 32, "vout": 0}],
            "outputs": [{"value": 1000, "script_pubkey": b"\x00" * 25}],
        })
        assert len(tx.inputs) == 1
        assert tx.version == 2

    def test_not_dict(self) -> None:
        with pytest.raises(ValueError, match="must be a dict"):
            tx_from_dict("bad")  # type: ignore[arg-type]

    def test_missing_version(self) -> None:
        with pytest.raises(ValueError, match="version must be an int"):
            tx_from_dict({"inputs": [], "outputs": []})

    def test_bad_version_type(self) -> None:
        with pytest.raises(ValueError, match="version must be an int"):
            tx_from_dict({"version": "2", "inputs": [], "outputs": []})

    def test_missing_inputs(self) -> None:
        with pytest.raises(ValueError, match="inputs must be a sequence"):
            tx_from_dict({"version": 2, "outputs": []})

    def test_bad_inputs_type(self) -> None:
        with pytest.raises(ValueError, match="inputs must be a sequence"):
            tx_from_dict({"version": 2, "inputs": "bad", "outputs": []})

    def test_bad_outputs_type(self) -> None:
        with pytest.raises(ValueError, match="outputs must be a sequence"):
            tx_from_dict({"version": 2, "inputs": [], "outputs": "bad"})

    def test_bad_lock_time(self) -> None:
        with pytest.raises(ValueError, match="lock_time must be an int"):
            tx_from_dict({
                "version": 2, "inputs": [], "outputs": [], "lock_time": "zero",
            })

    def test_input_not_dict(self) -> None:
        with pytest.raises(ValueError, match="Each input must be a dict"):
            tx_from_dict({
                "version": 2,
                "inputs": ["not_dict"],
                "outputs": [{"value": 100, "script_pubkey": b"\x00"}],
            })

    def test_input_missing_txid(self) -> None:
        with pytest.raises(ValueError, match="Each input must have a bytes txid"):
            tx_from_dict({
                "version": 2,
                "inputs": [{"vout": 0}],
                "outputs": [{"value": 100, "script_pubkey": b"\x00"}],
            })

    def test_input_bad_vout(self) -> None:
        with pytest.raises(ValueError, match="Each input must have an int vout"):
            tx_from_dict({
                "version": 2,
                "inputs": [{"txid": b"\x01" * 32, "vout": "zero"}],
                "outputs": [{"value": 100, "script_pubkey": b"\x00"}],
            })

    def test_output_not_dict(self) -> None:
        with pytest.raises(ValueError, match="Each output must be a dict"):
            tx_from_dict({
                "version": 2,
                "inputs": [{"txid": b"\x01" * 32, "vout": 0}],
                "outputs": ["not_dict"],
            })

    def test_output_missing_value(self) -> None:
        with pytest.raises(ValueError, match="Each output must have an int value"):
            tx_from_dict({
                "version": 2,
                "inputs": [{"txid": b"\x01" * 32, "vout": 0}],
                "outputs": [{"script_pubkey": b"\x00"}],
            })

    def test_output_missing_script(self) -> None:
        with pytest.raises(ValueError, match="bytes script_pubkey"):
            tx_from_dict({
                "version": 2,
                "inputs": [{"txid": b"\x01" * 32, "vout": 0}],
                "outputs": [{"value": 100}],
            })

    def test_with_lock_time(self) -> None:
        tx = tx_from_dict({
            "version": 2,
            "inputs": [{"txid": b"\x01" * 32, "vout": 0}],
            "outputs": [{"value": 1000, "script_pubkey": b"\x00" * 25}],
            "lock_time": 100,
        })
        assert tx.lock_time == 100

    def test_with_optional_fields(self) -> None:
        tx = tx_from_dict({
            "version": 2,
            "inputs": [{
                "txid": b"\x01" * 32,
                "vout": 0,
                "script_sig": b"\x00",
                "sequence": 0xFFFFFFFE,
                "witness": (b"\x01" * 64,),
            }],
            "outputs": [{"value": 1000, "script_pubkey": b"\x00" * 25}],
        })
        assert tx.inputs[0].sequence == 0xFFFFFFFE
        assert len(tx.inputs[0].witness.items) == 1


# ===================================================================
# signer.py (24 % coverage)
# ===================================================================

class TestSigner:
    def test_sign_and_verify(self) -> None:
        priv = 12345
        msg = sha256(b"hello")
        sig = sign(msg, priv)
        pub = multiply(priv, GENERATOR)
        assert verify_sig(msg, sig, pub)

    def test_sign_bad_hash_length(self) -> None:
        with pytest.raises(ValueError, match="Message hash must be 32 bytes"):
            sign(b"short", 1)

    def test_sign_tx_input_legacy(self) -> None:
        priv = 42
        tx = make_test_tx()
        script_pubkey = build_p2pkh(TEST_PUB_HASH)
        sig = sign_tx_input(tx, 0, priv, script=script_pubkey, value=0)
        assert 70 < len(sig) < 74
        assert sig[-1] == SIGHASH_ALL

    def test_sign_tx_input_segwit(self) -> None:
        priv = 99
        tx = Tx(
            version=2,
            inputs=(
                TxIn(
                    previous_output=OutPoint(txid=b"\x01" * 32, vout=0),
                    script_sig=b"",
                    sequence=0xFFFFFFFF,
                    witness=Witness((b"\x02" * 64,)),
                ),
            ),
            outputs=(
                TxOut(value=10000, script_pubkey=build_p2wpkh(TEST_PUB_HASH)),
            ),
            lock_time=0,
        )
        sig = sign_tx_input(
            tx, 0, priv, script=build_p2wpkh(TEST_PUB_HASH), value=10000
        )
        assert sig[-1] == SIGHASH_ALL


# ===================================================================
# pipeline.py (25 % coverage)
# ===================================================================

class TestPipeline:
    def test_batch_extract_single(self) -> None:
        tx = make_test_tx()
        raw = serialize_tx(tx)
        result = batch_extract([raw.hex()])
        assert result.total_transactions == 1
        assert result.successful == 0
        assert result.failed == 1
        assert "No signatures found" in result.errors[0][1]

    def test_batch_extract_bytes(self) -> None:
        tx = make_test_tx()
        raw = serialize_tx(tx)
        result = batch_extract([raw])
        assert result.successful == 0
        assert "No signatures found" in result.errors[0][1]

    def test_batch_extract_multiple(self) -> None:
        tx1 = make_test_tx()
        tx2 = make_test_tx()
        result = batch_extract(
            [serialize_tx(tx1).hex(), serialize_tx(tx2).hex()],
        )
        assert result.total_transactions == 2
        assert result.failed == 2

    def test_batch_extract_with_utxo(self) -> None:
        tx = make_test_tx()
        raw = serialize_tx(tx)
        script = build_p2pkh(TEST_PUB_HASH)
        result = batch_extract(
            [raw.hex()],
            utxo_scripts=[[script]],
            utxo_values=[[10000]],
        )
        assert result.successful == 0
        assert "No signatures found" in result.errors[0][1]

    def test_batch_extract_length_mismatch(self) -> None:
        with pytest.raises(ValueError, match="must match"):
            batch_extract(
                ["aaaa"],
                utxo_scripts=[[b"\x00"], [b"\x01"]],
            )

    def test_batch_extract_with_errors(self) -> None:
        result = batch_extract(["not_a_valid_hex_string"])
        assert result.failed == 1
        assert len(result.errors) == 1

    def test_batch_extract_parallel(self) -> None:
        tx = make_test_tx()
        raw = serialize_tx(tx)
        result = batch_extract([raw.hex()] * 3, max_workers=2)
        assert result.successful == 0
        assert result.failed == 3

    def test_batch_extract_from_file(self, tmp_path: object) -> None:
        tx = make_test_tx()
        raw = serialize_tx(tx).hex()
        f = tmp_path / "txs.txt"  # type: ignore[operator]
        f.write_text(f"{raw}\n{raw}\n")  # type: ignore[union-attr]
        result = batch_extract_from_file(str(f))  # type: ignore[arg-type]
        assert result.successful == 0
        assert result.failed == 2

    def test_batch_extract_from_file_with_comments(self, tmp_path: object) -> None:
        from bitcoin.transaction.models import Tx, TxIn, TxOut, OutPoint, Witness
        from bitcoin.services.serializer import serialize_legacy_tx
        from bitcoin.script import build_p2pkh
        from bitcoin.script.parser import serialize_script
        priv = 42
        txin = TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF, Witness(()))
        txout = TxOut(1000, build_p2pkh(TEST_PUB_HASH))
        tx = Tx(2, (txin,), (txout,), 0)
        sig = sign_tx_input(tx, 0, priv, script=build_p2pkh(TEST_PUB_HASH), value=0)
        pubkey = multiply(priv, GENERATOR)
        scriptsig = serialize_script([sig, pubkey.to_sec_compressed()])
        txin2 = TxIn(OutPoint(b"\x01" * 32, 0), scriptsig, 0xFFFFFFFF, Witness(()))
        tx2 = Tx(2, (txin2,), (txout,), 0)
        raw = serialize_legacy_tx(tx2).hex()
        f = tmp_path / "txs.txt"  # type: ignore[operator]
        f.write_text(f"# comment\n{raw}\n\n{raw}\n")  # type: ignore[union-attr]
        result = batch_extract_from_file(str(f))  # type: ignore[arg-type]
        assert result.successful == 2

    def test_batch_extract_from_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            batch_extract_from_file("/nonexistent/file.txt")

    def test_merge_records(self) -> None:
        r1 = Record(
            txid=b"\x01" * 32, input_index=0,
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR, script_type="p2pkh", sighash_flag=1, amount=0,
        )
        r2 = Record(
            txid=b"\x02" * 32, input_index=0,
            signature=b"\x30\x06\x02\x01\x02\x02\x01\x02",
            public_key=GENERATOR, script_type="p2pkh", sighash_flag=1, amount=0,
        )
        result1 = BatchResult(records=[r1], total_transactions=1, successful=1)
        result2 = BatchResult(records=[r2], total_transactions=1, successful=1)
        merged = merge_records([result1, result2])
        assert len(merged) == 2

    def test_merge_records_dedup(self) -> None:
        rec = Record(
            txid=b"\x01" * 32, input_index=0,
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR, script_type="p2pkh", sighash_flag=1, amount=0,
        )
        result = BatchResult(records=[rec, rec], total_transactions=2, successful=2)
        merged = merge_records([result])
        assert len(merged) == 1

    def test_correlate_across_transactions(self) -> None:
        sig = encode_der(42, 7)
        records = [
            Record(
                txid=b"\x01" * 32, input_index=0, signature=sig,
                public_key=GENERATOR, script_type="p2pkh", sighash_flag=1, amount=0,
            ),
            Record(
                txid=b"\x02" * 32, input_index=0, signature=sig,
                public_key=GENERATOR, script_type="p2pkh", sighash_flag=1, amount=0,
            ),
        ]
        groups = correlate_across_transactions(records)
        assert list(groups) == ["p2pkh"]
        assert groups["p2pkh"][0].indices == (0, 1)

    def test_correlate_across_transactions_no_reuse(self) -> None:
        records = [
            Record(
                txid=b"\x01" * 32, input_index=0, signature=encode_der(1, 2),
                public_key=GENERATOR, script_type="p2pkh", sighash_flag=1, amount=0,
            ),
            Record(
                txid=b"\x02" * 32, input_index=0, signature=encode_der(3, 4),
                public_key=GENERATOR, script_type="p2pkh", sighash_flag=1, amount=0,
            ),
        ]
        groups = correlate_across_transactions(records)
        assert groups == {}

    def test_correlate_with_bad_sig(self) -> None:
        records = [
            Record(
                txid=b"\x01" * 32, input_index=0, signature=b"\x00",
                public_key=GENERATOR, script_type="p2pkh", sighash_flag=1, amount=0,
            ),
        ]
        groups = correlate_across_transactions(records)
        assert groups == {}

    def test_extract_r_from_record_schnorr(self) -> None:
        """extract_r_from_record handles 64-byte Schnorr signatures."""
        from bitcoin.signature.pipeline import extract_r_from_record
        r_val = 42
        sig_64 = r_val.to_bytes(32, "big") + b"\x00" * 32
        rec = Record(
            txid=b"\x01" * 32, input_index=0, signature=sig_64,
            public_key=GENERATOR, script_type="taproot",
            sighash_flag=0, amount=0,
        )
        assert extract_r_from_record(rec) == r_val

    def test_extract_r_from_record_der(self) -> None:
        """extract_r_from_record handles DER-encoded ECDSA signatures."""
        from bitcoin.signature.pipeline import extract_r_from_record
        rec = Record(
            txid=b"\x01" * 32, input_index=0, signature=encode_der(7, 8),
            public_key=GENERATOR, script_type="p2pkh",
            sighash_flag=1, amount=0,
        )
        assert extract_r_from_record(rec) == 7

    def test_extract_r_from_record_bad(self) -> None:
        """extract_r_from_record returns None for invalid sigs."""
        from bitcoin.signature.pipeline import extract_r_from_record
        rec = Record(
            txid=b"\x01" * 32, input_index=0, signature=b"\x00",
            public_key=GENERATOR, script_type="p2pkh",
            sighash_flag=1, amount=0,
        )
        assert extract_r_from_record(rec) is None

    def test_batch_extract_threaded(self) -> None:
        """batch_extract with multiple workers processes successfully."""
        from bitcoin.transaction.models import Tx, TxIn, TxOut, OutPoint, Witness
        from bitcoin.services.serializer import serialize_legacy_tx
        from bitcoin.signature.pipeline import batch_extract
        from bitcoin.script import build_p2pkh
        from bitcoin.script.parser import serialize_script
        priv = 42
        txin = TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF, Witness(()))
        txout = TxOut(1000, build_p2pkh(TEST_PUB_HASH))
        tx = Tx(2, (txin,), (txout,), 0)
        sig = sign_tx_input(tx, 0, priv, script=build_p2pkh(TEST_PUB_HASH), value=0)
        pubkey = multiply(priv, GENERATOR)
        scriptsig = serialize_script([sig, pubkey.to_sec_compressed()])
        txin2 = TxIn(OutPoint(b"\x01" * 32, 0), scriptsig, 0xFFFFFFFF, Witness(()))
        tx2 = Tx(2, (txin2,), (txout,), 0)
        raw = serialize_legacy_tx(tx2)
        result = batch_extract([raw, raw], max_workers=2)
        assert result.total_transactions == 2
        assert result.successful == 2
        assert result.failed == 0

    def test_batch_extract_from_file2(self) -> None:
        """batch_extract_from_file reads hex txs from a file (2)."""
        import tempfile
        from bitcoin.signature.pipeline import batch_extract_from_file
        from bitcoin.transaction.models import Tx, TxIn, TxOut, OutPoint, Witness
        from bitcoin.services.serializer import serialize_legacy_tx
        from bitcoin.script import build_p2pkh
        from bitcoin.script.parser import serialize_script
        priv = 42
        txin = TxIn(OutPoint(b"\x01" * 32, 0), b"", 0xFFFFFFFF, Witness(()))
        txout = TxOut(1000, build_p2pkh(TEST_PUB_HASH))
        tx = Tx(2, (txin,), (txout,), 0)
        sig = sign_tx_input(tx, 0, priv, script=build_p2pkh(TEST_PUB_HASH), value=0)
        pubkey = multiply(priv, GENERATOR)
        scriptsig = serialize_script([sig, pubkey.to_sec_compressed()])
        txin2 = TxIn(OutPoint(b"\x01" * 32, 0), scriptsig, 0xFFFFFFFF, Witness(()))
        tx2 = Tx(2, (txin2,), (txout,), 0)
        raw_hex = serialize_legacy_tx(tx2).hex()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write(raw_hex + "\n")
            f.write("# comment\n")
            f.write(raw_hex + "\n")
            fpath = f.name
        try:
            result = batch_extract_from_file(fpath)
            assert result.total_transactions == 2
            assert result.successful == 2
        finally:
            import os
            os.unlink(fpath)


# ===================================================================
# blockchain.py (27 % coverage)
# ===================================================================

def _make_tx_json(txid: str) -> dict:
    return {
        "txid": txid,
        "vout": [
            {"scriptpubkey": "0014" + "00" * 20, "value": 10000},
            {"scriptpubkey": "0014" + "11" * 20, "value": 20000},
        ],
        "out": [
            {"script": "76a914" + "00" * 20 + "88ac", "value": 10000},
        ],
    }


class TestBlockstreamProvider:
    def test_get_transaction_hex(self) -> None:
        with patch(
            "bitcoin.services.blockchain.fetch_text",
            return_value="01000000...",
        ) as mock_fetch:
            p = BlockstreamProvider()
            result = p.get_transaction_hex("aa" * 32)
            assert result == "01000000..."
            mock_fetch.assert_called_once()

    def test_get_utxo_script_pubkey(self) -> None:
        txid = "aa" * 32
        with patch.object(
            BlockstreamProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = BlockstreamProvider()
            script = p.get_utxo_script_pubkey(txid, 0)
            assert script

    def test_get_utxo_script_pubkey_out_of_range(self) -> None:
        txid = "aa" * 32
        with patch.object(
            BlockstreamProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = BlockstreamProvider()
            with pytest.raises(ValueError, match="out of range"):
                p.get_utxo_script_pubkey(txid, 99)

    def test_get_utxo_value(self) -> None:
        txid = "bb" * 32
        with patch.object(
            BlockstreamProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = BlockstreamProvider()
            val = p.get_utxo_value(txid, 0)
            assert val == 10000

    def test_get_utxo_value_out_of_range(self) -> None:
        txid = "bb" * 32
        with patch.object(
            BlockstreamProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = BlockstreamProvider()
            with pytest.raises(ValueError, match="out of range"):
                p.get_utxo_value(txid, 99)

    def test_fetch_tx_json_invalid_json(self) -> None:
        with patch(
            "bitcoin.services.blockchain.fetch_text",
            return_value="not json",
        ):
            p = BlockstreamProvider()
            with pytest.raises(ValueError, match="Invalid JSON"):
                p.fetch_tx_json("aa" * 32)


class TestBlockchainInfoProvider:
    def test_get_transaction_hex(self) -> None:
        with patch(
            "bitcoin.services.blockchain.fetch_text",
            return_value="01000000...",
        ):
            p = BlockchainInfoProvider()
            result = p.get_transaction_hex("aa" * 32)
            assert result == "01000000..."

    def test_get_utxo_script_pubkey(self) -> None:
        txid = "cc" * 32
        with patch.object(
            BlockchainInfoProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = BlockchainInfoProvider()
            script = p.get_utxo_script_pubkey(txid, 0)
            assert script

    def test_get_utxo_script_pubkey_no_script(self) -> None:
        txid = "dd" * 32
        with patch.object(
            BlockchainInfoProvider,
            "fetch_tx_json",
            return_value={"out": [{}]},
        ):
            p = BlockchainInfoProvider()
            with pytest.raises(ValueError, match="No script"):
                p.get_utxo_script_pubkey(txid, 0)

    def test_get_utxo_script_pubkey_out_of_range(self) -> None:
        txid = "ee" * 32
        with patch.object(
            BlockchainInfoProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = BlockchainInfoProvider()
            with pytest.raises(ValueError, match="out of range"):
                p.get_utxo_script_pubkey(txid, 99)

    def test_get_utxo_value(self) -> None:
        txid = "ff" * 32
        with patch.object(
            BlockchainInfoProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = BlockchainInfoProvider()
            val = p.get_utxo_value(txid, 0)
            assert val == 10000

    def test_get_utxo_value_out_of_range(self) -> None:
        txid = "00" * 32
        with patch.object(
            BlockchainInfoProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = BlockchainInfoProvider()
            with pytest.raises(ValueError, match="out of range"):
                p.get_utxo_value(txid, 99)


class TestMempoolSpaceProvider:
    def test_get_transaction_hex(self) -> None:
        with patch(
            "bitcoin.services.blockchain.fetch_text",
            return_value="01000000...",
        ):
            p = MempoolSpaceProvider()
            result = p.get_transaction_hex("aa" * 32)
            assert result == "01000000..."

    def test_get_utxo_script_pubkey(self) -> None:
        txid = "11" * 32
        with patch.object(
            MempoolSpaceProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = MempoolSpaceProvider()
            script = p.get_utxo_script_pubkey(txid, 0)
            assert script

    def test_get_utxo_script_pubkey_out_of_range(self) -> None:
        txid = "22" * 32
        with patch.object(
            MempoolSpaceProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = MempoolSpaceProvider()
            with pytest.raises(ValueError, match="out of range"):
                p.get_utxo_script_pubkey(txid, 99)

    def test_get_utxo_value(self) -> None:
        txid = "33" * 32
        with patch.object(
            MempoolSpaceProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = MempoolSpaceProvider()
            val = p.get_utxo_value(txid, 0)
            assert val == 10000

    def test_get_utxo_value_out_of_range(self) -> None:
        txid = "44" * 32
        with patch.object(
            MempoolSpaceProvider,
            "fetch_tx_json",
            return_value=_make_tx_json(txid),
        ):
            p = MempoolSpaceProvider()
            with pytest.raises(ValueError, match="out of range"):
                p.get_utxo_value(txid, 99)


class TestFetchText:
    def test_http_error(self) -> None:
        from urllib.error import HTTPError
        with patch("bitcoin.services.blockchain.urlopen") as mock:
            mock.side_effect = HTTPError(
                "http://example.com", 404, "Not Found", {}, None,  # type: ignore[arg-type]
            )
            with pytest.raises(OSError, match="HTTP 404"):
                fetch_text("http://example.com")

    def test_url_error(self) -> None:
        from urllib.error import URLError
        with patch("bitcoin.services.blockchain.urlopen") as mock:
            mock.side_effect = URLError("connection failed")
            with pytest.raises(OSError, match="URL error"):
                fetch_text("http://example.com")

    def test_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"response data"
        mock_resp.__enter__.return_value = mock_resp
        with patch("bitcoin.services.blockchain.urlopen", return_value=mock_resp):
            result = fetch_text("http://example.com")
            assert result == "response data"

    def test_fetch_tx_json_invalid_json(self) -> None:
        with patch(
            "bitcoin.services.blockchain.fetch_text",
            return_value="not json",
        ):
            p = MempoolSpaceProvider()
            with pytest.raises(ValueError, match="Invalid JSON"):
                p.fetch_tx_json("aa" * 32)


class TestEnrichTransaction:
    def test_basic(self) -> None:
        tx = make_test_tx()
        raw = serialize_tx(tx).hex()
        mock_provider = MagicMock()
        mock_provider.get_utxo_script_pubkey.return_value = build_p2pkh(TEST_PUB_HASH)
        mock_provider.get_utxo_value.return_value = 10000
        scripts, values = enrich_transaction(raw, provider=mock_provider)
        assert len(scripts) == 1
        assert values == [10000]

    def test_default_provider(self) -> None:
        tx = make_test_tx()
        raw = serialize_tx(tx).hex()
        with patch(
            "bitcoin.services.blockchain.fetch_text",
            return_value="01000000...",
        ):
            with pytest.raises((OSError, ValueError)):
                enrich_transaction(raw)


class TestFetchAndExtract:
    def test_with_txid(self) -> None:
        mock_provider = MagicMock()
        mock_provider.get_transaction_hex.return_value = "00"
        with pytest.raises((ValueError, OSError)):
            fetch_and_extract("aa" * 32, provider=mock_provider)

    def test_with_hex(self) -> None:
        mock_provider = MagicMock()
        with pytest.raises((ValueError, OSError)):
            fetch_and_extract("nothex", provider=mock_provider)

    def test_does_not_look_like_txid(self) -> None:
        mock_provider = MagicMock()
        with pytest.raises((ValueError, OSError)):
            # 64 chars but not valid tx hex
            fetch_and_extract("zzz" * 21 + "z", provider=mock_provider)


# ===================================================================
# editor.py (47 % coverage)
# ===================================================================

class TestPsbtEditor:
    def test_from_tx(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        psbt = editor.build()
        assert len(psbt.inputs) == 1
        assert len(psbt.outputs) == 1

    def test_from_existing_psbt(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        psbt = Psbt(tx=raw, inputs=(PsbtInput(),), outputs=(PsbtOutput(),))
        editor = PsbtEditor(psbt)
        result = editor.build()
        assert result.tx == raw

    def test_set_input_utxo(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.set_input_utxo(0, non_witness_utxo=b"\x01" * 10)
        psbt = editor.build()
        assert psbt.inputs[0].non_witness_utxo == b"\x01" * 10

    def test_set_input_utxo_witness(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.set_input_utxo(0, witness_utxo=b"\x02" * 10)
        psbt = editor.build()
        assert psbt.inputs[0].witness_utxo == b"\x02" * 10

    def test_set_input_redeem_script(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.set_input_redeem_script(0, b"\x00" * 23)
        assert editor.inputs[0].redeem_script == b"\x00" * 23

    def test_set_input_witness_script(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.set_input_witness_script(0, b"\x00" * 35)
        assert editor.inputs[0].witness_script == b"\x00" * 35

    def test_set_input_sighash_type(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.set_input_sighash_type(0, 1)
        assert editor.inputs[0].sighash_type == 1

    def test_add_input_partial_sig(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.add_input_partial_sig(0, b"\x02" * 33, b"\x30" * 70)
        assert b"\x02" * 33 in editor.inputs[0].partial_sigs

    def test_set_output_redeem_script(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.set_output_redeem_script(0, b"\x00" * 23)
        assert editor.outputs[0].redeem_script == b"\x00" * 23

    def test_set_output_witness_script(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.set_output_witness_script(0, b"\x00" * 35)
        assert editor.outputs[0].witness_script == b"\x00" * 35

    def test_finalize_input(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        editor = PsbtEditor.from_tx(raw)
        editor.finalize_input(
            0, final_script_sig=b"\x00\x01", final_witness=(b"\x02",),
        )
        assert editor.inputs[0].final_script_sig == b"\x00\x01"
        assert editor.inputs[0].final_script_witness == (b"\x02",)

    def test_chaining(self) -> None:
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        psbt = (
            PsbtEditor.from_tx(raw)
            .set_input_utxo(0, non_witness_utxo=b"\x01")
            .set_input_sighash_type(0, 1)
            .add_input_partial_sig(0, b"\x02" * 33, b"\x30" * 70)
            .build()
        )
        assert psbt.inputs[0].sighash_type == 1


class TestMutableInput:
    def test_defaults(self) -> None:
        mi = MutableInput()
        assert mi.non_witness_utxo is None
        assert mi.witness_utxo is None
        assert mi.partial_sigs == {}
        assert mi.sighash_type is None

    def test_with_values(self) -> None:
        mi = MutableInput(
            non_witness_utxo=b"\x01",
            witness_utxo=b"\x02",
            partial_sigs={b"\x03": b"\x04"},
            sighash_type=1,
        )
        assert mi.non_witness_utxo == b"\x01"
        assert mi.sighash_type == 1


class TestMutableOutput:
    def test_defaults(self) -> None:
        mo = MutableOutput()
        assert mo.redeem_script is None
        assert mo.witness_script is None

    def test_with_values(self) -> None:
        mo = MutableOutput(redeem_script=b"\x01", witness_script=b"\x02")
        assert mo.redeem_script == b"\x01"


# ===================================================================
# taproot.py (41 % coverage)
# ===================================================================

class TestTaproot:
    def test_parse_taproot_witness_key_path(self) -> None:
        result = parse_taproot_witness_stack((b"\x00" * 64,))
        assert result is None

    def test_parse_taproot_witness_empty(self) -> None:
        assert parse_taproot_witness_stack(()) is None

    def test_parse_taproot_witness_script_path(self) -> None:
        items = (
            b"\x00" * 64,  # sig
            b"\x01" * 32,  # leaf script
            b"\x02" * 33,  # control block
        )
        result = parse_taproot_witness_stack(items)
        assert result is not None
        assert len(result) == 1
        assert result[0].script == b"\x01" * 32
        assert len(result[0].sigs) == 1

    def test_parse_taproot_witness_multiple_sigs(self) -> None:
        items = (
            b"\x00" * 64,
            b"\x01" * 65,
            b"\x02" * 32,
            b"\x03" * 33,
        )
        result = parse_taproot_witness_stack(items)
        assert result is not None
        assert len(result[0].sigs) == 2

    def test_parse_taproot_witness_no_sigs(self) -> None:
        items = (
            b"\x01" * 32,
            b"\x02" * 33,
        )
        result = parse_taproot_witness_stack(items)
        assert result is not None
        assert result[0].sigs == ()

    def test_extract_taproot_scripts(self) -> None:
        records = [
            Record(
                txid=b"\x01" * 32, input_index=0,
                signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
                public_key=GENERATOR, script_type="p2tr", sighash_flag=1, amount=0,
            ),
        ]
        result = extract_taproot_scripts(records)
        assert len(result) == 1

    def test_get_x_only_pubkey_valid(self) -> None:
        pubkey = b"\x01" * 32
        script = b"\x51\x20" + pubkey
        result = get_x_only_pubkey(script)
        assert result == pubkey

    def test_get_x_only_pubkey_too_short(self) -> None:
        assert get_x_only_pubkey(b"\x51\x20" + b"\x01" * 31) is None

    def test_get_x_only_pubkey_wrong_opcode(self) -> None:
        assert get_x_only_pubkey(b"\x00\x20" + b"\x01" * 32) is None

    def test_get_x_only_pubkey_wrong_push(self) -> None:
        assert get_x_only_pubkey(b"\x51\x21" + b"\x01" * 33) is None

    def test_taproot_script_path_dataclass(self) -> None:
        tsp = TaprootScriptPath(
            script=b"\x01", control_block=b"\x02", sigs=(b"\x03",),
        )
        assert tsp.script == b"\x01"
        assert len(tsp.sigs) == 1


# ===================================================================
# classifier.py (74 % coverage) — remaining branches
# ===================================================================

class TestClassifierRemaining:
    def test_classify_script_pubkey_empty(self) -> None:
        assert classify_script_pubkey(b"") == NON_STANDARD

    def test_classify_script_pubkey_p2pkh(self) -> None:
        script = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        assert classify_script_pubkey(script) == P2PKH

    def test_classify_script_pubkey_p2sh(self) -> None:
        script = b"\xa9\x14" + b"\x00" * 20 + b"\x87"
        assert classify_script_pubkey(script) == P2SH

    def test_classify_script_pubkey_p2sh_alt(self) -> None:
        script = b"\xa9\x14" + b"\x11" * 20 + b"\x87"
        assert classify_script_pubkey(script) == P2SH

    def test_classify_script_pubkey_p2wpkh(self) -> None:
        script = b"\x00\x14" + b"\x00" * 20
        assert classify_script_pubkey(script) == P2WPKH

    def test_classify_script_pubkey_p2wsh(self) -> None:
        script = b"\x00\x20" + b"\x00" * 32
        assert classify_script_pubkey(script) == P2WSH

    def test_classify_script_pubkey_p2tr(self) -> None:
        script = b"\x51\x20" + b"\x00" * 32
        assert classify_script_pubkey(script) == P2TR

    def test_classify_script_pubkey_p2pk(self) -> None:
        script = bytes([33]) + b"\x02" + b"\x00" * 32 + b"\xac"
        assert classify_script_pubkey(script) == P2PK

    def test_classify_script_pubkey_p2pk_65(self) -> None:
        script = bytes([65]) + b"\x04" + b"\x00" * 64 + b"\xac"
        assert classify_script_pubkey(script) == P2PK

    def test_classify_script_pubkey_non_standard(self) -> None:
        assert classify_script_pubkey(b"\x00\x00\x00") == NON_STANDARD

    def test_classify_script_sig_empty(self) -> None:
        assert classify_script_sig(b"") == "empty"

    def test_classify_script_sig_p2pkh(self) -> None:
        script = bytes([70]) + b"\x30" * 70 + bytes([33]) + b"\x02" + b"\x00" * 32
        assert classify_script_sig(script) == "p2pkh"

    def test_classify_script_sig_non_standard(self) -> None:
        assert classify_script_sig(b"\x00") == "non_standard"

    def test_parse_p2pkh_script_sig_empty(self) -> None:
        with pytest.raises(ValueError, match="Empty scriptSig"):
            parse_p2pkh_script_sig(b"")

    def test_parse_p2pkh_script_sig_truncated(self) -> None:
        with pytest.raises(ValueError, match="Truncated"):
            parse_p2pkh_script_sig(b"\x01\x00")

    def test_is_p2sh(self) -> None:
        script = b"\xa9\x14" + b"\x00" * 20 + b"\x87"
        assert is_p2sh(script)
        assert not is_p2sh(b"\x00")

    def test_is_op_return(self) -> None:
        assert is_op_return(b"\x6a\x00")
        assert not is_op_return(b"\x00")
        assert not is_op_return(b"")

    def test_is_bare_multisig(self) -> None:
        script = (
            b"\x52" + b"\x21" + b"\x02" + b"\x00" * 32
            + b"\x21" + b"\x03" + b"\x01" * 32 + b"\x53\xae"
        )
        assert is_bare_multisig(script)

    def test_is_bare_multisig_too_short(self) -> None:
        assert not is_bare_multisig(b"\x00")

    def test_is_bare_multisig_bad_first(self) -> None:
        assert not is_bare_multisig(b"\x4f" + b"\x00" * 40)

    def test_is_bare_multisig_bad_last(self) -> None:
        assert not is_bare_multisig(
            b"\x52" + b"\x21" + b"\x02" + b"\x00" * 32 + b"\x53\x00"
        )

    def test_is_bare_multisig_bad_second_last(self) -> None:
        assert not is_bare_multisig(
            b"\x52" + b"\x21" + b"\x02" + b"\x00" * 32 + b"\x4f\xae"
        )

    def test_has_timelocks(self) -> None:
        assert has_timelocks(b"\xb1\x00")
        assert has_timelocks(b"\xb2\x00")
        assert not has_timelocks(b"\x00")

    def test_classify_detailed_empty(self) -> None:
        assert classify_detailed(b"") == NON_STANDARD

    def test_classify_detailed_op_return(self) -> None:
        assert classify_detailed(b"\x6a\x00") == "op_return"

    def test_classify_detailed_multisig(self) -> None:
        script = (
            b"\x52" + b"\x21" + b"\x02" + b"\x00" * 32
            + b"\x21" + b"\x03" + b"\x01" * 32 + b"\x53\xae"
        )
        assert classify_detailed(script) == MULTISIG

    def test_classify_detailed_p2pkh(self) -> None:
        script = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        assert classify_detailed(script) == P2PKH

    def test_classify_detailed_timelock(self) -> None:
        script = b"\x00\xb1\x00"
        assert classify_detailed(script) == TIMELOCK

    def test_classify_detailed_non_standard(self) -> None:
        assert classify_detailed(b"\x00\x00") == NON_STANDARD


# ===================================================================
# batch_verify.py (new)
# ===================================================================

class TestBatchVerify:
    def test_single_sig(self) -> None:
        priv = 42
        pub = multiply(priv, GENERATOR)
        msg = sha256(b"test message")
        sig = sign(msg, priv)
        assert batch_verify([msg], [sig], [pub])

    def test_multiple_sigs(self) -> None:
        msgs = []
        sigs = []
        pubs = []
        for i in range(3):
            priv = i + 1
            pubs.append(multiply(priv, GENERATOR))
            msg = sha256(f"msg{i}".encode())
            msgs.append(msg)
            sigs.append(sign(msg, priv))
        assert batch_verify(msgs, sigs, pubs)

    def test_empty_batch(self) -> None:
        assert batch_verify([], [], [])

    def test_length_mismatch(self) -> None:
        with pytest.raises(ValueError, match="Length mismatch"):
            batch_verify([b"\x00" * 32], [], [])

    def test_invalid_sig(self) -> None:
        priv = 7
        pub = multiply(priv, GENERATOR)
        msg = sha256(b"real")
        bad_sig = encode_der(1, 1)
        assert not batch_verify([msg], [bad_sig], [pub])

    def test_bad_der(self) -> None:
        priv = 7
        pub = multiply(priv, GENERATOR)
        msg = sha256(b"real")
        assert not batch_verify([msg], [b"\x00"], [pub])


# ===================================================================
# rbf.py (new)
# ===================================================================

class TestRBF:
    def make_txin(self, sequence: int) -> TxIn:
        return TxIn(
            previous_output=OutPoint(txid=b"\x01" * 32, vout=0),
            script_sig=b"",
            sequence=sequence,
            witness=EMPTY_WITNESS,
        )

    def test_opt_in_rbf_true(self) -> None:
        tx = Tx(
            version=2,
            inputs=(self.make_txin(0xFFFFFFFD),),
            outputs=(TxOut(value=1000, script_pubkey=b"\x00"),),
            lock_time=0,
        )
        assert is_opt_in_rbf(tx)

    def test_opt_in_rbf_false(self) -> None:
        tx = Tx(
            version=2,
            inputs=(self.make_txin(0xFFFFFFFF),),
            outputs=(TxOut(value=1000, script_pubkey=b"\x00"),),
            lock_time=0,
        )
        assert not is_opt_in_rbf(tx)

    def test_has_sequence_lock_true(self) -> None:
        tx = Tx(
            version=2,
            inputs=(self.make_txin(0xFFFFFFFD),),
            outputs=(TxOut(value=1000, script_pubkey=b"\x00"),),
            lock_time=0,
        )
        assert has_sequence_lock(tx)

    def test_has_sequence_lock_false(self) -> None:
        tx = Tx(
            version=2,
            inputs=(self.make_txin(0xFFFFFFFF),),
            outputs=(TxOut(value=1000, script_pubkey=b"\x00"),),
            lock_time=0,
        )
        assert not has_sequence_lock(tx)

    def test_opt_in_rbf_exact_threshold(self) -> None:
        tx = Tx(
            version=2,
            inputs=(self.make_txin(0xFFFFFFFD),),
            outputs=(TxOut(value=1000, script_pubkey=b"\x00"),),
            lock_time=0,
        )
        assert is_opt_in_rbf(tx)


# ===================================================================
# Point caching (bitcoin/curve/operations.py)
# ===================================================================

class TestMultiplyCache:
    def test_multiply_by_zero(self) -> None:
        result = multiply(0, GENERATOR)
        assert result.infinity

    def test_multiply_by_one(self) -> None:
        result = multiply(1, GENERATOR)
        assert result == GENERATOR


# ===================================================================
# schnorr.py remaining branches (69 %)
# ===================================================================

class TestSchnorrAdditional:
    def test_lift_x_invalid(self) -> None:
        from bitcoin.signature.schnorr import lift_x as lift_x_fn
        assert lift_x_fn(FIELD_PRIME) is None
        # Find a non-QR x
        for x in range(1, 100):
            y_sq = (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
            y = pow(y_sq, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
            if (y * y) % FIELD_PRIME != y_sq:
                assert lift_x_fn(x) is None
                return

    def test_verify_schnorr_bad_lengths(self) -> None:
        from bitcoin.signature.schnorr import verify_schnorr_sig as vss
        assert not vss(b"\x00" * 31, b"\x00" * 64, b"\x00" * 32)
        assert not vss(b"\x00" * 32, b"\x00" * 63, b"\x00" * 32)
        assert not vss(b"\x00" * 32, b"\x00" * 64, b"\x00" * 31)

    def test_verify_schnorr_bad_pubkey(self) -> None:
        from bitcoin.signature.schnorr import verify_schnorr_sig as vss
        assert not vss(b"\xff" * 32, b"\x00" * 64, b"\x00" * 32)

    def test_verify_schnorr_bad_r(self) -> None:
        from bitcoin.signature.schnorr import verify_schnorr_sig as vss
        assert not vss(
            b"\x00" * 32,
            b"\xff" * 32 + b"\x00" * 32,
            b"\x00" * 32,
        )


# ===================================================================
# signer.py remaining branches (24 → 100 %)
# ===================================================================

class TestSignerEdge:
    def test_sign_tx_input_segwit_zero_value(self) -> None:
        tx = Tx(
            version=2,
            inputs=(
                TxIn(
                    previous_output=OutPoint(txid=b"\x01" * 32, vout=0),
                    script_sig=b"",
                    sequence=0xFFFFFFFF,
                    witness=Witness((b"\x02" * 64,)),
                ),
            ),
            outputs=(TxOut(value=0, script_pubkey=b"\x00"),),
            lock_time=0,
        )
        sig = sign_tx_input(tx, 0, 42, script=b"\x00", value=0)
        assert 70 < len(sig) < 74


# ===================================================================
# psbt_extract_signatures (low coverage in parser.py)
# ===================================================================

class TestPsbtExtractSignatures:
    def test_psbt_extract_signatures(self) -> None:
        from bitcoin.psbt.parser import psbt_extract_signatures
        tx = make_test_tx()
        raw = serialize_legacy_tx(tx)
        pubkey_bytes = GENERATOR.to_sec_compressed()
        inp = PsbtInput(partial_sigs={
            pubkey_bytes: b"\x30\x06\x02\x01\x01\x02\x01\x01\x01",
        })
        psbt = Psbt(tx=raw, inputs=(inp,), outputs=(PsbtOutput(),))
        records = psbt_extract_signatures(psbt)
        assert len(records) == 1


# ===================================================================
# tx.py remaining branches (79 %)
# ===================================================================

class TestMakeTx:
    def test_make_tx(self) -> None:
        tx = make_tx(
            version=2,
            inputs=[{"txid": b"\x01" * 32, "vout": 0}],
            outputs=[{"value": 1000, "script_pubkey": b"\x00"}],
        )
        assert tx.version == 2

    def test_make_tx_bad_witness_type(self) -> None:
        with pytest.raises(TypeError, match="witness must be a tuple"):
            make_tx(
                version=2,
                inputs=[{"txid": b"\x01" * 32, "vout": 0, "witness": [b"x"]}],
                outputs=[{"value": 1000, "script_pubkey": b"\x00"}],
            )

    def test_make_tx_bad_txid(self) -> None:
        with pytest.raises(TypeError, match="txid must be bytes"):
            make_tx(
                version=2,
                inputs=[{"txid": 123, "vout": 0}],
                outputs=[{"value": 1000, "script_pubkey": b"\x00"}],
            )

    def test_make_tx_bad_vout(self) -> None:
        with pytest.raises(TypeError, match="vout must be int"):
            make_tx(
                version=2,
                inputs=[{"txid": b"\x01" * 32, "vout": "zero"}],
                outputs=[{"value": 1000, "script_pubkey": b"\x00"}],
            )

    def test_make_tx_bad_script_sig(self) -> None:
        with pytest.raises(TypeError, match="script_sig must be bytes"):
            make_tx(
                version=2,
                inputs=[{"txid": b"\x01" * 32, "vout": 0, "script_sig": 123}],
                outputs=[{"value": 1000, "script_pubkey": b"\x00"}],
            )

    def test_make_tx_bad_sequence(self) -> None:
        with pytest.raises(TypeError, match="sequence must be int"):
            make_tx(
                version=2,
                inputs=[{"txid": b"\x01" * 32, "vout": 0, "sequence": "max"}],
                outputs=[{"value": 1000, "script_pubkey": b"\x00"}],
            )

    def test_make_tx_bad_value(self) -> None:
        with pytest.raises(TypeError, match="value must be int"):
            make_tx(
                version=2,
                inputs=[{"txid": b"\x01" * 32, "vout": 0}],
                outputs=[{"value": "lots", "script_pubkey": b"\x00"}],
            )

    def test_make_tx_bad_script_pubkey(self) -> None:
        with pytest.raises(TypeError, match="script_pubkey must be bytes"):
            make_tx(
                version=2,
                inputs=[{"txid": b"\x01" * 32, "vout": 0}],
                outputs=[{"value": 1000, "script_pubkey": 123}],
            )
