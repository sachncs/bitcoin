"""Comprehensive coverage tests for extraction engine, classifier, builder, and signature check."""
from __future__ import annotations

import pytest

from bitcoin.curve import GENERATOR, INFINITY, Point, is_on_curve, multiply
from bitcoin.curve.dispatch import parse_public_key
from bitcoin.curve.params import CURVE_ORDER, FIELD_PRIME
from bitcoin.encoding.der import encode_der
from bitcoin.encoding.hasher import hash160, hash256, sha256
from bitcoin.script.classifier import (
    P2PK,
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    NON_STANDARD,
    classify_script_pubkey,
    classify_script_sig,
    is_p2sh,
    parse_p2pkh_script_sig,
)
from bitcoin.script.builder import (
    build_p2pk,
    build_p2pkh,
    build_p2wpkh,
    build_p2wsh,
    build_p2tr,
    make_p2pkh_script,
)
from bitcoin.signature.check import recover_public_key, verify_sig
from bitcoin.signature.extraction.engine import extract_signatures
from bitcoin.signature.record import Record
from bitcoin.transaction.models import EMPTY_WITNESS, OutPoint, Tx, TxIn, TxOut, Witness

# ── helpers ────────────────────────────────────────────────────────────────────

SECP = FIELD_PRIME


def p2pkh_script(pubkey_hash: bytes) -> bytes:
    return b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"


def p2sh_script(redeem_hash: bytes) -> bytes:
    return b"\xa9\x14" + redeem_hash + b"\x87"


def p2wpkh_script(pubkey_hash: bytes) -> bytes:
    return b"\x00\x14" + pubkey_hash


def p2wsh_script(script_hash: bytes) -> bytes:
    return b"\x00\x20" + script_hash


def p2tr_script(xonly: bytes) -> bytes:
    return b"\x51\x20" + xonly


def p2pk_script(pubkey: bytes) -> bytes:
    return bytes([len(pubkey)]) + pubkey + b"\xac"


# Standard test key (priv=1 → pub is GENERATOR)
TEST_PRIV = 1
TEST_PUB: Point = multiply(TEST_PRIV, GENERATOR)
TEST_PUB_SEC = TEST_PUB.to_sec_compressed()  # 33 bytes
TEST_PUB_HASH = hash160(TEST_PUB_SEC)

# DER signature for (r=1, s=1) — valid DER format, triggers recovery
DER_R1S1 = encode_der(1, 1)
SIG_R1S1_ALL = DER_R1S1 + b"\x01"  # with SIGHASH_ALL

# Non-QR r value where r^3 + 7 is not a quadratic residue mod FIELD_PRIME
NON_QR_R: int | None = None
for r_val in range(1, 10000):
    r_y_sq = (pow(r_val, 3, SECP) + 7) % SECP
    r_y = pow(r_y_sq, (SECP + 1) // 4, SECP)
    if (r_y * r_y) % SECP != r_y_sq:
        NON_QR_R = r_val
        break
NON_QR_SIG = encode_der(NON_QR_R, 1) if NON_QR_R else b""


def make_p2pkh_scriptsig() -> bytes:
    """Build a P2PKH scriptSig: <sig+flag> <pubkey>."""
    sig_push = bytes([len(SIG_R1S1_ALL)])
    pub_push = bytes([len(TEST_PUB_SEC)])
    return sig_push + SIG_R1S1_ALL + pub_push + TEST_PUB_SEC


def base_tx(
    script_sig: bytes = b"",
    witness: Witness = EMPTY_WITNESS,
    script_pubkey: bytes = b"",
    value: int = 0,
    num_outputs: int = 1,
) -> Tx:
    txin = TxIn(
        previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
        script_sig=script_sig,
        sequence=0xFFFFFFFF,
        witness=witness,
    )
    txouts = tuple(
        TxOut(value=value, script_pubkey=script_pubkey) for _ in range(num_outputs)
    )
    return Tx(version=2, inputs=(txin,), outputs=txouts, lock_time=0)


# ─── Classifier tests ──────────────────────────────────────────────────────────


class TestClassifierPubKey:
    def test_p2pkh(self) -> None:
        sc = p2pkh_script(b"\x00" * 20)
        assert classify_script_pubkey(sc) == P2PKH

    def test_p2sh(self) -> None:
        sc = p2sh_script(b"\x00" * 20)
        assert classify_script_pubkey(sc) == P2SH

    def test_p2wpkh(self) -> None:
        sc = p2wpkh_script(b"\x00" * 20)
        assert classify_script_pubkey(sc) == P2WPKH

    def test_p2wsh(self) -> None:
        sc = p2wsh_script(b"\x00" * 32)
        assert classify_script_pubkey(sc) == P2WSH

    def test_p2tr(self) -> None:
        sc = p2tr_script(b"\x00" * 32)
        assert classify_script_pubkey(sc) == P2TR

    def test_p2pk(self) -> None:
        sc = p2pk_script(b"\x02" + b"\x00" * 32)
        assert classify_script_pubkey(sc) == P2PK

    def test_non_standard_empty(self) -> None:
        assert classify_script_pubkey(b"") == NON_STANDARD

    def test_non_standard_short(self) -> None:
        assert classify_script_pubkey(b"\x00") == NON_STANDARD

    def test_non_standard_op_return(self) -> None:
        assert classify_script_pubkey(b"\x6a") == NON_STANDARD

    def test_p2pk_short_pubkey(self) -> None:
        """P2PK with pubkey length not in {33, 65} is non-standard."""
        sc = bytes([32]) + b"\x00" * 32 + b"\xac"
        assert classify_script_pubkey(sc) == NON_STANDARD

    def test_p2pk_no_checksig(self) -> None:
        """Script ending without OP_CHECKSIG is non-standard."""
        sc = bytes([33]) + b"\x02" + b"\x00" * 32 + b"\x76"
        assert classify_script_pubkey(sc) == NON_STANDARD


class TestClassifierScriptSig:
    def test_empty(self) -> None:
        assert classify_script_sig(b"") == "empty"

    def test_p2pkh(self) -> None:
        script = make_p2pkh_scriptsig()
        assert classify_script_sig(script) == "p2pkh"

    def test_non_standard(self) -> None:
        assert classify_script_sig(b"\x01\x00") == "non_standard"

    def test_p2pkh_len_mismatch(self) -> None:
        """Sig len + pubkey len + 2 ≠ total length → non_standard."""
        script = bytes([4]) + b"\x00" * 4 + bytes([33]) + b"\x00" * 32
        assert classify_script_sig(script) == "non_standard"


class TestClassifierParseP2PKH:
    def test_success(self) -> None:
        sig, pub = parse_p2pkh_script_sig(make_p2pkh_scriptsig())
        assert sig == SIG_R1S1_ALL
        assert pub == TEST_PUB_SEC

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="Empty"):
            parse_p2pkh_script_sig(b"")

    def test_truncated_missing_pubkey(self) -> None:
        script = bytes([3]) + b"\x00" * 3
        with pytest.raises(ValueError, match="Truncated"):
            parse_p2pkh_script_sig(script)


class TestClassifierIsP2SH:
    def test_is_p2sh_true(self) -> None:
        sc = p2sh_script(b"\x00" * 20)
        assert is_p2sh(sc) is True

    def test_is_p2sh_false(self) -> None:
        sc = p2pkh_script(b"\x00" * 20)
        assert is_p2sh(sc) is False


# ─── Builder tests ─────────────────────────────────────────────────────────────


class TestBuilder:
    def test_build_p2pk(self) -> None:
        pk = TEST_PUB_SEC
        result = build_p2pk(pk)
        assert len(result) == 35
        assert result[-1] == 0xAC

    def test_build_p2pkh(self) -> None:
        result = build_p2pkh(b"\x00" * 20)
        assert len(result) == 25
        assert result[:2] == b"\x76\xa9"

    def test_build_p2pkh_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="20-byte"):
            build_p2pkh(b"\x00" * 19)

    def test_build_p2wpkh(self) -> None:
        result = build_p2wpkh(b"\x00" * 20)
        assert len(result) == 22
        assert result[0] == 0x00

    def test_build_p2wpkh_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="20-byte"):
            build_p2wpkh(b"\x00" * 19)

    def test_build_p2wsh(self) -> None:
        result = build_p2wsh(b"\x00" * 32)
        assert len(result) == 34
        assert result[0] == 0x00

    def test_build_p2wsh_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="32-byte"):
            build_p2wsh(b"\x00" * 31)

    def test_build_p2tr(self) -> None:
        result = build_p2tr(b"\x00" * 32)
        assert len(result) == 34
        assert result[0] == 0x51

    def test_build_p2tr_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="32-byte"):
            build_p2tr(b"\x00" * 31)

    def test_make_p2pkh_script(self) -> None:
        result = make_p2pkh_script(TEST_PUB_SEC)
        assert len(result) == 25
        assert result[:2] == b"\x76\xa9"


# ─── Signature check tests ─────────────────────────────────────────────────────


class TestVerifySig:

    VALID_PRIV = 123456
    VALID_PUB: Point = multiply(VALID_PRIV, GENERATOR)
    VALID_MSG = hash256(b"coverage test message for verify_sig")
    VALID_E = int.from_bytes(VALID_MSG, "big") % CURVE_ORDER
    VALID_K = 98765
    VALID_R_PT: Point = multiply(VALID_K, GENERATOR)
    assert VALID_R_PT.x is not None
    VALID_R = VALID_R_PT.x % CURVE_ORDER
    VALID_S = (pow(VALID_K, -1, CURVE_ORDER) * (
        VALID_E + VALID_R * VALID_PRIV
    )) % CURVE_ORDER
    VALID_SIG = encode_der(VALID_R, VALID_S)

    def test_valid(self) -> None:
        assert verify_sig(self.VALID_MSG, self.VALID_SIG, self.VALID_PUB) is True

    def test_invalid_der(self) -> None:
        assert verify_sig(self.VALID_MSG, b"\x00", self.VALID_PUB) is False

    def test_invalid_r_zero(self) -> None:
        # Manually construct DER with r=0: 30 06 02 01 00 02 01 01
        bad_sig = bytes([0x30, 6, 2, 1, 0, 2, 1, 1])
        assert verify_sig(self.VALID_MSG, bad_sig, self.VALID_PUB) is False

    def test_invalid_r_ge_order(self) -> None:
        bad_sig = encode_der(CURVE_ORDER, 1)
        assert verify_sig(self.VALID_MSG, bad_sig, self.VALID_PUB) is False

    def test_invalid_s_zero(self) -> None:
        # Manually construct DER with s=0: 30 06 02 01 01 02 01 00
        bad_sig = bytes([0x30, 6, 2, 1, 1, 2, 1, 0])
        assert verify_sig(self.VALID_MSG, bad_sig, self.VALID_PUB) is False

    def test_invalid_s_ge_order(self) -> None:
        bad_sig = encode_der(1, CURVE_ORDER, s_high_ok=True)
        assert verify_sig(self.VALID_MSG, bad_sig, self.VALID_PUB) is False

    def test_point_not_on_curve(self) -> None:
        off_curve = Point(x=1, y=1)
        assert not is_on_curve(off_curve)
        assert verify_sig(self.VALID_MSG, self.VALID_SIG, off_curve) is False

    def test_infinity_key(self) -> None:
        assert verify_sig(self.VALID_MSG, self.VALID_SIG, INFINITY) is False


class TestRecoverPublicKey:
    # Standard ECDSA: s = k^(-1) * (e + r*d) mod n
    # Recovery:       Q = r^(-1) * (s * R - e * G)

    VALID_PRIV = 123456
    VALID_PUB: Point = multiply(VALID_PRIV, GENERATOR)
    VALID_MSG = hash256(b"coverage test message for recover")
    VALID_E = int.from_bytes(VALID_MSG, "big") % CURVE_ORDER
    VALID_K = 98765
    VALID_R_PT: Point = multiply(VALID_K, GENERATOR)
    assert VALID_R_PT.x is not None
    assert VALID_R_PT.y is not None
    VALID_R = VALID_R_PT.x % CURVE_ORDER
    VALID_S = (pow(VALID_K, -1, CURVE_ORDER) *
               (VALID_E + VALID_R * VALID_PRIV)) % CURVE_ORDER
    VALID_SIG = encode_der(VALID_R, VALID_S)

    def test_recover_success(self) -> None:
        pt = self.VALID_R_PT
        assert pt.y is not None
        rec_flag = 27 + (pt.y & 1) + 4
        recovered = recover_public_key(self.VALID_MSG, self.VALID_SIG, rec_flag)
        assert recovered == self.VALID_PUB

    def test_recover_failure_non_qr(self) -> None:
        """Recovery with r where r^3+7 is not a QR raises ValueError."""
        with pytest.raises(ValueError):
            flag = 27 + 4  # compressed, rec_id=0
            recover_public_key(self.VALID_MSG, NON_QR_SIG, flag)

    def test_recover_different_flag_returns_different_point(self) -> None:
        """Using a wrong recovery flag still returns some non-infinity point."""
        rec_flag = 27 + 4  # compressed, rec_id=0
        recovered = recover_public_key(self.VALID_MSG, self.VALID_SIG, rec_flag)
        assert isinstance(recovered, Point)
        assert not recovered.infinity

    def test_recover_infinity_point(self) -> None:
        """When R = e*G, the recovered pubkey is infinity → ValueError."""
        msg = hash256(b"infinity test")
        e_val = int.from_bytes(msg, "big") % CURVE_ORDER
        r_pt = multiply(e_val, GENERATOR)
        assert r_pt.x is not None
        assert r_pt.y is not None
        r_val = r_pt.x % CURVE_ORDER
        sig = encode_der(r_val, 1)
        flag = 27 + (r_pt.y & 1) + 4
        with pytest.raises(ValueError, match="infinity"):
            recover_public_key(msg, sig, flag)


# ─── Extraction engine tests ──────────────────────────────────────────────────


class TestExtractLegacy:
    def test_p2pkh_with_utxo(self) -> None:
        sc = p2pkh_script(TEST_PUB_HASH)
        tx = base_tx(
            script_sig=make_p2pkh_scriptsig(),
            script_pubkey=sc,
        )
        records = extract_signatures(tx, utxo_script_pubkeys=[sc])
        assert len(records) == 1
        assert records[0].script_type == P2PKH
        assert isinstance(records[0].public_key, Point)

    def test_p2pkh_without_utxo(self) -> None:
        tx = base_tx(script_sig=make_p2pkh_scriptsig())
        records = extract_signatures(tx)
        assert len(records) == 1

    def test_p2pkh_no_pubkey_in_scriptsig(self) -> None:
        sig_push = bytes([len(SIG_R1S1_ALL)])
        script_sig = sig_push + SIG_R1S1_ALL
        tx = base_tx(script_sig=script_sig)
        records = extract_signatures(tx)
        assert isinstance(records, list)

    def test_empty_script_sig(self) -> None:
        tx = base_tx()
        records = extract_signatures(tx)
        assert records == []

    def test_malformed_der_element(self) -> None:
        sig_push = bytes([3])
        bad_sig = b"\x00\x00\x00"
        script_sig = sig_push + bad_sig
        tx = base_tx(script_sig=script_sig)
        records = extract_signatures(tx)
        assert records == []

    def test_trailing_data_in_der(self) -> None:
        der_with_trailing = DER_R1S1 + b"\x02\x01\x02"
        sig_push = bytes([len(der_with_trailing)])
        script_sig = sig_push + der_with_trailing
        tx = base_tx(script_sig=script_sig)
        records = extract_signatures(tx)
        assert records == []

    def test_element_not_bytes(self) -> None:
        tx = base_tx(script_sig=b"\x00")
        records = extract_signatures(tx)
        assert records == []

    def test_element_too_short(self) -> None:
        tx = base_tx(script_sig=bytes([1]) + b"\x00")
        records = extract_signatures(tx)
        assert records == []

    def test_legacy_recovery_fails_no_fallback(self) -> None:
        non_qr_sig = NON_QR_SIG + b"\x01"
        sig_push = bytes([len(non_qr_sig)])
        tx = base_tx(script_sig=sig_push + non_qr_sig)
        records = extract_signatures(tx)
        assert records == []

    def test_recovery_fallback_pubkey_bytes(self) -> None:
        non_qr_der = NON_QR_SIG
        non_qr_sig = non_qr_der + b"\x01"
        sig_push = bytes([len(non_qr_sig)])
        pub_push = bytes([len(TEST_PUB_SEC)])
        script_sig = sig_push + non_qr_sig + pub_push + TEST_PUB_SEC
        sc = p2pkh_script(TEST_PUB_HASH)
        tx = base_tx(script_sig=script_sig, script_pubkey=sc)
        records = extract_signatures(tx, utxo_script_pubkeys=[sc])
        assert len(records) == 1


class TestExtractP2PK:
    def test_p2pk_extraction(self) -> None:
        from bitcoin.script.builder import build_p2pk
        sc = build_p2pk(TEST_PUB_SEC)
        sig_push = bytes([len(SIG_R1S1_ALL)])
        tx = base_tx(
            script_sig=sig_push + SIG_R1S1_ALL,
            script_pubkey=sc,
        )
        records = extract_signatures(tx, utxo_script_pubkeys=[sc])
        assert len(records) == 1
        assert records[0].script_type == P2PK
        assert records[0].sig == DER_R1S1

    def test_p2pk_no_sig(self) -> None:
        from bitcoin.script.builder import build_p2pk
        sc = build_p2pk(TEST_PUB_SEC)
        tx = base_tx(script_pubkey=sc)
        records = extract_signatures(tx, utxo_script_pubkeys=[sc])
        assert records == []


class TestExtractMultisig:
    def test_p2ms_extraction(self) -> None:
        sc = bytes([0x51]) + bytes([len(TEST_PUB_SEC)]) + TEST_PUB_SEC + bytes([0x51]) + bytes([0xae])
        sig_push = bytes([len(SIG_R1S1_ALL)])
        tx = base_tx(
            script_sig=sig_push + SIG_R1S1_ALL + bytes([0x00]),
            script_pubkey=sc,
        )
        records = extract_signatures(tx, utxo_script_pubkeys=[sc])
        assert len(records) == 1
        assert records[0].script_type == classify_script_pubkey(sc)

    def test_p2ms_empty_script_sig(self) -> None:
        sc = bytes([0x51]) + bytes([len(TEST_PUB_SEC)]) + TEST_PUB_SEC + bytes([0x51]) + bytes([0xae])
        tx = base_tx(script_pubkey=sc)
        records = extract_signatures(tx, utxo_script_pubkeys=[sc])
        assert records == []


class TestExtractP2WPKH:
    def test_p2wpkh_extraction(self) -> None:
        sc = p2wpkh_script(TEST_PUB_HASH)
        witness = Witness((SIG_R1S1_ALL, TEST_PUB_SEC))
        tx = base_tx(script_pubkey=sc, witness=witness, value=1000)
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=[sc],
            utxo_values=[1000],
        )
        assert len(records) == 1
        assert records[0].script_type == P2WPKH

    def test_p2wpkh_without_script_pubkey(self) -> None:
        """When script_pubkey is empty, default script code fallback."""
        witness = Witness((SIG_R1S1_ALL, TEST_PUB_SEC))
        tx = base_tx(witness=witness, value=1000)
        records = extract_signatures(tx, utxo_values=[1000])
        assert isinstance(records, list)

    def test_p2wpkh_recovery_fails(self) -> None:
        """Non-QR witness sig → recovery fails → skip item."""
        non_qr_sig = NON_QR_SIG + b"\x01"
        sc = p2wpkh_script(TEST_PUB_HASH)
        witness = Witness((non_qr_sig, TEST_PUB_SEC))
        tx = base_tx(script_pubkey=sc, witness=witness, value=1000)
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[1000],
        )
        assert records == []

    def test_p2wpkh_exception_handling(self) -> None:
        """Bad witness item raises ValueError → caught and continue."""
        bad_item = b"\x00\x01"  # item[:-1] = b"\x00" fails DER decode
        sc = p2wpkh_script(TEST_PUB_HASH)
        witness = Witness((bad_item, TEST_PUB_SEC))
        tx = base_tx(script_pubkey=sc, witness=witness, value=1000)
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[1000],
        )
        assert records == []


class TestExtractP2WSH:
    def test_p2wsh_extraction(self) -> None:
        witness_script = bytes([33]) + TEST_PUB_SEC + b"\xac"
        sc = p2wsh_script(sha256(witness_script))
        witness = Witness((SIG_R1S1_ALL, witness_script))
        tx = base_tx(script_pubkey=sc, witness=witness, value=2000)
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=[sc],
            utxo_values=[2000],
        )
        assert len(records) == 1
        assert records[0].script_type == P2WSH

    def test_p2wsh_empty_witness(self) -> None:
        sc = p2wsh_script(sha256(b"\xac"))
        tx = base_tx(script_pubkey=sc, witness=Witness(()), value=2000)
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[2000],
        )
        assert records == []

    def test_p2wsh_recovery_fails(self) -> None:
        """Non-QR witness sig → recovery fails → skip item."""
        non_qr_sig = NON_QR_SIG + b"\x01"
        witness_script = bytes([33]) + TEST_PUB_SEC + b"\xac"
        sc = p2wsh_script(sha256(witness_script))
        witness = Witness((non_qr_sig, witness_script))
        tx = base_tx(script_pubkey=sc, witness=witness, value=2000)
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[2000],
        )
        assert records == []

    def test_p2wsh_exception_handling(self) -> None:
        """Bad witness item raises ValueError → caught and continue."""
        bad_item = b"\x00\x01"
        witness_script = bytes([33]) + TEST_PUB_SEC + b"\xac"
        sc = p2wsh_script(sha256(witness_script))
        witness = Witness((bad_item, witness_script))
        tx = base_tx(script_pubkey=sc, witness=witness, value=2000)
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[2000],
        )
        assert records == []


class TestExtractP2SHSegWit:
    def test_p2sh_p2wpkh(self) -> None:
        redeem_script = p2wpkh_script(TEST_PUB_HASH)
        sc = p2sh_script(hash160(redeem_script))
        dummy_push = bytes([1]) + b"\x00"
        redeem_push = bytes([len(redeem_script)])
        script_sig = dummy_push + redeem_push + redeem_script
        witness = Witness((SIG_R1S1_ALL, TEST_PUB_SEC))
        tx = base_tx(
            script_sig=script_sig,
            witness=witness,
            script_pubkey=sc,
            value=3000,
        )
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=[sc],
            utxo_values=[3000],
        )
        assert len(records) == 1
        assert records[0].script_type == f"p2sh_{P2WPKH}"

    def test_p2sh_p2wsh(self) -> None:
        witness_script = bytes([33]) + TEST_PUB_SEC + b"\xac"
        redeem_script = p2wsh_script(sha256(witness_script))
        sc = p2sh_script(hash160(redeem_script))
        dummy_push = bytes([1]) + b"\x00"
        redeem_push = bytes([len(redeem_script)])
        script_sig = dummy_push + redeem_push + redeem_script
        witness = Witness((SIG_R1S1_ALL, witness_script))
        tx = base_tx(
            script_sig=script_sig,
            witness=witness,
            script_pubkey=sc,
            value=4000,
        )
        records = extract_signatures(
            tx,
            utxo_script_pubkeys=[sc],
            utxo_values=[4000],
        )
        assert len(records) == 1
        assert records[0].script_type == f"p2sh_{P2WSH}"

    def test_p2sh_short_scriptsig(self) -> None:
        """P2SH with segwit but fewer than 2 parsed elements → early return."""
        sc = p2sh_script(b"\x00" * 20)
        tx = base_tx(
            script_sig=b"\x00",
            witness=Witness((b"\x01" * 64,)),
            script_pubkey=sc,
            value=5000,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[5000],
        )
        assert records == []

    def test_p2sh_unknown_redeem_type(self) -> None:
        """P2SH redeem script that doesn't classify → default script code (else branch)."""
        redeem_script = b"\x6a"  # OP_RETURN → NON_STANDARD
        sc = p2sh_script(hash160(redeem_script))
        dummy_push = bytes([1]) + b"\x00"
        redeem_push = bytes([len(redeem_script)])
        script_sig = dummy_push + redeem_push + redeem_script
        witness = Witness((SIG_R1S1_ALL,))
        tx = base_tx(
            script_sig=script_sig,
            witness=witness,
            script_pubkey=sc,
            value=6000,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[6000],
        )
        assert isinstance(records, list)

    def test_p2sh_segwit_redeem_not_bytes(self) -> None:
        """Last scriptSig element is an opcode, not bytes → redeem=b''."""
        sc = p2sh_script(b"\x00" * 20)
        tx = base_tx(
            script_sig=b"\x00\x00",
            script_pubkey=sc,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[0],
        )
        assert records == []

    def test_p2sh_segwit_recovery_fails(self) -> None:
        """P2SH segwit recovery fails → pubkey None → continue."""
        redeem_script = p2wpkh_script(TEST_PUB_HASH)
        sc = p2sh_script(hash160(redeem_script))
        non_qr_sig = NON_QR_SIG + b"\x01"
        dummy_push = bytes([1]) + b"\x00"
        redeem_push = bytes([len(redeem_script)])
        script_sig = dummy_push + redeem_push + redeem_script
        witness = Witness((non_qr_sig, TEST_PUB_SEC))
        tx = base_tx(
            script_sig=script_sig,
            witness=witness,
            script_pubkey=sc,
            value=7000,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[7000],
        )
        assert records == []

    def test_p2sh_segwit_exception_handling(self) -> None:
        """P2SH segwit bad witness item → ValueError caught."""
        redeem_script = p2wpkh_script(TEST_PUB_HASH)
        sc = p2sh_script(hash160(redeem_script))
        bad_item = b"\x00\x01"
        dummy_push = bytes([1]) + b"\x00"
        redeem_push = bytes([len(redeem_script)])
        script_sig = dummy_push + redeem_push + redeem_script
        witness = Witness((bad_item, TEST_PUB_SEC))
        tx = base_tx(
            script_sig=script_sig,
            witness=witness,
            script_pubkey=sc,
            value=8000,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[8000],
        )
        assert records == []


class TestExtractTaproot:
    def test_key_path_64_bytes(self) -> None:
        sc = p2tr_script(b"\x00" * 32)
        tx = base_tx(
            witness=Witness((b"\x01" * 64,)),
            script_pubkey=sc,
            value=1000,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[1000],
        )
        assert len(records) == 1
        assert records[0].script_type == P2TR
        assert records[0].sighash_flag == 0x01

    def test_key_path_65_bytes(self) -> None:
        sc = p2tr_script(b"\x00" * 32)
        tx = base_tx(
            witness=Witness((b"\x01" * 64 + b"\x03",)),
            script_pubkey=sc,
            value=1000,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[1000],
        )
        assert len(records) == 1
        assert records[0].sighash_flag == 0x03

    def test_key_path_bad_length(self) -> None:
        """Key-path with sig length not 64 or 65 → no records."""
        sc = p2tr_script(b"\x00" * 32)
        tx = base_tx(
            witness=Witness((b"\x01" * 63,)),
            script_pubkey=sc,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[0],
        )
        assert records == []

    def test_script_path_spend(self) -> None:
        sc = p2tr_script(b"\x00" * 32)
        sig = b"\x01" * 64
        leaf = b"\x20\x00" * 16
        ctrl = b"\xc0" + b"\x00" * 32
        tx = base_tx(
            witness=Witness((sig, leaf, ctrl)),
            script_pubkey=sc,
            value=1000,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[1000],
        )
        assert len(records) == 1
        assert records[0].script_type == P2TR

    def test_script_path_65_byte_sig(self) -> None:
        sc = p2tr_script(b"\x00" * 32)
        sig = b"\x01" * 64 + b"\x02"
        leaf = b"\x20\x00" * 16
        ctrl = b"\xc0" + b"\x00" * 32
        tx = base_tx(
            witness=Witness((sig, leaf, ctrl)),
            script_pubkey=sc,
            value=1000,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[1000],
        )
        assert len(records) == 1
        assert records[0].sighash_flag == 0x02

    def test_script_path_short_sig(self) -> None:
        """Script-path with too-short sig items are skipped."""
        sc = p2tr_script(b"\x00" * 32)
        tx = base_tx(
            witness=Witness((b"\x01", b"\x02" * 33, b"\x03" * 33)),
            script_pubkey=sc,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[0],
        )
        assert records == []

    def test_script_path_empty_item(self) -> None:
        """Script-path with an empty witness item is skipped (continue)."""
        sc = p2tr_script(b"\x00" * 32)
        tx = base_tx(
            witness=Witness((b"", b"\x02" * 33, b"\x03" * 33)),
            script_pubkey=sc,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[0],
        )
        assert records == []

    def test_key_path_empty_sig(self) -> None:
        """Key-path with zero-length sig returns early."""
        sc = p2tr_script(b"\x00" * 32)
        tx = base_tx(
            witness=Witness((b"",)),
            script_pubkey=sc,
        )
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[0],
        )
        assert records == []

    def test_empty_witness(self) -> None:
        sc = p2tr_script(b"\x00" * 32)
        tx = base_tx(witness=Witness(()), script_pubkey=sc)
        records = extract_signatures(
            tx, utxo_script_pubkeys=[sc], utxo_values=[0],
        )
        assert records == []


class TestExtractUnknownScriptType:
    def test_unknown_script_type(self) -> None:
        """Empty script_pubkey → 'unknown' script type."""
        tx = base_tx(
            script_sig=make_p2pkh_scriptsig(),
            script_pubkey=b"",
        )
        records = extract_signatures(tx, utxo_script_pubkeys=[b""])
        assert len(records) == 1
        assert records[0].script_type == "unknown"


class TestExtractPubkeyFromScriptSig:
    def test_extract_success(self) -> None:
        from bitcoin.signature.extraction.engine import extract_pubkey_from_script_sig
        from bitcoin.script.parser import parse_script

        parsed = list(parse_script(make_p2pkh_scriptsig()))
        pk = extract_pubkey_from_script_sig(parsed)
        assert pk == TEST_PUB_SEC

    def test_extract_no_pubkey(self) -> None:
        from bitcoin.signature.extraction.engine import extract_pubkey_from_script_sig

        assert extract_pubkey_from_script_sig([1, 2, 3]) is None

    def test_extract_empty(self) -> None:
        from bitcoin.signature.extraction.engine import extract_pubkey_from_script_sig

        assert extract_pubkey_from_script_sig([]) is None

    def test_extract_wrong_length(self) -> None:
        from bitcoin.signature.extraction.engine import extract_pubkey_from_script_sig

        assert extract_pubkey_from_script_sig([b"\x00" * 32]) is None


class TestExtractGuessP2PKH:
    def test_guess_found(self) -> None:
        from bitcoin.signature.extraction.engine import guess_p2pkh_script
        from bitcoin.script.parser import parse_script

        parsed = list(parse_script(make_p2pkh_scriptsig()))
        result = guess_p2pkh_script(parsed)
        assert len(result) == 25
        assert result[:2] == b"\x76\xa9"

    def test_guess_not_found(self) -> None:
        from bitcoin.signature.extraction.engine import guess_p2pkh_script

        assert guess_p2pkh_script([b"\x00" * 32]) is None

    def test_guess_not_bytes(self) -> None:
        from bitcoin.signature.extraction.engine import guess_p2pkh_script

        assert guess_p2pkh_script([1, 2, 0x76]) is None


class TestExtractP2WPKHScriptCode:
    def test_normal(self) -> None:
        from bitcoin.signature.extraction.engine import p2wpkh_script_code

        sc = p2wpkh_script(b"\x00" * 20)
        code = p2wpkh_script_code(sc)
        assert len(code) == 26
        assert code[:2] == b"\x19\x76"

    def test_not_opus_zero(self) -> None:
        from bitcoin.signature.extraction.engine import p2wpkh_script_code

        sc = b"\x01\x14" + b"\x00" * 20
        code = p2wpkh_script_code(sc)
        assert len(code) == 26

    def test_short_program(self) -> None:
        from bitcoin.signature.extraction.engine import p2wpkh_script_code

        code = p2wpkh_script_code(b"\x00\x01")
        assert code == b"\x00" * 22

    def test_too_short(self) -> None:
        from bitcoin.signature.extraction.engine import p2wpkh_script_code

        code = p2wpkh_script_code(b"\x00")
        assert code == b"\x00" * 22


class TestExtractDefaultScriptCode:
    def test_default(self) -> None:
        from bitcoin.signature.extraction.engine import default_script_code

        assert default_script_code() == b"\x00" * 22


class TestExtractRecoverOrParsePubkey:
    def test_pubkey_bytes_fallback(self) -> None:
        """When recovery fails and pubkey_bytes is valid, fallback works."""
        from bitcoin.signature.extraction.engine import recover_or_parse_pubkey

        tx = base_tx()
        sig = NON_QR_SIG
        result = recover_or_parse_pubkey(
            tx, 0, sig, 0x01, b"\x00" * 22, value=0,
            pubkey_bytes=TEST_PUB_SEC,
        )
        assert result is not None
        assert result == TEST_PUB

    def test_pubkey_bytes_invalid_sec(self) -> None:
        """When pubkey_bytes is invalid SEC, return None."""
        from bitcoin.signature.extraction.engine import recover_or_parse_pubkey

        tx = base_tx()
        sig = NON_QR_SIG
        result = recover_or_parse_pubkey(
            tx, 0, sig, 0x01, b"\x00" * 22, value=0,
            pubkey_bytes=b"\x00" * 10,
        )
        assert result is None

    def test_pubkey_bytes_none(self) -> None:
        """When recovery fails and pubkey_bytes is None, return None."""
        from bitcoin.signature.extraction.engine import recover_or_parse_pubkey

        tx = base_tx()
        sig = NON_QR_SIG
        result = recover_or_parse_pubkey(
            tx, 0, sig, 0x01, b"\x00" * 22, value=0,
            pubkey_bytes=None,
        )
        assert result is None

    def test_recovery_succeeds(self) -> None:
        """Recovery with valid r=1, s=1 returns a point (not None)."""
        from bitcoin.signature.extraction.engine import recover_or_parse_pubkey

        tx = base_tx()
        result = recover_or_parse_pubkey(
            tx, 0, DER_R1S1, 0x01, b"\x00" * 22, value=0,
        )
        assert result is not None
        assert isinstance(result, Point)


class TestExtractScriptType:
    def test_unknown_type(self) -> None:
        from bitcoin.signature.extraction.engine import determine_script_type

        assert determine_script_type(b"", []) == "unknown"

    def test_known_type(self) -> None:
        from bitcoin.signature.extraction.engine import determine_script_type

        sc = p2pkh_script(b"\x00" * 20)
        assert determine_script_type(sc, []) == P2PKH


class TestExtractComputeSighash:
    def test_legacy(self) -> None:
        from bitcoin.signature.extraction.engine import compute_sighash

        tx = base_tx()
        hs = compute_sighash(tx, 0, b"\x00" * 22, 0x01, 0)
        assert len(hs) == 32

    def test_segwit(self) -> None:
        from bitcoin.signature.extraction.engine import compute_sighash

        tx = base_tx(witness=Witness((b"\x01" * 64,)))
        hs = compute_sighash(tx, 0, b"\x00" * 22, 0x01, 1000)
        assert len(hs) == 32


class TestExtractDeterministicBehavior:
    def test_empty_tx_no_records(self) -> None:
        tx = Tx(version=1, inputs=(), outputs=(), lock_time=0)
        assert extract_signatures(tx) == []

    def test_no_utxo_data(self) -> None:
        tx_in = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
            script_sig=bytes([len(DER_R1S1)]) + DER_R1S1,
            sequence=0xFFFFFFFF,
            witness=EMPTY_WITNESS,
        )
        tx_out = TxOut(value=0, script_pubkey=b"\x6a")
        tx = Tx(version=2, inputs=(tx_in,), outputs=(tx_out,), lock_time=0)
        records = extract_signatures(tx)
        assert isinstance(records, list)
