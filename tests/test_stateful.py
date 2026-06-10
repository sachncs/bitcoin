"""Stateful (rule-based) tests for the extraction pipeline."""

from __future__ import annotations

from hypothesis import assume, stateful
from hypothesis import strategies as st

from bitcoin.signature.extraction.engine import extract_signatures
from bitcoin.signature.record import Record
from bitcoin.transaction.models import Tx
from bitcoin.transaction.parser import parse_tx


class ExtractionPipeline(stateful.RuleBasedStateMachine):
    """Stateful test for the extraction pipeline."""

    def __init__(self) -> None:
        super().__init__()
        self.tx: Tx | None = None
        self.records: list[Record] = []

    @stateful.rule(tx_hex=st.text(min_size=1))
    def parse_tx(self, tx_hex: str) -> None:
        assume(all(c in "0123456789abcdefABCDEF" for c in tx_hex))
        assume(len(tx_hex) % 2 == 0)
        try:
            data = bytes.fromhex(tx_hex)
            self.tx, _ = parse_tx(data)
        except ValueError:
            self.tx = None

    @stateful.rule(scripts=st.lists(st.binary(min_size=1, max_size=100)))
    def set_utxo_scripts(self, scripts: list[bytes]) -> None:
        if self.tx is None:
            return
        if len(scripts) < len(self.tx.inputs):
            scripts = list(scripts) + [
                b"" for _ in range(len(self.tx.inputs) - len(scripts))
            ]
        self.utxo_scripts = scripts[:len(self.tx.inputs)]

    @stateful.rule()
    def extract(self) -> None:
        if self.tx is None:
            return
        utxo_scripts = getattr(self, "utxo_scripts", None)
        try:
            self.records = extract_signatures(
                self.tx,
                utxo_script_pubkeys=utxo_scripts,
            )
        except (ValueError, IndexError, TypeError):
            self.records = []

    @stateful.invariant()
    def records_are_valid(self) -> None:
        for rec in self.records:
            assert isinstance(rec, Record)
            assert isinstance(rec.txid, bytes) and len(rec.txid) == 32
            assert isinstance(rec.vin, int) and rec.vin >= 0
            assert isinstance(rec.sig, bytes) and len(rec.sig) >= 1

    @stateful.invariant()
    def linearization_preserves_records(self) -> None:
        if not self.records:
            return
        from bitcoin.signature.linearization import linearize_signatures
        flat = linearize_signatures(self.records)
        assert len(flat) == len(self.records)
        for rec in flat:
            assert isinstance(rec, Record)


TestExtractionPipeline = ExtractionPipeline.TestCase
