package receipts

import (
	"os"
	"testing"
	"time"
)

func TestLedgerHashChainAppend(t *testing.T) {
	f, err := os.CreateTemp("", "kronyx-ledger-*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)

	l := NewFileLedger(path)
	r1, err := l.Append(Receipt{ReceiptID: "r1", RequestHash: "a", TokenID: "t1", Summary: "s1", Timestamp: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := l.Append(Receipt{ReceiptID: "r2", RequestHash: "b", TokenID: "t2", Summary: "s2", Timestamp: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if r2.PrevHash != r1.EntryHash {
		t.Fatalf("expected chained prev hash")
	}
}
