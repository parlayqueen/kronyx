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
	status, err := l.VerifyChain()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Valid || status.Entries != 2 {
		t.Fatalf("expected valid chain with 2 entries, got %+v", status)
	}
}

func TestLedgerVerifyDetectsTamper(t *testing.T) {
	f, err := os.CreateTemp("", "kronyx-ledger-*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	defer os.Remove(path)

	l := NewFileLedger(path)
	_, _ = l.Append(Receipt{ReceiptID: "r1", RequestHash: "a", TokenID: "t1", Summary: "s1", Timestamp: time.Now()})
	_, _ = l.Append(Receipt{ReceiptID: "r2", RequestHash: "b", TokenID: "t2", Summary: "s2", Timestamp: time.Now()})

	// tamper second line prev_hash column
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := string(content)
	lines = replaceSecondPrevHash(lines)
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	status, err := l.VerifyChain()
	if err != nil {
		t.Fatal(err)
	}
	if status.Valid {
		t.Fatalf("expected tampered chain to be invalid")
	}
}

func replaceSecondPrevHash(in string) string {
	parts := splitLines(in)
	if len(parts) < 2 {
		return in
	}
	cols := splitCSV(parts[1])
	if len(cols) >= 4 {
		cols[3] = "tampered"
		parts[1] = joinCSV(cols)
	}
	return joinLines(parts)
}

func splitLines(in string) []string {
	out := []string{}
	cur := ""
	for _, r := range in {
		if r == '\n' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

func splitCSV(line string) []string {
	out := []string{}
	cur := ""
	for _, r := range line {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}

func joinCSV(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}
