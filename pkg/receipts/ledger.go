package receipts

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Receipt struct {
	ReceiptID     string    `json:"receipt_id"`
	RequestHash   string    `json:"request_hash"`
	PolicyVersion string    `json:"policy_version"`
	EvalResult    string    `json:"evaluation_result"`
	TokenID       string    `json:"token_id"`
	Actor         string    `json:"actor"`
	Resource      string    `json:"resource"`
	Connector     string    `json:"connector"`
	ConnectorCode int       `json:"connector_code"`
	Summary       string    `json:"summary"`
	Timestamp     time.Time `json:"timestamp"`
	PrevHash      string    `json:"prev_hash"`
	EntryHash     string    `json:"entry_hash"`
}

type FileLedger struct {
	mu   sync.Mutex
	path string
	last string
}

type ChainStatus struct {
	Valid    bool   `json:"valid"`
	Entries  int    `json:"entries"`
	LastHash string `json:"last_hash"`
}

func NewFileLedger(path string) *FileLedger {
	l := &FileLedger{path: path}
	l.last = l.loadLastHash()
	return l
}

func (l *FileLedger) Append(r Receipt) (Receipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.PrevHash = l.last
	blob := fmt.Sprintf("%s|%s|%s|%s", r.ReceiptID, r.RequestHash, r.TokenID, r.PrevHash)
	h := sha256.Sum256([]byte(blob))
	r.EntryHash = hex.EncodeToString(h[:])
	line := fmt.Sprintf("%s,%s,%s,%s,%s\n", r.Timestamp.UTC().Format(time.RFC3339Nano), r.ReceiptID, r.EntryHash, r.PrevHash, sanitizeSummary(r.Summary))
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return Receipt{}, err
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return Receipt{}, err
	}
	if err := f.Sync(); err != nil {
		return Receipt{}, err
	}
	l.last = r.EntryHash
	return r, nil
}

func (l *FileLedger) VerifyChain() (ChainStatus, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return ChainStatus{Valid: true, Entries: 0, LastHash: ""}, nil
		}
		return ChainStatus{}, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	prev := ""
	entries := 0
	last := ""
	for s.Scan() {
		line := s.Text()
		parts := strings.SplitN(line, ",", 5)
		if len(parts) < 5 {
			return ChainStatus{}, errors.New("invalid ledger line format")
		}
		entryHash := parts[2]
		prevHash := parts[3]
		if prevHash != prev {
			return ChainStatus{Valid: false, Entries: entries, LastHash: last}, nil
		}
		prev = entryHash
		last = entryHash
		entries++
	}
	if err := s.Err(); err != nil {
		return ChainStatus{}, err
	}
	l.last = last
	return ChainStatus{Valid: true, Entries: entries, LastHash: last}, nil
}

func (l *FileLedger) loadLastHash() string {
	f, err := os.Open(l.path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	last := ""
	for s.Scan() {
		parts := strings.Split(s.Text(), ",")
		if len(parts) >= 3 {
			last = parts[2]
		}
	}
	return last
}

func sanitizeSummary(in string) string { return strings.ReplaceAll(in, "\n", " ") }
