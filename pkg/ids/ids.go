package ids

import (
	"crypto/rand"
	"encoding/hex"
)

func New() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
