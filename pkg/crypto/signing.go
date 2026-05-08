package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func NewKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

func Sign(priv ed25519.PrivateKey, payload []byte) string {
	s := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(s)
}

func Verify(pub ed25519.PublicKey, payload []byte, sig string) error {
	b, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, b) {
		return errors.New("invalid signature")
	}
	return nil
}
