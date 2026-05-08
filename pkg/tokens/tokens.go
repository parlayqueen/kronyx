package tokens

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"kronyx/pkg/canonicaljson"
	"kronyx/pkg/crypto"
)

type Claims struct {
	TokenID    string            `json:"token_id"`
	ActionType string            `json:"action_type"`
	Subject    string            `json:"subject"`
	Resource   string            `json:"resource"`
	Bounds     map[string]string `json:"bounds"`
	Audience   string            `json:"aud"`
	ExpiresAt  time.Time         `json:"exp"`
	Nonce      string            `json:"nonce"`
	Revocation string            `json:"revocation_ref"`
	IssuedAt   time.Time         `json:"iat"`
	KeyID      string            `json:"kid"`
}

type SignedToken struct {
	Payload   []byte
	Signature string
	Claims    Claims
}

func Mint(priv ed25519.PrivateKey, claims Claims) (string, error) {
	if claims.TokenID == "" || claims.ActionType == "" || claims.Audience == "" || claims.KeyID == "" {
		return "", errors.New("missing required token claims")
	}
	if time.Now().UTC().After(claims.ExpiresAt) {
		return "", errors.New("token expiry in the past")
	}
	payload, err := canonicaljson.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("canonicalize claims: %w", err)
	}
	sig := crypto.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + sig, nil
}

func Parse(raw string) (SignedToken, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return SignedToken{}, errors.New("token must be 2-part payload.signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return SignedToken{}, fmt.Errorf("decode payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return SignedToken{}, fmt.Errorf("decode claims: %w", err)
	}
	return SignedToken{Payload: payload, Signature: parts[1], Claims: claims}, nil
}

func Verify(pub ed25519.PublicKey, tok SignedToken, expectedAudience string, now time.Time) error {
	if err := crypto.Verify(pub, tok.Payload, tok.Signature); err != nil {
		return fmt.Errorf("signature verify failed: %w", err)
	}
	if tok.Claims.Audience != expectedAudience {
		return errors.New("token audience mismatch")
	}
	if now.UTC().After(tok.Claims.ExpiresAt) {
		return errors.New("token expired")
	}
	return nil
}
