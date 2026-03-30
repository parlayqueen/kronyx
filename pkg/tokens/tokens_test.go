package tokens

import (
	"testing"
	"time"

	"kronyx/pkg/crypto"
)

func TestMintParseVerify(t *testing.T) {
	kp, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Mint(kp.Private, Claims{TokenID: "t1", ActionType: "deploy.promote_to_prod", Subject: "svc", Resource: "service/api", Audience: "enforcement-gateway", ExpiresAt: time.Now().UTC().Add(time.Minute), Nonce: "n1", Revocation: "r1", IssuedAt: time.Now().UTC(), KeyID: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(kp.Public, parsed, "enforcement-gateway", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}
