package ed25519

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/machinebox/graphql"
	"golang.org/x/crypto/blake2b"

	"github.com/block-vision/sui-go-sdk/constant"
	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/mystenbcs"
)

type SigFlag byte

const (
	SigFlagEd25519   SigFlag = 0x00
	SigFlagSecp256k1 SigFlag = 0x01
)

type Ed25519PublicKey struct {
	signature []byte
}

func NewEd25519PublicKey(signature []byte) *Ed25519PublicKey {
	return &Ed25519PublicKey{
		signature: signature,
	}
}

func (e *Ed25519PublicKey) ToSuiAddress() string {
	return ""
}

func (e *Ed25519PublicKey) VerifyPersonalMessage(message []byte, signature []byte, client *graphql.Client) (string, bool, error) {
	messageB64 := mystenbcs.ToBase64(message)
	signatureB64 := mystenbcs.ToBase64(signature)

	return VerifyMessage(messageB64, signatureB64, constant.PersonalMessageIntentScope)
}

func VerifyMessage(message, signature string, scope constant.IntentScope) (signer string, pass bool, err error) {
	messageBytes, err := mystenbcs.FromBase64(message)
	if err != nil {
		return "", false, err
	}

	messageWithIntent := models.NewMessageWithIntent(messageBytes, scope)

	serializedSignature, err := models.FromSerializedSignature(signature)
	if err != nil {
		return "", false, err
	}

	digest := blake2b.Sum256(messageWithIntent)

	pass = ed25519.Verify(serializedSignature.PubKey[:], digest[:], serializedSignature.Signature)

	signer = Ed25519PublicKeyToSuiAddress(serializedSignature.PubKey)

	return
}

func Ed25519PublicKeyToSuiAddress(pubKey []byte) string {
	newPubkey := []byte{byte(models.SigFlagEd25519)}
	newPubkey = append(newPubkey, pubKey...)

	addrBytes := blake2b.Sum256(newPubkey)
	return fmt.Sprintf("0x%s", hex.EncodeToString(addrBytes[:])[:64])
}
