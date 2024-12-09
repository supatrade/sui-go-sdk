package verify

import (
	"fmt"

	"github.com/block-vision/sui-go-sdk/cryptography"
	"github.com/block-vision/sui-go-sdk/cryptography/scheme"
	"github.com/block-vision/sui-go-sdk/keypairs/ed25519"
	"github.com/block-vision/sui-go-sdk/mystenbcs"
	"github.com/block-vision/sui-go-sdk/zklogin"
)

type ParsedSignature struct {
	Signature []byte
	PublicKey IPublicKey
}

func VerifyPersonalMessageSignature(message []byte, signature []byte, options *zklogin.ZkLoginPublicIdentifierOptions) (signer string, pass bool, err error) {
	parsedSignature, err := parseSignature(signature, options)
	if err != nil {
		return "", false, err
	}

	signer, pass, err = parsedSignature.PublicKey.VerifyPersonalMessage(message, parsedSignature.Signature, options.Client)
	if err != nil {
		return "", false, err
	}

	return signer, pass, nil
}

func parseSignature(signature []byte, options *zklogin.ZkLoginPublicIdentifierOptions) (*ParsedSignature, error) {
	signatureB64 := mystenbcs.ToBase64(signature)
	parsedSignature, err := cryptography.ParseSerializedSignature(signatureB64)
	if err != nil {
		return nil, err
	}

	publicKey, err := publicKeyFromRawBytes(parsedSignature.SignatureScheme, parsedSignature.PubKey, options)
	if err != nil {
		return nil, err
	}

	return &ParsedSignature{
		Signature: parsedSignature.Signature,
		PublicKey: publicKey,
	}, nil
}

// publicKeyFromRawBytes function in Go
func publicKeyFromRawBytes(signatureScheme scheme.SignatureScheme, bytes []byte, options *zklogin.ZkLoginPublicIdentifierOptions) (IPublicKey, error) {
	switch signatureScheme {
	case scheme.ED25519:
		return ed25519.NewEd25519PublicKey(bytes), nil
	case scheme.ZkLogin:
		return zklogin.NewZkLoginPublicIdentifier(bytes, options), nil
	default:
		return nil, fmt.Errorf("Unsupported signature scheme %s", signatureScheme)
	}
}
