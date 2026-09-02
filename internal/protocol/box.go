package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"math/big"

	"golang.org/x/crypto/nacl/box"
)

// AskFields are the request values sealed to each parent phone so the relay
// (and anyone else on the wire) sees only an opaque blob.
type AskFields struct {
	User     string `json:"user"`
	CWD      string `json:"cwd"`
	Cmd      string `json:"cmd"`
	HostName string `json:"host_name"`
}

// SealAsk encrypts fields to a paired Ed25519 public key using a NaCl box
// (X25519 + XSalsa20-Poly1305). The blob is
// ephemeral_pub (32) || nonce (24) || ciphertext, unpadded base64url.
func SealAsk(fields AskFields, parentPub ed25519.PublicKey) (string, error) {
	plain, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return SealToParent(plain, parentPub)
}

// OpenAsk decrypts a SealAsk blob with the parent Ed25519 private key.
func OpenAsk(blob string, parentPriv ed25519.PrivateKey) (AskFields, error) {
	plain, err := OpenFromDaemon(blob, parentPriv)
	if err != nil {
		return AskFields{}, err
	}
	var f AskFields
	if err := json.Unmarshal(plain, &f); err != nil {
		return AskFields{}, err
	}
	return f, nil
}

// SealToParent boxes plain to the X25519 form of parentPub.
func SealToParent(plain []byte, parentPub ed25519.PublicKey) (string, error) {
	their, err := Ed25519PubToX25519(parentPub)
	if err != nil {
		return "", err
	}
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	ct := box.Seal(nil, plain, &nonce, &their, ephPriv)
	out := make([]byte, 32+24+len(ct))
	copy(out[0:32], ephPub[:])
	copy(out[32:56], nonce[:])
	copy(out[56:], ct)
	return B64(out), nil
}

// OpenFromDaemon opens a SealToParent blob with the parent Ed25519 key.
func OpenFromDaemon(blob string, parentPriv ed25519.PrivateKey) ([]byte, error) {
	raw, err := DecodeB64(blob)
	if err != nil || len(raw) < 32+24+16 {
		return nil, errors.New("bad sealed blob")
	}
	if len(parentPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("bad ed25519 private key")
	}
	var their [32]byte
	copy(their[:], raw[0:32])
	var nonce [24]byte
	copy(nonce[:], raw[32:56])
	mine, err := Ed25519SeedToX25519(parentPriv.Seed())
	if err != nil {
		return nil, err
	}
	plain, ok := box.Open(nil, raw[56:], &nonce, &their, &mine)
	if !ok {
		return nil, errors.New("unseal failed")
	}
	return plain, nil
}

// Ed25519SeedToX25519 is the standard clamped SHA-512 scalar used by both
// Ed25519 signing and X25519.
func Ed25519SeedToX25519(seed []byte) ([32]byte, error) {
	var out [32]byte
	if len(seed) != ed25519.SeedSize {
		return out, errors.New("bad ed25519 seed")
	}
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	copy(out[:], h[:32])
	return out, nil
}

// Ed25519PubToX25519 maps an Edwards Y coordinate to Montgomery u = (1+y)/(1-y).
func Ed25519PubToX25519(pub ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte
	if len(pub) != ed25519.PublicKeySize {
		return out, errors.New("bad ed25519 public key")
	}
	yBytes := make([]byte, 32)
	copy(yBytes, pub)
	yBytes[31] &= 0x7f
	y := new(big.Int).SetBytes(reverse32(yBytes))
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	one := big.NewInt(1)
	num := new(big.Int).Add(one, y)
	den := new(big.Int).Sub(one, y)
	den.Mod(den, p)
	if den.Sign() == 0 {
		return out, errors.New("ed25519 to x25519: y=1")
	}
	inv := new(big.Int).ModInverse(den, p)
	if inv == nil {
		return out, errors.New("ed25519 to x25519: no inverse")
	}
	u := new(big.Int).Mul(num, inv)
	u.Mod(u, p)
	copy(out[:], reverse32(u.FillBytes(make([]byte, 32))))
	return out, nil
}

func reverse32(in []byte) []byte {
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = in[31-i]
	}
	return out
}
