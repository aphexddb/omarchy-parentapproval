// Package protocol is the wire format for parent-phone approvals.
//
// The QR is a capability request, not a capability. Security is an Ed25519
// key that never leaves the parent's phone. Canonical bytes are signed, not
// JSON, so key order cannot change the message.
package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	Version         = 1
	CanonicalPrefix = "OMARCHY-APPROVE/1"
	DecisionAllow   = "allow"
	DecisionDeny    = "deny"
	DefaultAskTTL   = 120
	DefaultPairTTL  = 120
	ListenPort      = 7421
	KidsGroup       = "omarchy-kids"
)

// B64 is raw URL-safe base64 (no padding), used for keys, nonces, hashes, sigs.
func B64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func DecodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// CmdHash is SHA-256 of user\0service\0cwd\0cmd\0. The phone hashes the
// fields it displayed; the daemon hashes the fields it stored. They must match.
func CmdHash(user, service, cwd, cmd string) []byte {
	h := sha256.New()
	h.Write([]byte(user))
	h.Write([]byte{0})
	h.Write([]byte(service))
	h.Write([]byte{0})
	h.Write([]byte(cwd))
	h.Write([]byte{0})
	h.Write([]byte(cmd))
	h.Write([]byte{0})
	return h.Sum(nil)
}

// Canonical is the exact byte string the phone signs and the daemon verifies.
// decision is "allow" or "deny". ridHex is lowercase hex. exp is unix seconds.
func Canonical(decision, ridHex, nonceB64 string, exp int64, hostIDB64, user, service, cmdHashB64 string) []byte {
	var b strings.Builder
	b.Grow(256)
	fmt.Fprintf(&b, "%s\n%s\n%s\n%s\n%d\n%s\n%s\n%s\n%s\n",
		CanonicalPrefix,
		decision,
		ridHex,
		nonceB64,
		exp,
		hostIDB64,
		user,
		service,
		cmdHashB64,
	)
	return []byte(b.String())
}

func Sign(priv ed25519.PrivateKey, canonical []byte) []byte {
	return ed25519.Sign(priv, canonical)
}

func Verify(pub ed25519.PublicKey, canonical, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, canonical, sig)
}

// Request is the JSON body for GET /a/{rid}.
type Request struct {
	V        int    `json:"v"`
	RID      string `json:"rid"`
	Nonce    string `json:"nonce"`
	Exp      int64  `json:"exp"`
	Match    string `json:"match"`
	HostName string `json:"host_name"`
	HostID   string `json:"host_id"`
	User     string `json:"user"`
	Service  string `json:"service"`
	CWD      string `json:"cwd"`
	Cmd      string `json:"cmd"`
	CmdHash  string `json:"cmd_hash"`
}

// Decision is the JSON body for POST /a/{rid}/decision.
type Decision struct {
	V         int    `json:"v"`
	DeviceID  string `json:"device_id"`
	Decision  string `json:"decision"`
	Signature string `json:"sig"`
}

// PairOffer is the JSON body for POST /pair/{sid}.
type PairOffer struct {
	V        int    `json:"v"`
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Alg      string `json:"alg"`
	PubKey   string `json:"pubkey"`
}

// PairDone is returned once the laptop confirms the SAS.
type PairDone struct {
	OK       bool   `json:"ok"`
	HostID   string `json:"host_id"`
	HostName string `json:"host_name"`
	DeviceID string `json:"device_id"`
}
