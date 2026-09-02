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
	WatchPrefix     = "OMARCHY-WATCH/1"
	SASPrefix       = "OMARCHY-SAS/1"
	DecisionAllow   = "allow"
	DecisionDeny    = "deny"
	DefaultAskTTL   = 120
	DefaultPairTTL  = 600
	WatchAuthMax    = 60
	WatchNonceMin   = 16
	ListenPort      = 17421
	KidsGroup       = "omarchy-kids"
	DefaultRelayURL = "https://parentapprovals.com"
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

// PairSAS is the 6-digit short-authentication string for a pairing offer.
// It is SHA-256 of OMARCHY-SAS/1\n<sid>\n<pubkey>\n mapped to decimal digits
// with rejection sampling. A substituted key yields different digits, so the
// laptop and phone only match when they saw the same offered key.
func PairSAS(sid, pubkeyB64 string) string {
	h := sha256.Sum256([]byte(SASPrefix + "\n" + sid + "\n" + pubkeyB64 + "\n"))
	return digitsFromHash(h[:], 6)
}

// digitsFromHash maps digest bytes to n decimal digits without modulo bias.
// Bytes 250–255 are skipped (250 is the largest multiple of 10 that fits in a
// byte). If the digest runs out, it is re-hashed with a counter.
func digitsFromHash(sum []byte, n int) string {
	out := make([]byte, 0, n)
	block := sum
	for counter := 0; len(out) < n; counter++ {
		for _, b := range block {
			if b >= 250 {
				continue
			}
			out = append(out, '0'+b%10)
			if len(out) == n {
				return string(out)
			}
		}
		h := sha256.New()
		h.Write(sum)
		h.Write([]byte{byte(counter + 1)})
		block = h.Sum(nil)
	}
	return string(out)
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

// CanonicalWatch is signed by a paired parent phone to subscribe to live asks.
// host_id is B64(host pubkey), not the hostname. nonce is unpadded base64url
// of at least WatchNonceMin random bytes, unique per poll. exp is unix seconds.
func CanonicalWatch(hostID, deviceID, nonce string, exp int64) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%d\n", WatchPrefix, hostID, deviceID, nonce, exp))
}

func WatchAuthFresh(exp, now int64) bool {
	return exp > now && exp <= now+WatchAuthMax
}

// ValidWatchNonce accepts an unpadded base64url nonce of at least 16 bytes.
func ValidWatchNonce(nonce string) bool {
	raw, err := DecodeB64(nonce)
	return err == nil && len(raw) >= WatchNonceMin
}

// ConsumeWatchNonce records a used (device, nonce) until exp. A repeat is
// rejected so a captured watch URL cannot be replayed inside the window.
func ConsumeWatchNonce(used map[string]int64, deviceID, nonce string, exp, now int64) bool {
	if used == nil || deviceID == "" || nonce == "" {
		return false
	}
	for k, e := range used {
		if e <= now {
			delete(used, k)
		}
	}
	key := deviceID + "\x00" + nonce
	if _, ok := used[key]; ok {
		return false
	}
	used[key] = exp
	return true
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

// StripLeadingSudo removes a leading sudo/pkexec (and a following --) so
// `ask --cmd "sudo echo hi"` and `sudo echo hi` hash to the same inner command.
func StripLeadingSudo(cmd string) string {
	s := strings.TrimSpace(cmd)
	for {
		switch {
		case strings.HasPrefix(strings.ToLower(s), "sudo "):
			s = strings.TrimSpace(s[5:])
		case strings.HasPrefix(s, "/usr/bin/sudo "):
			s = strings.TrimSpace(s[len("/usr/bin/sudo "):])
		case strings.HasPrefix(s, "/bin/sudo "):
			s = strings.TrimSpace(s[len("/bin/sudo "):])
		case strings.HasPrefix(strings.ToLower(s), "pkexec "):
			s = strings.TrimSpace(s[7:])
		case strings.HasPrefix(s, "-- "):
			s = strings.TrimSpace(s[3:])
		default:
			return s
		}
	}
}

// SudoShellKey is the cmdline PAM will see when ask runs `sudo -- sh -c inner`.
func SudoShellKey(displayed string) string {
	return "sh -c " + StripLeadingSudo(displayed)
}

// PolkitService is an ad-hoc polkit PAM/helper service. Those prompts stay
// stock: no parentapproval QR on the laptop.
func PolkitService(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "polkit", "polkit-1":
		return true
	default:
		return false
	}
}

// Request is the JSON body for GET /a/{rid}.
type Request struct {
	V        int               `json:"v"`
	RID      string            `json:"rid"`
	Nonce    string            `json:"nonce"`
	Exp      int64             `json:"exp"`
	Match    string            `json:"match"`
	HostName string            `json:"host_name"`
	HostID   string            `json:"host_id"`
	User     string            `json:"user"`
	Service  string            `json:"service"`
	CWD      string            `json:"cwd"`
	Cmd      string            `json:"cmd"`
	CmdHash  string            `json:"cmd_hash"`
	Sealed   map[string]string `json:"sealed,omitempty"`
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
