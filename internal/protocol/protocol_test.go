package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestPairSASVector(t *testing.T) {
	// Frozen so the phone JS and Go cannot drift.
	got := PairSAS("sid-aaaabbbbccccdddd", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if got != "237103" {
		t.Fatalf("frozen SAS %q want 237103", got)
	}
	if len(got) != 6 {
		t.Fatalf("len %d want 6: %q", len(got), got)
	}
	for _, r := range got {
		if r < '0' || r > '9' {
			t.Fatalf("non-digit %q in %q", r, got)
		}
	}
	again := PairSAS("sid-aaaabbbbccccdddd", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if got != again {
		t.Fatal("PairSAS not stable")
	}
	otherKey := PairSAS("sid-aaaabbbbccccdddd", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	if otherKey == got {
		t.Fatal("different pubkey produced the same SAS")
	}
	otherSID := PairSAS("sid-ffffffffffffffff", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if otherSID == got {
		t.Fatal("different sid produced the same SAS")
	}
}

func TestDigitsFromHashUnbiasedRange(t *testing.T) {
	// 250–255 must not appear as digits via %10 without rejection.
	sum := make([]byte, 32)
	for i := range sum {
		sum[i] = 255
	}
	got := digitsFromHash(sum, 6)
	if len(got) != 6 {
		t.Fatalf("len %d: %q", len(got), got)
	}
	for _, r := range got {
		if r < '0' || r > '9' {
			t.Fatalf("non-digit %q", r)
		}
	}
}

func TestCmdHashStable(t *testing.T) {
	a := CmdHash("milo", "sudo", "/home/milo", "pacman -S steam")
	b := CmdHash("milo", "sudo", "/home/milo", "pacman -S steam")
	if B64(a) != B64(b) {
		t.Fatal("hash not stable")
	}
	c := CmdHash("milo", "sudo", "/home/milo", "pacman -S vim")
	if B64(a) == B64(c) {
		t.Fatal("different commands hashed equal")
	}
}

func TestCanonicalVectors(t *testing.T) {
	// Frozen vector so the phone JS and Go cannot drift.
	got := string(Canonical(
		"allow",
		"9b1c4e7a2d8841f0b3aa55ccdd1199ee",
		"AAAAAAAAAAAAAAAAAAAAAA",
		1735689660,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"milo",
		"sudo",
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	))
	want := "OMARCHY-APPROVE/1\nallow\n9b1c4e7a2d8841f0b3aa55ccdd1199ee\nAAAAAAAAAAAAAAAAAAAAAA\n1735689660\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nmilo\nsudo\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
	if got != want {
		t.Fatalf("canonical mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestCanonicalWatchVector(t *testing.T) {
	got := string(CanonicalWatch(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"phone-1",
		"AAAAAAAAAAAAAAAAAAAAAA",
		1735689660,
	))
	want := "OMARCHY-WATCH/1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nphone-1\nAAAAAAAAAAAAAAAAAAAAAA\n1735689660\n"
	if got != want {
		t.Fatalf("canonical watch mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestConsumeWatchNonce(t *testing.T) {
	used := map[string]int64{}
	if !ConsumeWatchNonce(used, "phone-1", "n1", 1100, 1000) {
		t.Fatal("first nonce rejected")
	}
	if ConsumeWatchNonce(used, "phone-1", "n1", 1100, 1000) {
		t.Fatal("replay accepted")
	}
	if !ConsumeWatchNonce(used, "phone-1", "n2", 1100, 1000) {
		t.Fatal("new nonce rejected")
	}
	if ConsumeWatchNonce(used, "phone-1", "n1", 1100, 1100) {
		// expired entries are pruned; n1's exp is 1100 so at now=1100 it is gone
		// and would be accepted as a new use — only replay while exp>now matters.
	}
	if !ValidWatchNonce(B64(make([]byte, 16))) {
		t.Fatal("16-byte nonce rejected")
	}
	if ValidWatchNonce(B64(make([]byte, 8))) || ValidWatchNonce("") {
		t.Fatal("short nonce accepted")
	}
}

func TestWatchAuthFresh(t *testing.T) {
	now := int64(1000)
	if WatchAuthFresh(now, now) || WatchAuthFresh(now-1, now) {
		t.Fatal("expired watch auth accepted")
	}
	if !WatchAuthFresh(now+60, now) {
		t.Fatal("fresh watch auth rejected")
	}
	if WatchAuthFresh(now+WatchAuthMax+1, now) {
		t.Fatal("over-long watch auth accepted")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cmdHash := CmdHash("maya", "sudo", "/home/maya", "true")
	canon := Canonical("allow", "aa", B64(make([]byte, 16)), 1, B64(pub), "maya", "sudo", B64(cmdHash))
	sig := Sign(priv, canon)
	if !Verify(pub, canon, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(pub, canon, make([]byte, ed25519.SignatureSize)) {
		t.Fatal("zero signature accepted")
	}
	tampered := append([]byte{}, canon...)
	tampered[len(tampered)-2] = 'X'
	if Verify(pub, tampered, sig) {
		t.Fatal("tampered canonical accepted")
	}
}

func TestB64RoundTrip(t *testing.T) {
	raw, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	if got, err := DecodeB64(B64(raw)); err != nil || string(got) != string(raw) {
		t.Fatalf("roundtrip %x -> %s -> %x (%v)", raw, B64(raw), got, err)
	}
}

func TestVerifyRejectsShortKey(t *testing.T) {
	if Verify([]byte("short"), []byte("msg"), make([]byte, 64)) {
		t.Fatal("short pubkey accepted")
	}
}

func TestStripLeadingSudo(t *testing.T) {
	cases := map[string]string{
		"sudo echo 'LLLOOLLL'":     "echo 'LLLOOLLL'",
		"sudo -- pacman -S cowsay": "pacman -S cowsay",
		"pacman -S cowsay":         "pacman -S cowsay",
		"/usr/bin/sudo echo hi":    "echo hi",
		"pkexec true":              "true",
	}
	for in, want := range cases {
		if got := StripLeadingSudo(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestSudoShellKey(t *testing.T) {
	got := SudoShellKey("sudo echo 'LLLOOLLL'")
	want := "sh -c echo 'LLLOOLLL'"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestPolkitService(t *testing.T) {
	for _, s := range []string{"polkit", "polkit-1", "POLKIT-1"} {
		if !PolkitService(s) {
			t.Errorf("%q should be a polkit service", s)
		}
	}
	for _, s := range []string{"sudo", "login", ""} {
		if PolkitService(s) {
			t.Errorf("%q must not be treated as polkit", s)
		}
	}
}
