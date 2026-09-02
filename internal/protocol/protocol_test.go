package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

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
