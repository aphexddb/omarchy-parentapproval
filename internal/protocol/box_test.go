package protocol

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestEd25519ToX25519MatchesBasepoint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	xpriv, err := Ed25519SeedToX25519(priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	want, err := curve25519.X25519(xpriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Ed25519PubToX25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("pub conversion != scalar base\n got %x\nwant %x", got[:], want)
	}
}

func TestSealAskRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := AskFields{User: "milo", CWD: "/home/milo", Cmd: "pacman -S steam", HostName: "kid-laptop"}
	blob, err := SealAsk(want, pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAsk(blob, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAsk(blob, other); err == nil {
		t.Fatal("other parent opened the blob")
	}
}

func TestOpenAskRejectsShortBlob(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAsk("AAAA", priv); err == nil {
		t.Fatal("short blob accepted")
	}
}
