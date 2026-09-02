package web

import (
	"crypto/ed25519"
	"encoding/json"
	"os/exec"
	"testing"

	"parentapproval/internal/protocol"
)

func TestJSOpensGoSealedAsk(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := protocol.AskFields{
		User:     "milo",
		CWD:      "/home/milo",
		Cmd:      "pacman -S steam",
		HostName: "kid-laptop",
	}
	blob, err := protocol.SealAsk(want, pub)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", "box_sim.mjs", blob, protocol.B64(priv))
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("box_sim: %v\n%s", err, out)
	}
	var got protocol.AskFields
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json %v: %s", err, out)
	}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
}
