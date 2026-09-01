package qrdisp

import "testing"

func TestMatrixAndANSI(t *testing.T) {
	url := "http://192.168.1.20:7421/a/0123456789abcdef0123456789abcdef"
	rows, err := Matrix(url)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 21 {
		t.Fatalf("matrix too small: %d", len(rows))
	}
	for i, row := range rows {
		if len(row) != len(rows) {
			t.Fatalf("row %d length %d want %d", i, len(row), len(rows))
		}
	}
	art, err := ANSI(url)
	if err != nil {
		t.Fatal(err)
	}
	if len(art) < 50 {
		t.Fatal("ANSI QR too small to scan")
	}
	png, err := PNG(url, 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(png) < 100 || png[0] != 0x89 {
		t.Fatal("expected a PNG")
	}
}
