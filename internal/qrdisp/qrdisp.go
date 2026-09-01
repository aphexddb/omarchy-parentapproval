package qrdisp

import (
	"bytes"
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

func PNG(url string, size int) ([]byte, error) {
	if size < 128 {
		size = 256
	}
	return qrcode.Encode(url, qrcode.Medium, size)
}

func Matrix(url string) ([]string, error) {
	q, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	bm := q.Bitmap()
	rows := make([]string, len(bm))
	for i, row := range bm {
		var b strings.Builder
		b.Grow(len(row))
		for _, cell := range row {
			if cell {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		rows[i] = b.String()
	}
	return rows, nil
}

// ANSI renders a compact QR using Unicode half-blocks so a sudo TTY can
// show something a phone camera will actually read.
func ANSI(url string) (string, error) {
	q, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return "", err
	}
	bm := q.Bitmap()
	var buf bytes.Buffer
	n := len(bm)
	for y := 0; y < n; y += 2 {
		for x := 0; x < n; x++ {
			top := bm[y][x]
			bot := false
			if y+1 < n {
				bot = bm[y+1][x]
			}
			switch {
			case top && bot:
				buf.WriteRune('█')
			case top && !bot:
				buf.WriteRune('▀')
			case !top && bot:
				buf.WriteRune('▄')
			default:
				buf.WriteRune(' ')
			}
		}
		buf.WriteByte('\n')
	}
	return buf.String(), nil
}

func Box(title, url, extra string) (string, error) {
	art, err := ANSI(url)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if title != "" {
		fmt.Fprintf(&b, "%s\n\n", title)
	}
	b.WriteString(art)
	if extra != "" {
		fmt.Fprintf(&b, "\n%s\n", extra)
	}
	fmt.Fprintf(&b, "\n%s\n", url)
	return b.String(), nil
}
