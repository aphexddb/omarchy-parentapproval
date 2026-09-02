package web

import "embed"

//go:embed index.html app.js app.css nacl.min.js sha256.min.js manifest.webmanifest sw.js icon-192.png icon-512.png install
var FS embed.FS
