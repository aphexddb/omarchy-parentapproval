package web

import "embed"

//go:embed index.html app.js app.css nacl.min.js sha256.min.js
var FS embed.FS
