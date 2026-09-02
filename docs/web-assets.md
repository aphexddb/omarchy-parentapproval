# Parent PWA asset hashes

Verify a served file against this release. `sha384-` values are the
Subresource Integrity pins in `web/index.html`. `sha256` is for `sha256sum`.

| File | sha256 | SRI |
|---|---|---|
| `web/nacl.min.js` | `973cc5733cc7432e30ee4682098f413094f494bccf76a567c23908c5035ddbbc` | `sha384-LMUiUHpaYNGZFzWFRjsADnCSqae1Mk5llcUOHOLDhCxkyF2cdsWAueTZAzV+swW/` |
| `web/sha256.min.js` | `4b53da9acab6a5d4010107be2025002fe1a22da64804dd5200b46895cb899219` | `sha384-2hE+62EhDTI8GB1l6/KBZldM8qsy8CUJ/e5YlZaSbD6Bi4z0YhdrH2LCjDqYXAkg` |
| `web/app.js` | `d7a80f581d84016286f0e71d136ca9605bdde4b894769b363871798da3e07e48` | (versioned `?v=` query; hash this file after each change) |
| `web/app.css` | `13cd618de98fcd97a52cd0e6afdb86aee6dfe236e6e7fdb1324c03ae7d69559e` | |
| `web/sw.js` | `90a0efbf101c8324b85058263c2d99bb5f7d44c8cb885ea6334154ee07bbf415` | |

```bash
sha256sum web/nacl.min.js web/sha256.min.js web/app.js web/app.css web/sw.js
```

Regenerate SRI:

```bash
openssl dgst -sha384 -binary web/nacl.min.js | openssl base64 -A
openssl dgst -sha384 -binary web/sha256.min.js | openssl base64 -A
```
