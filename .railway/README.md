# Railway Infrastructure as Code

Project config for **parentapprovals** lives in `railway.ts`. Config as Code
(`railway.toml` / `railway.json`) is deprecated.

```bash
npm install
railway config plan    # preview
railway config apply   # apply after review
```

This file owns the whole environment. Do not add a named `partial` export.
