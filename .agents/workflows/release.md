---
description: How to safely build and release the EdgeClaw Desktop agent.
---

# Release & Deployment Workflow

// turbo-all

1. Ensure the code is clean and formatted.
   ```bash
   cargo fmt
   ```

2. Run full test suite.
   ```bash
   cargo test
   ```

3. Run clippy to check for potential issues.
   ```bash
   cargo clippy --all-targets -- -D warnings
   ```

4. Build the release binary.
   ```bash
   cargo build --release
   ```

5. Verify the artifact existence.
   ```bash
   ls -la target/release/edgeclaw_desktop.exe
   ```

6. Generate a release summary and update CHANGELOG.md.
