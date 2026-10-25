# BLS Blueprint

## Local qualification

Automatic pull-request and main-push Rust CI is retired. Before merging source changes, merge the current default branch and qualify the exact candidate through the maintained admitted Beelink gate:

```bash
beelink-gate auto https://github.com/tangle-network/bls-blueprint.git <full-sha> -- bash -lc 'cargo fmt -- --check && forge --version && forge soldeer update -d && forge update && forge build && cargo clippy --tests --examples -- -D warnings && cargo build --tests && RUST_LOG=info cargo nextest run --no-tests=pass'
```

The admitted host needs the repository-owned Rust toolchain, Foundry, protobuf compiler, and cargo-nextest. Solidity dependency preparation precedes the Rust build and tests, as in the retired workflow; inspect any dependency-lock changes before accepting the result. Keep dependency updates separate from production release authority.

Workflow/documentation-only changes use YAML, actionlint, link/content and exact-diff checks. The existing manual [Foundry workflow](.github/workflows/foundry.yml) is retained unchanged. A local qualification result does not publish a package, deploy a Blueprint, or authorize an on-chain transaction.
