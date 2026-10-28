# `blstrs_plus`

This crate provides an implementation of the BLS12-381 pairing-friendly elliptic curve construction with hash-to-curve and multi-exponentiation methods.

* **This implementation has not been reviewed or audited. Use at your own risk.**
* This implementation targets Rust `1.87` or later.
* This implementation does not require the Rust standard library.
* All operations are constant time unless explicitly noted.

## Features

* `bits` (on by default): Enables APIs for obtaining bit iterators for scalars.
* `groups` (on by default): Enables APIs for performing group arithmetic with G1, G2, and GT.
* `pairings` (on by default): Enables APIs for performing pairings.
* `alloc` (on by default): Enables APIs that require an allocator.
* `ark`: Enables compatibility with the arkworks ecosystem and the Rust standard library.
* `expose-fields`: Exposes the internal field modules; this also enables `groups`.
* `std`: Enables APIs that require the Rust standard library.

## Testing

Test for non-wasm32 targets:

```sh
cargo test --all-features
```

Test wasm32 targets:

```sh
cargo test --target wasm32-unknown-unknown
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
