# Changelog

All notable changes to `blstrs_plus` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-07-31

- Updated core cryptography trait dependencies to their latest compatible patch releases.
- Bumped `criterion` to `0.8.2`.
- Used `elliptic-curve-tools` for faster small- and medium-sized sums of products with `alloc`.
- Added `elliptic-curve`, `ff`, and `group` `0.14` compatibility while preserving the `0.13` traits required by `pairing`.
- Added arkworks compatibility behind the `ark` feature.
- Implemented `IsHigh` for the field and scalar types.

## [0.8.15] - 2024-02-16

- Match bls12_381_plus methods
- Update dependencies

## [0.8.9] - 2023-10-18

- Match bls12_381_plus methods

## [0.8.6] - 2023-10-18

- Fixed issue with 32-bit builds

## [0.1.0] - 2020-10-08

- Initial release
