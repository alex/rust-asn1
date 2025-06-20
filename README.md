# rust-asn1

[![Dependency Status][deps-rs-image]][deps-rs-link]
[![Documentation][docs-rs-image]][docs-rs-link]

This is a Rust library for parsing and generating ASN.1 data (DER only).

## Installation

Add `asn1` to your `Cargo.toml`:

```console
$ cargo add asn1
```

Builds on Rust 1.74.0 and newer.

`rust-asn1` is compatible with `#![no_std]` environments:

```console
$ cargo add asn1 --no-default-features
```

## Changelog

### Unreleased

### [0.22.0]

#### Added

- Added `Asn1Writable::encoded_length`, `SimpleAsn1Writable::data_length`, and
  `Asn1DefinedByWritable::encoded_length`. Implementing these functions reduces
  the number of re-allocations required when writing. `None` can be returned if
  it is not possible to provide an efficient implementation.

#### Changes

- Updated MSRV to 1.74.0.

### [0.21.3]

#### Added

- `BitString::new` is now `const fn`.

### [0.21.2]

#### Added

- `BigInt::new`, `BigUint::new`, and `DateTime::new` are now `const fn`.

### [0.21.1]

#### Added

- `Parser` now exposes a `peek_tag` method that returns the tag of the next
   element in the parse, without consuming that element.
   ([#532](https://github.com/alex/rust-asn1/pull/532))
- `Parser` now exposes `read_explicit_element` and `read_implicit_element`
   methods that allow parsing EXPLICIT/IMPLICIT elements when the tag number
   is not known at compile time.
- `PrintableString`, `Utf8String`, `BMPString`, and `UniversalString` now
  `#[derive(Hash)]`. ([#536](https://github.com/alex/rust-asn1/pull/536))

### [0.21.0]

#### Changes

- Updated MSRV to 1.65.0.

#### Fixes

- Fixed ["perfect derives"](https://smallcultfollowing.com/babysteps/blog/2022/04/12/implied-bounds-and-perfect-derive/)
  in conjunction with `#[derive(Asn1DefinedByRead)]` and
  `#[derive(Asn1DefinedByWrite)]`.
  ([#506](https://github.com/alex/rust-asn1/pull/506))

### [0.20.0]

#### :rotating_light: Breaking changes

- Removed `Writer::{write_explicit_element, write_optional_explicit_element, write_implicit_element, write_optional_implicit_element}`.
  These can all be better accomplished with the `asn1::Explicit` and
  `asn1::Implicit` types.

#### Fixes

- Fixed ["perfect derives"](https://smallcultfollowing.com/babysteps/blog/2022/04/12/implied-bounds-and-perfect-derive/)
  in conjunction with `#[implicit]` and `#[explicit]`.
  ([#502](https://github.com/alex/rust-asn1/pull/502))

### [0.19.0]

#### :rotating_light: Breaking changes

- `GeneralizedTime` has been renamed to `X509GeneralizedTime`. The type does
  not allow fractional seconds, however this restriction is not actually a DER
  rule, it is specific to X.509.
  ([#494](https://github.com/alex/rust-asn1/pull/494))

- `GeneralizedTime` is a new type that accepts fractional seconds
  replacing the old `GeneralizedTime`.
  ([#492](https://github.com/alex/rust-asn1/pull/492))

- `#[derive(asn1::Asn1Read)]` and `#[derive(asn1::Asn1Write)]` now implement
  ["perfect derives"](https://smallcultfollowing.com/babysteps/blog/2022/04/12/implied-bounds-and-perfect-derive/).
  ([#496](https://github.com/alex/rust-asn1/pull/496))

[deps-rs-image]: https://deps.rs/repo/github/alex/rust-asn1/status.svg
[deps-rs-link]: https://deps.rs/repo/github/alex/rust-asn1
[docs-rs-image]: https://docs.rs/asn1/badge.svg
[docs-rs-link]: https://docs.rs/asn1/
