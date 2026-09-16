# Gitar Postgres compatibility fork

The `gitar-0.6.11` branch preserves the Quaint API used by Prisma client Rust 0.6.11 and Prisma engines `pcr-0.6.10`. Its upstream base is `Brendonovich/quaint` tag `0.6.5`, commit `c502995f`.

The `postgresql` feature uses rustls with an explicit ring provider. It retains the patched PgBouncer driver from `gitarcode/rust-postgres` at `418e011eb5ea53fa2ca8050726df3fb6e224e60d`. Other database connectors are outside this fork's TLS migration.

System roots and PEM roots supplied with `sslcert` remain supported. `sslidentity` and `sslpassword` still load PKCS#12 using the Rust `p12-keystore` parser, including legacy encryption. `sslaccept` and `sslmode` retain their existing defaults. This release does not tighten certificate verification defaults.

Consumers must repeat both Cargo patch tables from this manifest at their workspace root. Cargo ignores patches in dependencies. The registry patch makes `tokio-postgres-rustls` use the same driver source as Quaint.

Run `python3 tests/rustls/run.py` with Docker and OpenSSL 3 to exercise certificate verification and SCRAM channel binding. The runner also covers client identities and TLS negotiation. Set `OPENSSL_BIN` if OpenSSL 3 is not the default executable.

Release tested source with immutable tags and pin consumers by commit. CLI binaries and checksums belong to the compatible `gitarcode/prisma-client-rust` release, which consumes this fork. Downloaded Prisma engine executables are separate artifacts and do not inherit this source change.
