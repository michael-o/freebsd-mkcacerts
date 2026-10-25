# mkcacerts

Generate a Java-compatible PKCS#12 truststore from FreeBSD's
[`certctl(8)`](https://man.freebsd.org/cgi/man.cgi?certctl(8)) trusted
certificate store — no JVM or `keytool` required.

`mkcacerts` reads the hashed certificate directory `certctl(8)`
already maintains (`/etc/ssl/certs` by default) and writes a
password-less PKCS#12 file that a JVM can use directly as its default
truststore via `-Djavax.net.ssl.trustStore`. Each certificate's
PKCS#12 `friendlyName` is derived from its subject, with the
`certctl(8)` hashed file name always appended (e.g.
`Example CA (deadbeef.0)`) to guarantee uniqueness and let the name
be traced back to its file — purely cosmetic, with no effect on
trust decisions.

## Why

FreeBSD's system truststore and a JVM's default truststore
(`cacerts`) are normally two independent, manually synchronized
things. `mkcacerts` derives the latter from the former automatically,
so the system CA bundle stays the single source of truth.

For the generated file to actually become a JVM's default truststore,
the target `java/openjdkN` port must be built with its
`OPENJDK_SYMLINK_CACERTS` variable set to `mkcacerts`'s output path —
see [`mkcacerts(8)`](mkcacerts.8) for details.

## Requirements

- FreeBSD, with `certctl(8)` already populating `/etc/ssl/certs`
- OpenSSL 3.0 or later (3.2+ unlocks a cleaner code path; both are
  supported)
- `bmake` / `bsd.prog.mk`

## Build

```sh
make
```

## Usage

```sh
mkcacerts -v
```

See [`mkcacerts(8)`](mkcacerts.8) for the full option and environment
variable reference.

## Status

Functional and tested against real `certctl(8)` output on FreeBSD
14.5/OpenSSL 3.0 and FreeBSD 16-CURRENT/OpenSSL 3.5, including
cross-platform verification against a non-FreeBSD, non-OpenJDK JVM.
A FreeBSD port is drafted but not yet published or test-built.
Folding this functionality directly into `certctl(8)` is planned but
not yet done.

## License

BSD-2-Clause, see [`LICENSE`](LICENSE).
