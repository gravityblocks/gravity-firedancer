# Gravity wire golden vectors

Generates `src/disco/pack/gravity/fixtures/test_gravity_wire_vectors.h`,
the golden vectors `test_gravity_wire` and `test_gravity_sess` check the
pack tile's Gravity relay client against.  The bytes come from the real
Rust types: `gravity-types` (the relay/connector wire protocol), `flux`
framing and `wincode`.

`Cargo.lock` pins the wire crates to the versions the relay is built
with (flux can only be pinned there, as `gravity-types` depends on its
git branch).  Currently: `gravity-types` tag `v0.4.1` (`b35d905`), flux
`49cb677`, wincode 0.6.1.

Regenerate (deterministic) with:

```
cd contrib/gravity-wire-vectors
cargo run --release
```

This also writes `vectors.txt`, a readable dump of the same records (not
committed), and runs a loopback self-test of flux-network's TCP framing.

When the relay moves to a new `gravity-types`, bump the tag in
`Cargo.toml`, run `cargo update -p flux` if needed, regenerate, and update the C codec until the tests pass.
