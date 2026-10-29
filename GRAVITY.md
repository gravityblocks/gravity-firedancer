# Gravity relay support for Firedancer

This fork lets a Firedancer leader build its blocks from a Gravity block
building relay, as [gravity-connector](https://github.com/gravityblocks/gravity-connector)
does for Agave through the scheduler bindings.  It follows the
connector's behaviour wherever that is natural in Firedancer, and states
the reason wherever it does not.

Status: experimental.  Unit tested, and tested end to end on a local
single-node cluster with the relay and a test block builder.  Not run on
testnet or mainnet.

## Scope

In scope:

- a relay session from the leader: authentication with the identity key,
  slot progress, and relay failover;
- forwarding TPU transactions and Jito bundles to the relay;
- executing the relay's mini-block graphs in leader slots, and reporting
  a result per graph node;
- falling back to native block packing, and the connector's failsafe;
- the Jito tip crank in relay-built slots, when `[tiles.bundle]` is
  enabled.

Out of scope for now:

- builder transactions that use address lookup tables (rejected with
  `ALT_NOT_FOUND`; forwarded transactions may use them);
- the shred destinations the relay sends (`ShredReceiverAddresses`,
  `ShredRetransmitReceiverAddresses`); shred routing stays static
  configuration;
- the relay's `PreviousTipReceiver` (pack reads the tip payment config
  from its bank) and `ReadyForTips`.

## Design

**The relay client runs inside the pack tile.**  There is no new tile,
no extra core and no sidecar process.  The code is in
`src/disco/pack/gravity/`:

| File | Role |
|---|---|
| `fd_gravity_wire.{c,h}` | Relay wire codec (flux framing, wincode payloads), bounded decoding |
| `fd_gravity_sess.{c,h}` | Non-blocking TCP session: connect, `SOLGTC01` login, buffers, failover across up to 4 relays |
| `fd_gravity.{c,h}` | Progress, forwarding and retention, graph intake, window modes, results, failsafe, Jito |

Pack calls in from a few hooks in `fd_pack_tile.c`: housekeeping, the
`resolv_pack` input, becoming leader, scheduling, execution results, and
the end of a slot.

**Session.**  Pack opens an outbound TCP connection to the relay.  It
signs the login challenge with the validator identity over a
`pack_sign` link: the bundle tile's link when that tile is enabled,
otherwise one added for gravity.  The keyguard accepts one new payload
type: exactly 72 bytes starting with `SOLGTC01`, which cannot be
mistaken for a transaction message.

**Progress.**  Pack builds `Progress` messages from the replay messages
it already consumes.  A leader slot's Progress is sent when pack becomes
leader, because the relay releases a slot's first mini-block on its
first Progress.

**Forwarding and retention.**  Every transaction pack receives from
resolv is forwarded to the relay as a `Transaction` message, and a
copy is kept in a retention ring (256 MiB by default).  The relay refers
to forwarded transactions by signature prefix only, so graph nodes are
resolved against that ring.

**Graph execution.**  Each node of a mini-block graph becomes an
`fd_pack` bundle, and the nodes are inserted in index order.  The relay
only emits forward edges, so pack's bundle FIFO together with account
locks executes the nodes in an order equivalent to the graph.  A result
is reported for every node.  Nodes that never ran are reported with a
reason (for example `SLOT_ENDED`).

**Window modes.**  The mode is decided at the first leader slot of each
4-slot window:

- **GRAVITY:** pack schedules only the relay's nodes, plus the tip
  crank's initializer bundle, which runs first.
- **NATIVE:** upstream pack behaviour.

A window is GRAVITY if the session has been up, and sending Progress,
for 12 s.  The relay announces new connectors to builders on a 10 s
timer, and this warmup covers it.  A GRAVITY window stays GRAVITY to its
end, even if slots stay empty, unless the session drops.  The rest of
the window is then NATIVE.

**Failsafe**, as in the connector:

- A GRAVITY slot is *missed* if orders were offered to the relay but
  nothing from it was scheduled.  Orders that were dropped because the
  send buffer was full still count.
- A later slot of the same leadership that schedules relay work clears
  the miss.  Adjacent windows count as one leadership.
- A leadership that ends on a miss trips a latch.  After that, every
  window is NATIVE, nothing is forwarded and no Progress is sent, until
  the relay sends `DeleteFailsafe` or Firedancer restarts.

There is no failsafe file, and the process never exits on relay
trouble.

**Jito** (when `[tiles.bundle]` is enabled):

- **Routing:** bundles from the block engine are retained.  Unless the
  current window is NATIVE, there is no session or the failsafe is
  tripped, they are forwarded to
  the relay as `BundleV2` under Jito's bundle id instead of going into
  pack.  In GRAVITY windows they execute only as part of the relay's
  mini-blocks.
- **Mode changes:** bundles move between pack and the relay as windows
  change mode.  At a GRAVITY slot start, native bundles are deleted from
  pack and forwarded.  At a NATIVE window start or a mid-window
  fallback, retained bundles that are not in pack are inserted back.
- **Tips:** pack's own tip crank runs before the relay's nodes, through
  pack's initializer-bundle gate.  If the crank fails, the relay's nodes
  run without it for the rest of that window.

**Trust.**  Builder-supplied transactions are parsed but not
signature-verified, as with Agave and the connector: the relay is
trusted.

## Differences from Agave with gravity-connector

| Aspect | Agave + connector | This fork | Why |
|---|---|---|---|
| Process | Separate connector, scheduler bindings | Inside the pack tile | No extra core; no IPC hop |
| Failsafe state | On-disk file; process exits | In-memory latch; cleared by `DeleteFailsafe` or a restart | Keeps on-disk state compatible with upstream; the validator never exits because of the relay |
| Session warmup | None | 12 s before a window is GRAVITY | The relay announces connectors to builders on a 10 s timer |
| Tip crank | Connector's tip manager on plain Agave; Jito-Agave cranks itself | Firedancer's crank (bundle tile) | Firedancer already has a crank |
| Graph dispatch | Deepest ready node first | Bundle FIFO in node order | Reuses `fd_pack` unchanged; equivalent for forward-edge graphs |
| ALTs in builder transactions | Supported | Rejected (`ALT_NOT_FOUND`) | Needs resolution in pack; not done yet |

## Changes to upstream files

Outside `src/disco/pack/gravity/` the fork adds about 780 lines and
removes about 90, not counting the generated seccomp header:

- **`fd_pack_tile.c`:** most of the change (about 500 lines added).  It
  holds the hooks, the crank decision, the sandbox fields, and the
  relay socket fd.
- **`fd_pack.{c,h}`:** one new function, `fd_pack_delete_bundles`.
- **Pack sandbox:** `fd_pack_tile.seccomppolicy` and its generated
  header.  Pack may create one `AF_INET` stream socket, and use connect,
  send, receive and close on it.  When gravity is disabled, the address
  family is invalid, so no socket can be created.
- **Topology (`topology.c`, `fd_topo.h`):** the `pack_sign` /
  `sign_pack` links, unreliable taps of `execle_poh`, and the tile's
  gravity configuration.
- **Configuration (`fd_config*`, `default.toml`):** the
  `[tiles.gravity]` section.
- **Keyguard:** the new payload type, with tests.

Gravity is off by default.  With `enabled = false`, the seccomp policy
denies sockets and the gravity hooks are skipped.

## Configuration

```toml
[tiles.gravity]
    enabled = true
    relays = [ "192.0.2.10:9000" ] # example; IPv4 literals, at most 4
    retention_buffer_mib = 256
    receive_buffer_mib = 32
    send_buffer_mib = 8
    max_lane_nodes = 16384
    filter_ofac = false
    jito_tip_weight_bps = 10000
```

Each option is documented in `src/app/firedancer/config/default.toml`.
With `[tiles.bundle]`, `[tiles.pack] use_consumed_cus` must be enabled.

## Testing

```bash
make -j test_gravity test_gravity_wire test_gravity_sess test_keyguard
"$(make --silent objdir)/unit-test/test_gravity"
```

- **`test_gravity_wire`, `test_gravity_sess`:** check the codec and the
  session against golden vectors generated from the relay's Rust types.
  See `contrib/gravity-wire-vectors/` to regenerate them.
- **`test_gravity`:** drives window modes, intake, results, the failsafe
  and Jito against a real `fd_pack`.

## Open points

1. **Crank not tested end to end.**  The Jito tip crank in GRAVITY slots
   has not yet run on a chain with the Jito programs deployed.
2. **Untested pack-tile paths.**  The crank decision, crank-failure
   handling and the post-fallback bundle mask in `fd_pack_tile.c` have
   no unit tests.  They need a small harness around the tile.
3. **ALTs in builder transactions** are rejected.  Supporting them means
   resolving lookup tables in pack, or a round trip through resolv.
4. **Jito bundle ids.**  It is unconfirmed that Firedancer's derived
   bundle id equals the block engine's uuid on live traffic.  The relay's
   cross-source dedup relies on it.
5. **Plaintext, unauthenticated link.**  The relay is not authenticated
   to the validator.  Run the relay on a private network or through a
   tunnel.
6. **Untrusted input in the scheduler.**  Relay input is parsed inside
   pack, which now has network access.  Decoding is bounded and has no
   asserts on relay data, but it has not been fuzzed or reviewed for
   security yet.
7. **Performance unmeasured.**  The load on pack's core while leading,
   and FIFO head-of-line blocking on hot-account graphs, have not been
   measured on real builder graphs.  A DAG dispatcher (`fd_rdisp`) in
   front of the FIFO is an option if FIFO dispatch turns out to be too
   slow.
8. **No wire versioning.**  The relay wire carries no version, so the
   codec is pinned to a `gravity-types` release by the golden vectors.
9. **Shred destinations** from the relay are ignored.
10. **Rebase cost.**  `fd_pack_tile.c` changes often upstream, so keep
    the hooks small when rebasing.
