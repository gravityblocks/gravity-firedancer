# Gravity Firedancer

This fork adds a `gravity` tile to Firedancer. The tile builds the
validator's leader blocks from [GBX](https://docs.gravityblocks.xyz), an
open and competitive marketplace for Solana blockspace. For Agave and
Jito-Solana, use
[gravity-connector](https://github.com/gravityblocks/gravity-connector).

## Compatibility

Each release is a tag named `v<gravity version>+firedancer.<firedancer
version>`, for example `v0.5.0+firedancer.26.10.8`. It is the upstream
Firedancer release with the Gravity patch on top.

## Build

```console
$ git clone https://github.com/gravityblocks/gravity-firedancer.git
$ cd gravity-firedancer
$ git checkout <release tag>
$ ./deps.sh
$ make -j firedancer
```

The binary is `build/firedancer`. Configure and run it as
upstream Firedancer, with the additions below.

## Configuration

Set up the [`[tiles.gravity]`](src/app/firedancer/config/default.toml#L1649)
section of your config. The default config documents every field.

Allow outbound TCP to every relay `host:port`.

## Behavior

- The tile connects to relays only after replay has caught up and the
  identity has upcoming leader slots.
- Pack decides at the first slot of each 4-slot leader window. The
  window is relay-built if a relay session is up then, and packed
  natively otherwise. If the session drops during a relay-built window,
  pack packs the rest of the window natively.
- While a relay session is up, the validator advertises the relay's TPU
  address in gossip. Without a session, it advertises its own TPU again.
- **Failsafe**: if the relay builds nothing in a whole leadership, the
  tile writes `1` to `<paths.base>/gravity_failsafe` and packs natively.
  The failsafe stays set across restarts until the relay clears it.

The rest of this README is upstream Firedancer's.

# [Firedancer](https://jumpcrypto.com/firedancer/) 🔥💃

Firedancer is a new validator client for Solana.

* **Fast** Designed from the ground up to be *fast*. The concurrency
model draws from experience in the low latency trading space, and the code
contains many novel high-performance reimplementations of core Solana
primitives.
* **Secure** The architecture of the validator allows it to run with a
highly restrictive sandbox and almost no system calls.
* **Independent** Firedancer is written from scratch. This brings client
diversity to the Solana network and helps it stay resilient to supply
chain attacks in build tooling or dependencies.

## Documentation
If you are an operator or looking to run the validator, see the Getting
Started guide in the [Firedancer
docs](https://docs.firedancer.io/)

## Releases
If you are an operator looking to run the validator, see the [Releases
Guide](https://docs.firedancer.io/guide/getting-started.html#releases)
in the documentation.

The Firedancer project is producing two validators,

* **Frankendancer** A hybrid validator using parts of Firedancer and
parts of Agave. Frankendancer uses the Firedancer networking stack and
block production components to perform better while leader. Other
functionality including execution and consensus is using the Agave
validator code.
* **Firedancer** A full from-scratch Firedancer with no Agave code.

Both validators are built from this codebase.

## Developing
Firedancer currently only supports Linux and requires a relatively new
kernel, at least v4.18 to build.

```console
$ git clone https://github.com/firedancer-io/firedancer.git
$ cd firedancer
$ ./deps.sh                        # install system dependencies
$ make -j                          # build `firedancer-dev`
$ ./build/firedancer-dev --testnet # join testnet
```

`firedancer-dev` (without args) configures your system for validator
operation and creates a new local development cluster. First it creates
a genesis block, some keys, a faucet, and then it starts a validator on
the local machine. `firedancer-dev` will use `sudo` to make privileged
changes to system configuration where needed. If `sudo` is not available,
you may need to run the command as root.

If you wish to join this cluster with other validators, you can define
`[gossip.entrypoints]` in the configuration file to point at your first
validator and join with `firedancer-dev run`.

## License
Firedancer is available under the [Apache 2
license](https://www.apache.org/licenses/LICENSE-2.0). Firedancer also
includes external libraries that are available under a variety of
licenses. See [LICENSE](LICENSE) for the full license text.
