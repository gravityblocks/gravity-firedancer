//! Golden vectors for the gravity relay <-> connector wire protocol.
//!
//! Every byte string here is produced by the real `gravity-types` crate at the
//! revision the relay is built with (git tag v0.4.1 = b35d905), with flux
//! (49cb677) and wincode (0.6.1) pinned to match (see Cargo.lock).
//!
//! Outputs (next to Cargo.toml):
//!   vectors.txt      line-oriented, TAB-separated records (see header)
//!   vectors_gen.h    the same records as C arrays (fd_util types)
//!
//! It also runs a loopback self-test of flux-network's TCP framing (the code
//! the relay listens with) against a raw std socket, i.e. what a C client does.

use std::{
    fmt::Write as _,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream},
    time::{Duration as StdDuration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};

use flux::{
    timing::Nanos,
    utils::{ArrayStr, ArrayVec},
};
use flux_network::{Network, NetworkEvent, TcpGroupConfig};
use gravity_types::{
    BundleId, ExecutionResult, MiniBlockUuid, NextLeaderRange, NotIncludedReason, SigPrefix,
    SlotProgress,
    ffi_safety::FfiOption,
    wire::{
        BOOTSTRAP_MAGIC, BatchExecutionResult, BatchOrders, BootstrapFrame,
        BuilderOriginatedOrders, ClientHello, ConnectorToRelay, CsrNode, Handshake, HandshakeV2,
        NodeOrderRef, RejectReason, RelayToConnector, ServerHello, WireMiniBlockGraph,
        WireSharableBundle, WireSharableTx, WireStats, decode_bootstrap_frame,
        encode_bootstrap_frame, sign_auth_proof, verify_auth_proof,
    },
};
use serde_json::{Value, json};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::{
    Hash, Message as LegacyMessage, MessageHeader, VersionedMessage,
    compiled_instruction::CompiledInstruction, v0, v1,
};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

/// Fixed flux frame `send_ts` used in every FRAME vector: 2025-10-26T00:00:00Z.
const SEND_TS: u64 = 1_761_436_800_000_000_000;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        write!(s, "{x:02x}").unwrap();
    }
    s
}

/// flux-network `Framing::LengthPrefixed`: u32 LE payload len, u64 LE send_ts.
fn frame(payload: &[u8], ts: u64) -> Vec<u8> {
    let mut f = Vec::with_capacity(12 + payload.len());
    f.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    f.extend_from_slice(&ts.to_le_bytes());
    f.extend_from_slice(payload);
    f
}

fn addr(b: u8) -> Address {
    Address::new_from_array([b; 32])
}

fn mb_uuid(b: [u8; 16]) -> MiniBlockUuid {
    wincode::deserialize::<MiniBlockUuid>(&b).unwrap()
}

fn sp(b: u8) -> SigPrefix {
    SigPrefix([b; 16])
}

fn astr<const N: usize>(s: &str) -> ArrayStr<N> {
    ArrayStr::<N>::try_from(s).unwrap()
}

fn reason_name(r: NotIncludedReason) -> String {
    format!("{r:?}")
}

fn exec_json(r: &ExecutionResult) -> Value {
    match r {
        ExecutionResult::Included { execution_slot, cost_units } => {
            json!({"Included": {"execution_slot": execution_slot, "cost_units": cost_units}})
        }
        ExecutionResult::NotIncluded(reason) => json!({"NotIncluded": reason_name(*reason)}),
    }
}

fn orders_json(o: &BatchOrders) -> Value {
    match o {
        BatchOrders::Transactions { txs } => {
            json!({"Transactions": txs.iter().map(|s| hex(&s.0)).collect::<Vec<_>>()})
        }
        BatchOrders::Bundle { id } => json!({"Bundle": hex(&id.0)}),
    }
}

fn node_ref_json(r: &NodeOrderRef) -> Value {
    match r {
        NodeOrderRef::Tx { sig } => json!({"Tx": hex(&sig.0)}),
        NodeOrderRef::Bundle { id } => json!({"Bundle": hex(&id.0)}),
    }
}

fn ffi_u64(o: FfiOption<u64>) -> Value {
    Option::<u64>::from(o).map_or(Value::Null, |v| json!(v))
}

// ---------------------------------------------------------------------------
// output records
// ---------------------------------------------------------------------------

struct Rec {
    kind: &'static str,
    name: String,
    bytes: Vec<u8>,
    framed: bool,
    desc: Value,
}

#[derive(Default)]
struct Out {
    recs: Vec<Rec>,
}

impl Out {
    fn push(&mut self, kind: &'static str, name: &str, bytes: Vec<u8>, framed: bool, desc: Value) {
        assert!(
            !self.recs.iter().any(|r| r.name == name),
            "duplicate vector name {name}"
        );
        self.recs.push(Rec { kind, name: name.to_string(), bytes, framed, desc });
    }

    fn boot(&mut self, name: &str, f: &BootstrapFrame, desc: Value) {
        let bytes = encode_bootstrap_frame(f);
        assert_eq!(decode_bootstrap_frame(&bytes).as_ref(), Ok(f), "{name} roundtrip");
        self.push("BOOT", name, bytes, true, desc);
    }

    fn c2r(&mut self, name: &str, m: &ConnectorToRelay<'_>, desc: Value) -> Vec<u8> {
        let bytes = wincode::serialize(m).unwrap();
        let back: ConnectorToRelay = wincode::deserialize(&bytes).expect("c2r decodes");
        assert_eq!(wincode::serialize(&back).unwrap(), bytes, "{name} roundtrip");
        // what the relay additionally requires of a session frame: it
        // must not look like a bootstrap frame
        assert!(!gravity_types::wire::is_bootstrap_frame(&bytes));
        self.push("C2R", name, bytes.clone(), true, desc);
        bytes
    }

    fn r2c(&mut self, name: &str, m: &RelayToConnector<'_>, desc: Value) -> Vec<u8> {
        let bytes = wincode::serialize(m).unwrap();
        let back: RelayToConnector = wincode::deserialize(&bytes).expect("r2c decodes");
        assert_eq!(wincode::serialize(&back).unwrap(), bytes, "{name} roundtrip");
        self.push("R2C", name, bytes.clone(), true, desc);
        bytes
    }

    fn write_txt(&self, path: &str) {
        let mut s = String::new();
        s.push_str(HEADER);
        for r in &self.recs {
            let frame_hex = if r.framed { hex(&frame(&r.bytes, SEND_TS)) } else { "-".into() };
            writeln!(
                s,
                "{}\t{}\t{}\t{}\t{}\t{}",
                r.kind,
                r.name,
                r.bytes.len(),
                if r.bytes.is_empty() { "-".to_string() } else { hex(&r.bytes) },
                frame_hex,
                serde_json::to_string(&r.desc).unwrap()
            )
            .unwrap();
        }
        std::fs::write(path, s).unwrap();
    }

    fn write_h(&self, path: &str) {
        let mut s = String::new();
        s.push_str(
            "/* Generated by contrib/gravity-wire-vectors (see its README). Do not edit.\n   \
             Source of truth: gravity-types v0.4.1 (b35d905), flux 49cb677, wincode 0.6.1.\n   \
             frame = u32 LE payload_sz | u64 LE send_ts | payload, send_ts = ",
        );
        writeln!(s, "{SEND_TS}UL. */\n").unwrap();
        s.push_str("#ifndef HEADER_fd_src_disco_pack_gravity_fixtures_test_gravity_wire_vectors_h\n#define HEADER_fd_src_disco_pack_gravity_fixtures_test_gravity_wire_vectors_h\n\n");
        writeln!(s, "#define GRAVITY_WIRE_VEC_SEND_TS ({SEND_TS}UL)\n").unwrap();
        s.push_str(
            "struct gravity_wire_vec {\n  char const *  kind;   /* BOOT C2R R2C RAW NEG REASON SIGPREFIX ADDR */\n  \
             char const *  name;\n  uchar const * payload;\n  ulong         payload_sz;\n  \
             uchar const * frame;  /* NULL if not a frame */\n  ulong         frame_sz;\n  char const *  json;\n};\n\n",
        );
        let c_bytes = |b: &[u8]| -> String {
            if b.is_empty() {
                return "{ 0 }".into();
            }
            let mut o = String::from("{");
            for (i, x) in b.iter().enumerate() {
                if i % 16 == 0 {
                    o.push_str("\n  ");
                }
                write!(o, "0x{x:02x},").unwrap();
            }
            o.push_str("\n}");
            o
        };
        for (i, r) in self.recs.iter().enumerate() {
            writeln!(s, "static uchar const gwv_p{i}[] = {}; /* {} */", c_bytes(&r.bytes), r.name)
                .unwrap();
            if r.framed {
                writeln!(s, "static uchar const gwv_f{i}[] = {};", c_bytes(&frame(&r.bytes, SEND_TS)))
                    .unwrap();
            }
        }
        s.push_str("\nstatic struct gravity_wire_vec const gravity_wire_vecs[] = {\n");
        for (i, r) in self.recs.iter().enumerate() {
            let js = serde_json::to_string(&r.desc).unwrap().replace('\\', "\\\\").replace('"', "\\\"");
            let (f, fsz) = if r.framed {
                (format!("gwv_f{i}"), format!("{}UL", r.bytes.len() + 12))
            } else {
                ("NULL".into(), "0UL".into())
            };
            writeln!(
                s,
                "  {{ \"{}\", \"{}\", gwv_p{i}, {}UL, {f}, {fsz}, \"{js}\" }},",
                r.kind,
                r.name,
                r.bytes.len()
            )
            .unwrap();
        }
        s.push_str("};\n\n#define GRAVITY_WIRE_VEC_CNT (sizeof(gravity_wire_vecs)/sizeof(gravity_wire_vecs[0]))\n\n#endif\n");
        std::fs::write(path, s).unwrap();
    }
}

const HEADER: &str = "\
# Gravity relay <-> connector wire golden vectors.
# Generated by contrib/gravity-wire-vectors/src/main.rs, compiled against the exact
# crates the relay is built with: gravity-types git tag v0.4.1 (b35d90566cdffa272cff059fb7cd7b01109e3031),
# flux 49cb677158a30e20a70d2e1391abbed453bbb68d, wincode 0.6.1 / wincode-derive 0.5.1.
#
# One record per line, 6 TAB-separated fields:
#   kind  name  payload_len  payload_hex  frame_hex  json
# kind:
#   BOOT       bootstrap payload: \"SOLGTC01\" || wincode(BootstrapFrame)
#   C2R        wincode(ConnectorToRelay) session payload
#   R2C        wincode(RelayToConnector) session payload
#   RAW        raw bytes that are not a frame (auth message, keys, signature, tx bytes)
#   NEG        bytes the Rust decoder named in json.decoder REJECTS (json.rust_result)
#              or, if json.rust_result == \"accepted\", accepts (documented quirks)
#   REASON     wire encoding (u32 LE variant index) of one NotIncludedReason
#   SIGPREFIX  payload_hex = serialized transaction, json.sig_prefix = expected 16-byte prefix or null
#   ADDR       wincode(std::net::SocketAddr)
# payload_hex is \"-\" for an empty payload. frame_hex is the complete flux TCP frame
#   (u32 LE payload_len | u64 LE send_ts | payload) with send_ts = 1761436800000000000
#   (= 0x1871e16fe64d0000, LE bytes 00004de66fe17118), or \"-\" when the bytes are not framed.
# json: field values (byte strings as lowercase hex, integers as numbers).
";

// ---------------------------------------------------------------------------
// transactions
// ---------------------------------------------------------------------------

struct Txs {
    legacy: Vec<u8>,
    legacy2: Vec<u8>,
    v0: Vec<u8>,
    v1: Vec<u8>,
    v1_2: Vec<u8>,
    legacy_sig0: [u8; 64],
    legacy2_sig0: [u8; 64],
    v0_sig0: [u8; 64],
    v1_sig0: [u8; 64],
    v1_2_sig0: [u8; 64],
}

fn transfer_ix() -> CompiledInstruction {
    // system program transfer of 1_000_000 lamports: accounts [payer, recipient]
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    CompiledInstruction { program_id_index: 2, accounts: vec![0, 1], data }
}

fn build_txs(payer: &Keypair, second: &Keypair) -> Txs {
    let blockhash = || Hash::new_from_array([0x42; 32]);
    let recipient = addr(0x33);
    let system = Address::new_from_array([0; 32]);
    let header1 = MessageHeader {
        num_required_signatures: 1,
        num_readonly_signed_accounts: 0,
        num_readonly_unsigned_accounts: 1,
    };
    let ser = |tx: &VersionedTransaction| -> (Vec<u8>, [u8; 64]) {
        let b = wincode::serialize(tx).unwrap();
        let back: VersionedTransaction = wincode::deserialize(&b).unwrap();
        assert_eq!(&back, tx);
        (b, *tx.signatures[0].as_array())
    };

    let legacy = VersionedTransaction::try_new(
        VersionedMessage::Legacy(LegacyMessage {
            header: header1,
            account_keys: vec![payer.pubkey(), recipient, system],
            recent_blockhash: blockhash(),
            instructions: vec![transfer_ix()],
        }),
        &[payer],
    )
    .unwrap();
    // two signers: fee payer first; prefix must come from signature 0
    let legacy2 = VersionedTransaction::try_new(
        VersionedMessage::Legacy(LegacyMessage {
            header: MessageHeader {
                num_required_signatures: 2,
                num_readonly_signed_accounts: 1,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![payer.pubkey(), second.pubkey(), system],
            recent_blockhash: blockhash(),
            instructions: vec![CompiledInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: transfer_ix().data,
            }],
        }),
        &[payer, second],
    )
    .unwrap();
    let v0tx = VersionedTransaction::try_new(
        VersionedMessage::V0(v0::Message {
            header: header1,
            account_keys: vec![payer.pubkey(), recipient, system],
            recent_blockhash: blockhash(),
            instructions: vec![transfer_ix()],
            address_table_lookups: vec![],
        }),
        &[payer],
    )
    .unwrap();
    let v1tx = VersionedTransaction::try_new(
        VersionedMessage::V1(v1::Message {
            header: header1,
            config: v1::TransactionConfig::empty(),
            lifetime_specifier: blockhash(),
            account_keys: vec![payer.pubkey(), recipient, system],
            instructions: vec![transfer_ix()],
        }),
        &[payer],
    )
    .unwrap();
    let v1tx2 = VersionedTransaction::try_new(
        VersionedMessage::V1(v1::Message {
            header: MessageHeader {
                num_required_signatures: 2,
                num_readonly_signed_accounts: 1,
                num_readonly_unsigned_accounts: 1,
            },
            config: v1::TransactionConfig::empty(),
            lifetime_specifier: blockhash(),
            account_keys: vec![payer.pubkey(), second.pubkey(), system],
            instructions: vec![transfer_ix()],
        }),
        &[payer, second],
    )
    .unwrap();
    let (legacy, legacy_sig0) = ser(&legacy);
    let (legacy2, legacy2_sig0) = ser(&legacy2);
    let (v0, v0_sig0) = ser(&v0tx);
    let (v1, v1_sig0) = ser(&v1tx);
    let (v1_2, v1_2_sig0) = ser(&v1tx2);
    assert_eq!(v1[0], 0x81);
    Txs { legacy, legacy2, v0, v1, v1_2, legacy_sig0, legacy2_sig0, v0_sig0, v1_sig0, v1_2_sig0 }
}

// ---------------------------------------------------------------------------
// vector groups
// ---------------------------------------------------------------------------

fn auth_message(identity: &Address, challenge: &[u8; 32]) -> Vec<u8> {
    // mirrors gravity-types wire/bootstrap.rs auth_message (private)
    let mut m = Vec::with_capacity(72);
    m.extend_from_slice(&BOOTSTRAP_MAGIC);
    m.extend_from_slice(identity.as_array());
    m.extend_from_slice(challenge);
    m
}

fn bootstrap(o: &mut Out, kp: &Keypair, rfc: &Keypair) {
    let identity = kp.pubkey();
    let mut challenge = [0u8; 32];
    for (i, c) in challenge.iter_mut().enumerate() {
        *c = i as u8;
    }

    o.push(
        "RAW",
        "test_keypair_seed",
        kp.secret_bytes().to_vec(),
        false,
        json!({"what": "ed25519 32-byte secret seed of the test identity (all 0x07)",
               "pubkey_hex": hex(identity.as_array()), "pubkey_b58": identity.to_string()}),
    );
    o.boot(
        "boot_client_hello",
        &BootstrapFrame::ClientHello(ClientHello { identity }),
        json!({"frame": "ClientHello", "tag": 0, "identity": hex(identity.as_array())}),
    );
    o.boot(
        "boot_server_hello",
        &BootstrapFrame::ServerHello(ServerHello { challenge }),
        json!({"frame": "ServerHello", "tag": 1, "challenge": hex(&challenge)}),
    );

    let msg = auth_message(&identity, &challenge);
    let proof = sign_auth_proof(kp, &challenge);
    // cross-check: the proof is a plain ed25519 signature over the 72-byte message
    assert_eq!(proof.signature, *kp.sign_message(&msg).as_array());
    assert!(verify_auth_proof(&identity, &proof, &challenge));
    let mut bad = challenge;
    bad[0] ^= 1;
    assert!(!verify_auth_proof(&identity, &proof, &bad));
    o.push(
        "RAW",
        "auth_message",
        msg.clone(),
        false,
        json!({"what": "bytes signed for AuthProof = \"SOLGTC01\" || identity[32] || challenge[32] (72 B, signed raw, no prehash)",
               "identity": hex(identity.as_array()), "challenge": hex(&challenge)}),
    );
    o.push(
        "RAW",
        "auth_signature",
        proof.signature.to_vec(),
        false,
        json!({"what": "ed25519(seed=07*32) signature over auth_message (deterministic RFC 8032)"}),
    );
    o.boot(
        "boot_auth_proof",
        &BootstrapFrame::AuthProof(proof),
        json!({"frame": "AuthProof", "tag": 2, "signature": hex(&proof.signature)}),
    );

    // RFC 8032 section 7.1 TEST 1 key, so a C test can cross-check with fd_ed25519
    let rid = rfc.pubkey();
    assert_eq!(
        hex(rid.as_array()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let rchallenge = [0xaau8; 32];
    let rmsg = auth_message(&rid, &rchallenge);
    let rproof = sign_auth_proof(rfc, &rchallenge);
    assert!(verify_auth_proof(&rid, &rproof, &rchallenge));
    o.push(
        "RAW",
        "rfc8032_auth_message",
        rmsg,
        false,
        json!({"what": "auth message for RFC 8032 TEST 1 key",
               "secret_seed": hex(rfc.secret_bytes()), "identity": hex(rid.as_array()),
               "challenge": hex(&rchallenge)}),
    );
    o.push(
        "RAW",
        "rfc8032_auth_signature",
        rproof.signature.to_vec(),
        false,
        json!({"what": "signature over rfc8032_auth_message"}),
    );
    o.boot(
        "boot_rfc8032_client_hello",
        &BootstrapFrame::ClientHello(ClientHello { identity: rid }),
        json!({"frame": "ClientHello", "tag": 0, "identity": hex(rid.as_array())}),
    );
    o.boot(
        "boot_rfc8032_auth_proof",
        &BootstrapFrame::AuthProof(rproof),
        json!({"frame": "AuthProof", "tag": 2, "signature": hex(&rproof.signature)}),
    );

    o.boot("boot_accepted", &BootstrapFrame::Accepted, json!({"frame": "Accepted", "tag": 3}));
    for (i, (r, n)) in [
        (RejectReason::InvalidHello, "InvalidHello"),
        (RejectReason::UnknownIdentity, "UnknownIdentity"),
        (RejectReason::InvalidProof, "InvalidProof"),
        (RejectReason::Timeout, "Timeout"),
    ]
    .into_iter()
    .enumerate()
    {
        o.boot(
            &format!("boot_rejected_{}", n.to_lowercase()),
            &BootstrapFrame::Rejected { reason: r },
            json!({"frame": "Rejected", "tag": 4, "reason": n, "reason_tag": i}),
        );
    }
}

fn handshakes(o: &mut Out, identity: Address) {
    let h = HandshakeV2 {
        identity,
        conn_version: "fd-gravity/0.1.0".into(),
        num_threads: 4,
        filter_ofac: false,
        blacklisted_accounts: vec![],
        jito_tip_weight_bps: 10_000,
    };
    o.c2r(
        "c2r_handshake_v2_basic",
        &ConnectorToRelay::HandshakeV2(h.clone()),
        json!({"msg": "HandshakeV2", "tag": 10, "identity": hex(identity.as_array()),
               "conn_version": "fd-gravity/0.1.0", "num_threads": 4, "filter_ofac": false,
               "blacklisted_accounts": [], "jito_tip_weight_bps": 10000}),
    );
    let h2 = HandshakeV2 {
        conn_version: String::new(),
        num_threads: 1,
        filter_ofac: true,
        blacklisted_accounts: vec![[0x0b; 32], [0xbb; 32]],
        jito_tip_weight_bps: 0,
        ..h.clone()
    };
    o.c2r(
        "c2r_handshake_v2_blacklist",
        &ConnectorToRelay::HandshakeV2(h2),
        json!({"msg": "HandshakeV2", "tag": 10, "identity": hex(identity.as_array()),
               "conn_version": "", "num_threads": 1, "filter_ofac": true,
               "blacklisted_accounts": [hex(&[0x0b; 32]), hex(&[0xbb; 32])],
               "jito_tip_weight_bps": 0}),
    );
    let h3 = HandshakeV2 { num_threads: 255, jito_tip_weight_bps: 5_000, ..h };
    o.c2r(
        "c2r_handshake_v2_maxthreads",
        &ConnectorToRelay::HandshakeV2(h3),
        json!({"msg": "HandshakeV2", "tag": 10, "identity": hex(identity.as_array()),
               "conn_version": "fd-gravity/0.1.0", "num_threads": 255, "filter_ofac": false,
               "blacklisted_accounts": [], "jito_tip_weight_bps": 5000}),
    );
    o.c2r(
        "c2r_handshake_v1_legacy",
        &ConnectorToRelay::Handshake(Handshake {
            identity,
            conn_version: "fd".into(),
            num_threads: 1,
            filter_ofac: true,
        }),
        json!({"msg": "Handshake (legacy v1; relay upgrades to V2 with empty blacklist, jito 10000)",
               "tag": 0, "identity": hex(identity.as_array()), "conn_version": "fd",
               "num_threads": 1, "filter_ofac": true}),
    );
    o.c2r("c2r_join_session", &ConnectorToRelay::JoinSession, json!({"msg": "JoinSession", "tag": 12}));
}

fn progress(o: &mut Out) {
    let p = |slot: u64, obs: u64, pct: u8, ovr: Option<u64>, nl: Option<(u64, u64)>, bh: Option<[u8; 32]>| {
        SlotProgress {
            slot_num: slot,
            observed_at: Nanos(obs),
            current_slot_progress: pct,
            slot_duration_override_ms: ovr.into(),
            next_leadership: nl.map(|(start, end)| NextLeaderRange { start, end }).into(),
            latest_blockhash: bh.into(),
        }
    };
    let cases = [
        ("c2r_progress_all_none", p(101, 1_761_436_800_123_456_789, 0, None, None, None)),
        (
            "c2r_progress_all_some",
            p(100, 1_761_436_800_000_000_000, 37, Some(400), Some((100, 103)), Some([0xcc; 32])),
        ),
        (
            "c2r_progress_leader_no_override",
            p(4_000, 1_761_436_801_600_000_000, 2, None, Some((4_000, 4_003)), Some([0x5a; 32])),
        ),
        (
            "c2r_progress_max",
            p(u64::MAX, u64::MAX, 100, Some(u64::MAX), Some((u64::MAX - 3, u64::MAX)), Some([0xff; 32])),
        ),
    ];
    for (name, sp) in cases {
        let bh: Option<[u8; 32]> = sp.latest_blockhash.into();
        let nl: Option<NextLeaderRange> = sp.next_leadership.into();
        o.c2r(
            name,
            &ConnectorToRelay::Progress(sp),
            json!({"msg": "Progress", "tag": 9, "slot_num": sp.slot_num,
                   "observed_at": sp.observed_at.0, "current_slot_progress": sp.current_slot_progress,
                   "slot_duration_override_ms": ffi_u64(sp.slot_duration_override_ms),
                   "next_leadership": nl.map(|n| json!({"start": n.start, "end": n.end})),
                   "latest_blockhash": bh.map(|b| hex(&b))}),
        );
    }
}

fn simple(o: &mut Out) {
    for (name, v) in [("c2r_pong_0", 0u64), ("c2r_pong_7", 7), ("c2r_pong_max", u64::MAX)] {
        o.c2r(name, &ConnectorToRelay::Pong(v), json!({"msg": "Pong", "tag": 8, "seq": v}));
    }
    o.c2r(
        "c2r_ready_for_tips",
        &ConnectorToRelay::ReadyForTips(4_000),
        json!({"msg": "ReadyForTips (ignored by relay)", "tag": 4, "slot": 4000}),
    );
    o.c2r(
        "c2r_stats_empty",
        &ConnectorToRelay::Stats(WireStats::default()),
        json!({"msg": "Stats", "tag": 13, "stats": []}),
    );
    o.c2r(
        "c2r_stats_two",
        &ConnectorToRelay::Stats(WireStats::new([("txs_fwd", 12u64), ("graphs", 3)])),
        json!({"msg": "Stats", "tag": 13, "stats": [{"name": "txs_fwd", "value": 12}, {"name": "graphs", "value": 3}]}),
    );

    for (name, v) in [("r2c_ping_0", 0u64), ("r2c_ping_seq", 0x0102_0304_0506_0708), ("r2c_ping_max", u64::MAX)] {
        o.r2c(name, &RelayToConnector::Ping(v), json!({"msg": "Ping", "tag": 4, "seq": v}));
    }
    o.r2c("r2c_delete_failsafe", &RelayToConnector::DeleteFailsafe, json!({"msg": "DeleteFailsafe", "tag": 1}));
    o.r2c(
        "r2c_previous_tip_receiver",
        &RelayToConnector::PreviousTipReceiver { slot: 4_000, tip_receiver: addr(0x71), block_builder: addr(0x72) },
        json!({"msg": "PreviousTipReceiver", "tag": 2, "slot": 4000,
               "tip_receiver": hex(&[0x71; 32]), "block_builder": hex(&[0x72; 32])}),
    );
    let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 7), 8001));
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0xabcd, 0, 0));
    o.r2c(
        "r2c_shred_receivers_empty",
        &RelayToConnector::ShredReceiverAddresses(vec![]),
        json!({"msg": "ShredReceiverAddresses", "tag": 3, "addrs": []}),
    );
    o.r2c(
        "r2c_shred_receivers_v4_v6",
        &RelayToConnector::ShredReceiverAddresses(vec![v4, v6]),
        json!({"msg": "ShredReceiverAddresses", "tag": 3, "addrs": ["10.0.0.7:8001", "[::1]:43981"]}),
    );
    o.r2c(
        "r2c_shred_retransmit_receivers_v4",
        &RelayToConnector::ShredRetransmitReceiverAddresses(vec![v4]),
        json!({"msg": "ShredRetransmitReceiverAddresses", "tag": 5, "addrs": ["10.0.0.7:8001"]}),
    );
    for (name, a, s) in [("addr_v4", v4, "10.0.0.7:8001"), ("addr_v6", v6, "[::1]:43981")] {
        o.push("ADDR", name, wincode::serialize(&a).unwrap(), false, json!({"addr": s}));
    }
}

fn orders(o: &mut Out, t: &Txs) {
    let src_v4 = Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped().octets();
    o.c2r(
        "c2r_transaction_tpu",
        &ConnectorToRelay::Transaction {
            order: WireSharableTx { tx_bytes: &t.legacy },
            sent_at: Nanos(1_761_436_800_000_500_000),
            received_at: Nanos(1_761_436_800_000_400_000),
            src_addr: src_v4,
            source_uri: None,
        },
        json!({"msg": "Transaction", "tag": 1, "tx": hex(&t.legacy), "tx_kind": "legacy",
               "sent_at": 1_761_436_800_000_500_000u64, "received_at": 1_761_436_800_000_400_000u64,
               "src_addr": hex(&src_v4), "src_addr_text": "::ffff:10.0.0.1", "source_uri": null}),
    );
    let uri = "https://mainnet.block-engine.jito.wtf";
    o.c2r(
        "c2r_transaction_block_engine_v0",
        &ConnectorToRelay::Transaction {
            order: WireSharableTx { tx_bytes: &t.v0 },
            sent_at: Nanos(2),
            received_at: Nanos(1),
            src_addr: [0; 16],
            source_uri: Some(astr::<64>(uri)),
        },
        json!({"msg": "Transaction", "tag": 1, "tx": hex(&t.v0), "tx_kind": "v0",
               "sent_at": 2, "received_at": 1, "src_addr": hex(&[0; 16]), "source_uri": uri}),
    );
    let uri64 = "u".repeat(64);
    o.c2r(
        "c2r_transaction_v1_uri64",
        &ConnectorToRelay::Transaction {
            order: WireSharableTx { tx_bytes: &t.v1 },
            sent_at: Nanos(u64::MAX),
            received_at: Nanos(0),
            src_addr: [0xfe; 16],
            source_uri: Some(astr::<64>(&uri64)),
        },
        json!({"msg": "Transaction", "tag": 1, "tx": hex(&t.v1), "tx_kind": "v1",
               "sent_at": u64::MAX, "received_at": 0, "src_addr": hex(&[0xfe; 16]),
               "source_uri": uri64, "note": "source_uri at its 64-byte maximum"}),
    );

    let mut b1 = ArrayVec::new();
    b1.push(WireSharableTx { tx_bytes: &t.legacy });
    let bundle1 = WireSharableBundle { ext_uuid: BundleId([0xb0; 32]), txs: b1 };
    o.c2r(
        "c2r_bundle_v2_one_tx",
        &ConnectorToRelay::BundleV2 {
            bundle: bundle1,
            source_uri: astr::<64>(uri),
            received_at: Nanos(1_761_436_800_000_400_000),
            sent_at: Nanos(1_761_436_800_000_500_000),
        },
        json!({"msg": "BundleV2", "tag": 11, "ext_uuid": hex(&[0xb0; 32]), "txs": [hex(&t.legacy)],
               "source_uri": uri, "received_at": 1_761_436_800_000_400_000u64,
               "sent_at": 1_761_436_800_000_500_000u64}),
    );
    let all = [&t.legacy, &t.v0, &t.v1, &t.legacy2, &t.v1_2];
    let mut b5 = ArrayVec::new();
    for tx in all {
        b5.push(WireSharableTx { tx_bytes: tx });
    }
    let bundle5 = WireSharableBundle { ext_uuid: BundleId([0xff; 32]), txs: b5 };
    o.c2r(
        "c2r_bundle_v2_five_txs_empty_uri",
        &ConnectorToRelay::BundleV2 { bundle: bundle5, source_uri: astr::<64>(""), received_at: Nanos(0), sent_at: Nanos(0) },
        json!({"msg": "BundleV2", "tag": 11, "ext_uuid": hex(&[0xff; 32]),
               "txs": all.iter().map(|x| hex(x)).collect::<Vec<_>>(),
               "source_uri": "", "received_at": 0, "sent_at": 0,
               "note": "5 txs = MAX_TXS_PER_BUNDLE"}),
    );
    o.c2r(
        "c2r_bundle_v1_legacy",
        &ConnectorToRelay::Bundle { bundle: bundle1, source_uri: astr::<64>("be"), received_at: Nanos(3) },
        json!({"msg": "Bundle (v1, prefer BundleV2)", "tag": 6, "ext_uuid": hex(&[0xb0; 32]),
               "txs": [hex(&t.legacy)], "source_uri": "be", "received_at": 3}),
    );
    o.c2r(
        "c2r_crank_bundle",
        &ConnectorToRelay::CrankBundle(bundle1),
        json!({"msg": "CrankBundle (ignored by relay)", "tag": 5, "ext_uuid": hex(&[0xb0; 32]),
               "txs": [hex(&t.legacy)]}),
    );
}

fn exec_results(o: &mut Out) {
    let uuid = [0x22u8; 16];
    let mut add = |name: &str, r: BatchExecutionResult, note: &str| {
        o.c2r(
            name,
            &ConnectorToRelay::ExecutionResult(r),
            json!({"msg": "ExecutionResult", "tag": 3, "slot": r.slot, "mini_block_uuid": hex(&uuid),
                   "orders": orders_json(&r.orders),
                   "results": r.results.iter().map(exec_json).collect::<Vec<_>>(),
                   "batch_received_at": r.batch_received_at.0, "forwarded_at": r.forwarded_at.0,
                   "res_received_at": r.res_received_at.0, "worker": r.worker, "note": note}),
        );
    };
    let base = |orders: BatchOrders, results: &[ExecutionResult]| {
        let mut rs = ArrayVec::new();
        for r in results {
            rs.push(*r);
        }
        BatchExecutionResult {
            slot: 4_000,
            mini_block_uuid: mb_uuid(uuid),
            orders,
            results: rs,
            batch_received_at: Nanos(5),
            forwarded_at: Nanos(6),
            res_received_at: Nanos(7),
            worker: 0,
        }
    };
    let one = |s: SigPrefix| {
        let mut v = ArrayVec::new();
        v.push(s);
        BatchOrders::Transactions { txs: v }
    };
    let inc = ExecutionResult::Included { execution_slot: 4_000, cost_units: 1_500 };
    let ni = ExecutionResult::NotIncluded;

    add("c2r_exec_tx_included", base(one(sp(0x51)), &[inc]), "one loose tx landed");
    add(
        "c2r_exec_tx_instruction_error",
        base(one(sp(0x52)), &[ni(NotIncludedReason::INSTRUCTION_ERROR)]),
        "one loose tx not included",
    );
    add(
        "c2r_exec_bundle_ok",
        base(BatchOrders::Bundle { id: BundleId([0xb0; 32]) }, &[inc, inc, inc]),
        "3-tx bundle, all included: one result per bundle tx in bundle order",
    );
    add(
        "c2r_exec_bundle_failed_mid",
        base(
            BatchOrders::Bundle { id: BundleId([0xb1; 32]) },
            &[
                ni(NotIncludedReason::ALL_OR_NOTHING_BATCH_FAILURE),
                ni(NotIncludedReason::INSUFFICIENT_FUNDS_FOR_FEE),
                ni(NotIncludedReason::ALL_OR_NOTHING_BATCH_FAILURE),
            ],
        ),
        "3-tx bundle, tx 1 failed: real reason at the failing index, ALL_OR_NOTHING_BATCH_FAILURE elsewhere",
    );
    // synthetic rejects exactly as the Rust connector builds them
    // (gravity-types wire/mod.rs reject_orders: worker=255, forwarded_at=res_received_at=0)
    add(
        "c2r_exec_reject_unknown_orders_tx",
        BatchExecutionResult::reject_orders(4_000, mb_uuid(uuid), one(sp(0x53)), 1, Nanos(9), NotIncludedReason::UNKNOWN_ORDERS),
        "BatchExecutionResult::reject_orders(.., 1, UNKNOWN_ORDERS): node not resolvable",
    );
    add(
        "c2r_exec_reject_slot_ended_bundle",
        BatchExecutionResult::reject_orders(
            4_000,
            mb_uuid(uuid),
            BatchOrders::Bundle { id: BundleId([0xb2; 32]) },
            2,
            Nanos(9),
            NotIncludedReason::SLOT_ENDED,
        ),
        "reject_orders(bundle, 2, SLOT_ENDED): [SLOT_ENDED, ALL_OR_NOTHING_BATCH_FAILURE]",
    );
    add(
        "c2r_exec_reject_bank_not_available",
        BatchExecutionResult::reject_orders(4_000, mb_uuid(uuid), one(sp(0x54)), 1, Nanos(0), NotIncludedReason::BANK_NOT_AVAILABLE),
        "BANK_NOT_AVAILABLE: the only reason the relay itself inspects (ends an overdue tail)",
    );
    let mut sigs = ArrayVec::new();
    let mut rs = Vec::new();
    for i in 0..16u8 {
        sigs.push(SigPrefix([0x60 + i; 16]));
        rs.push(if i % 2 == 0 {
            ExecutionResult::Included { execution_slot: u64::MAX, cost_units: u64::from(i) * 1000 }
        } else {
            ni(NotIncludedReason::BLOCKHASH_NOT_FOUND)
        });
    }
    let mut max = base(BatchOrders::Transactions { txs: sigs }, &rs);
    max.worker = 31;
    max.slot = u64::MAX;
    add("c2r_exec_16_txs_max", max, "16 loose txs = MAX_TXS_PER_MESSAGE; results zip with txs");
    add(
        "c2r_exec_empty",
        base(BatchOrders::Transactions { txs: ArrayVec::new() }, &[]),
        "encoding edge case only: empty txs and results (never sent by the connector)",
    );
}

fn graphs(o: &mut Out, t: &Txs) {
    let uuid = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00];
    let pref = |b: &[u8]| SigPrefix::try_from_transaction_bytes(b).unwrap();

    let mut cases: Vec<(&str, WireMiniBlockGraph, Vec<&[u8]>, Vec<(BundleId, Vec<&[u8]>)>, &str)> = vec![];
    // 1. single builder tx
    cases.push((
        "r2c_graph_single_tx",
        WireMiniBlockGraph {
            slot: 4_000,
            index_in_slot: 0,
            uuid: mb_uuid(uuid),
            row_offsets: vec![0, 0],
            col_indices: vec![],
            nodes: vec![CsrNode { order_ref: NodeOrderRef::Tx { sig: pref(&t.legacy) }, depth: 1 }],
        },
        vec![&t.legacy],
        vec![],
        "1 node, no edges, tx bytes supplied in orders.txs",
    ));
    // 2. mixed DAG: 0:Tx(v0) 1:Bundle(2 txs) 2:Tx(v1); edges 0->2, 1->2
    let bid = BundleId([0xb3; 32]);
    cases.push((
        "r2c_graph_mixed_dag",
        WireMiniBlockGraph {
            slot: 4_001,
            index_in_slot: 3,
            uuid: mb_uuid(uuid),
            row_offsets: vec![0, 1, 2, 2],
            col_indices: vec![2, 2],
            nodes: vec![
                CsrNode { order_ref: NodeOrderRef::Tx { sig: pref(&t.v0) }, depth: 2 },
                CsrNode { order_ref: NodeOrderRef::Bundle { id: bid }, depth: 2 },
                CsrNode { order_ref: NodeOrderRef::Tx { sig: pref(&t.v1) }, depth: 1 },
            ],
        },
        vec![&t.v0, &t.v1],
        vec![(bid, vec![&t.legacy2, &t.v1_2])],
        "3 nodes [Tx v0, Bundle(2 txs), Tx v1], edges 0->2 and 1->2; all bytes supplied",
    ));
    // 3. nodes that the connector itself forwarded: no bytes in orders (empty vecs)
    cases.push((
        "r2c_graph_connector_sourced",
        WireMiniBlockGraph {
            slot: 4_002,
            index_in_slot: 7,
            uuid: mb_uuid(uuid),
            row_offsets: vec![0, 1, 1],
            col_indices: vec![1],
            nodes: vec![
                CsrNode { order_ref: NodeOrderRef::Tx { sig: pref(&t.legacy) }, depth: 2 },
                CsrNode { order_ref: NodeOrderRef::Bundle { id: BundleId([0xb0; 32]) }, depth: 1 },
            ],
        },
        vec![],
        vec![],
        "2 nodes referencing orders this connector forwarded earlier (c2r_transaction_tpu, c2r_bundle_v2_one_tx); orders.txs and orders.bundles empty: resolve from local retention cache",
    ));

    for (name, g, txs, bundles, note) in cases {
        let wire_bundles: Vec<WireSharableBundle> = bundles
            .iter()
            .map(|(id, txs)| {
                let mut v = ArrayVec::new();
                for tx in txs {
                    v.push(WireSharableTx { tx_bytes: tx });
                }
                WireSharableBundle { ext_uuid: *id, txs: v }
            })
            .collect();
        let ord = BuilderOriginatedOrders {
            txs: txs.iter().map(|tx| WireSharableTx { tx_bytes: tx }).collect(),
            bundles: wire_bundles.clone(),
        };
        // the relay writes u32 tag 0 || graph bytes || orders bytes; check
        // that equals wincode's encoding
        let mut manual = 0u32.to_le_bytes().to_vec();
        manual.extend(wincode::serialize(&g).unwrap());
        manual.extend(wincode::serialize(&ord).unwrap());
        let desc = json!({
            "msg": "MiniBlockGraph", "tag": 0, "slot": g.slot, "index_in_slot": g.index_in_slot,
            "uuid": hex(&uuid), "row_offsets": g.row_offsets, "col_indices": g.col_indices,
            "nodes": g.nodes.iter().map(|n| json!({"order_ref": node_ref_json(&n.order_ref), "depth": n.depth})).collect::<Vec<_>>(),
            "orders": {"txs": txs.iter().map(|x| hex(x)).collect::<Vec<_>>(),
                       "bundles": bundles.iter().map(|(id, txs)| json!({"ext_uuid": hex(&id.0), "txs": txs.iter().map(|x| hex(x)).collect::<Vec<_>>()})).collect::<Vec<_>>()},
            "note": note,
        });
        let bytes = o.r2c(name, &RelayToConnector::MiniBlockGraph { graph: g, orders: ord }, desc);
        assert_eq!(bytes, manual, "{name}: relay's manual writer matches wincode");
    }
}

fn reasons(o: &mut Out) {
    use NotIncludedReason as R;
    // declaration order of gravity-types src/execution_result.rs:47-169
    let all = [
        R::NONE, R::BANK_NOT_AVAILABLE, R::ALL_OR_NOTHING_BATCH_FAILURE, R::ACCOUNT_IN_USE,
        R::ACCOUNT_LOADED_TWICE, R::ACCOUNT_NOT_FOUND, R::PROGRAM_ACCOUNT_NOT_FOUND,
        R::INSUFFICIENT_FUNDS_FOR_FEE, R::INVALID_ACCOUNT_FOR_FEE, R::ALREADY_PROCESSED,
        R::BLOCKHASH_NOT_FOUND, R::INSTRUCTION_ERROR, R::CALL_CHAIN_TOO_DEEP,
        R::MISSING_SIGNATURE_FOR_FEE, R::INVALID_ACCOUNT_INDEX, R::SIGNATURE_FAILURE,
        R::INVALID_PROGRAM_FOR_EXECUTION, R::SANITIZE_FAILURE, R::CLUSTER_MAINTENANCE,
        R::ACCOUNT_BORROW_OUTSTANDING, R::WOULD_EXCEED_MAX_BLOCK_COST_LIMIT, R::UNSUPPORTED_VERSION,
        R::INVALID_WRITABLE_ACCOUNT, R::WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT,
        R::WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT, R::TOO_MANY_ACCOUNT_LOCKS,
        R::ADDRESS_LOOKUP_TABLE_NOT_FOUND, R::INVALID_ADDRESS_LOOKUP_TABLE_OWNER,
        R::INVALID_ADDRESS_LOOKUP_TABLE_DATA, R::INVALID_ADDRESS_LOOKUP_TABLE_INDEX,
        R::INVALID_RENT_PAYING_ACCOUNT, R::WOULD_EXCEED_MAX_VOTE_COST_LIMIT,
        R::WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT, R::DUPLICATE_INSTRUCTION,
        R::INSUFFICIENT_FUNDS_FOR_RENT, R::MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED,
        R::INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT, R::RESANITIZATION_NEEDED,
        R::PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED, R::UNBALANCED_TRANSACTION,
        R::PROGRAM_CACHE_HIT_MAX_LIMIT, R::MAX_WORKING_SLOT_EXCEEDED, R::NOT_SEQUENCING,
        R::UNKNOWN_ORDERS, R::SLOT_ENDED,
    ];
    for (idx, r) in all.into_iter().enumerate() {
        let b = wincode::serialize(&r).unwrap();
        assert_eq!(b, (idx as u32).to_le_bytes(), "{r:?} is index-encoded");
        let back: R = wincode::deserialize(&b).unwrap();
        assert_eq!(back, r);
        o.push(
            "REASON",
            &format!("reason_{}", reason_name(r).to_lowercase()),
            b,
            false,
            json!({"name": reason_name(r), "wire_tag": idx, "repr_u8": r as u8}),
        );
    }
    let past = (all.len() as u32).to_le_bytes();
    assert!(wincode::deserialize::<R>(&past).is_err(), "no variant past SLOT_ENDED");
}

fn sig_prefixes(o: &mut Out, t: &Txs) {
    let cases: [(&str, &[u8], Option<[u8; 64]>, &str); 5] = [
        ("sigprefix_legacy", &t.legacy, Some(t.legacy_sig0), "legacy: b[0]=1 sig count, prefix = b[1..17]"),
        ("sigprefix_legacy_2sig", &t.legacy2, Some(t.legacy2_sig0), "legacy, 2 signatures: prefix of signature 0 = b[1..17]"),
        ("sigprefix_v0", &t.v0, Some(t.v0_sig0), "v0: b[0]=1 sig count, prefix = b[1..17]"),
        ("sigprefix_v1", &t.v1, Some(t.v1_sig0), "v1: b[0]=0x81, b[1]=nsig=1, sigs at end: prefix = b[len-64..len-48]"),
        ("sigprefix_v1_2sig", &t.v1_2, Some(t.v1_2_sig0), "v1, nsig=2: prefix = b[len-128..len-112]"),
    ];
    for (name, bytes, sig0, note) in cases {
        let p = SigPrefix::try_from_transaction_bytes(bytes).unwrap();
        assert_eq!(p.0, sig0.unwrap()[..16]);
        o.push("SIGPREFIX", name, bytes.to_vec(), false,
            json!({"sig_prefix": hex(&p.0), "first_signature": hex(&sig0.unwrap()), "note": note}));
    }
    let bad: [(&str, Vec<u8>, &str); 7] = [
        ("sigprefix_bad_empty", vec![], "empty"),
        ("sigprefix_bad_zero_sigs", vec![0, 1, 2], "legacy/v0 sig count 0"),
        ("sigprefix_bad_v1_zero_sigs", vec![0x81, 0, 0, 0], "v1 with nsig 0"),
        ("sigprefix_bad_v2_prefix", vec![0x82, 1, 0, 0], "unknown version 0x82"),
        ("sigprefix_bad_multibyte_count", vec![0x80, 0x01], "count byte has 0x80 set (compact-u16 continuation / version bit)"),
        ("sigprefix_bad_short_legacy", vec![1; 16], "legacy with fewer than 1+16 bytes"),
        ("sigprefix_bad_v1_too_short", vec![0x81, 2, 0, 0, 0, 0], "v1 nsig*64 > len"),
    ];
    for (name, bytes, note) in bad {
        assert!(SigPrefix::try_from_transaction_bytes(&bytes).is_none(), "{name}");
        o.push("SIGPREFIX", name, bytes, false, json!({"sig_prefix": null, "note": note}));
    }
    // boundary: exactly 17 bytes legacy works
    let mut b17 = vec![1u8];
    b17.extend(0x10..0x20u8);
    let p = SigPrefix::try_from_transaction_bytes(&b17).unwrap();
    o.push("SIGPREFIX", "sigprefix_min_legacy_17b", b17.clone(), false,
        json!({"sig_prefix": hex(&p.0), "note": "minimum accepted legacy length (1+16); prefix only, not a real tx"}));
}

/// Bytes the Rust decoders reject (or, for documented quirks, accept).
fn negatives(o: &mut Out, t: &Txs) {
    let c2r = |b: &[u8]| match wincode::deserialize::<ConnectorToRelay>(b) {
        Ok(_) => "accepted".to_string(),
        Err(e) => format!("error: {e}"),
    };
    let r2c = |b: &[u8]| match wincode::deserialize::<RelayToConnector>(b) {
        Ok(_) => "accepted".to_string(),
        Err(e) => format!("error: {e}"),
    };
    let boot = |b: &[u8]| match decode_bootstrap_frame(b) {
        Ok(_) => "accepted".to_string(),
        Err(e) => format!("error: {e}"),
    };
    let mut neg = |name: &str, decoder: &str, bytes: Vec<u8>, verdict: String, note: &str, expect_ok: bool| {
        assert_eq!(verdict == "accepted", expect_ok, "{name}: {verdict}");
        o.push("NEG", name, bytes, false,
            json!({"decoder": decoder, "rust_result": verdict, "note": note}));
    };

    for tag in [2u32, 7, 14, 0xffff_ffff] {
        let b = tag.to_le_bytes().to_vec();
        let v = c2r(&b);
        neg(&format!("neg_c2r_unused_tag_{tag}"), "ConnectorToRelay", b, v, "unassigned ConnectorToRelay tag", false);
    }
    for tag in [6u32, 0xffff_ffff] {
        let b = tag.to_le_bytes().to_vec();
        let v = r2c(&b);
        neg(&format!("neg_r2c_unused_tag_{tag}"), "RelayToConnector", b, v, "unassigned RelayToConnector tag", false);
    }
    // tag widths: enum tags are u32, a 1-byte tag is truncated input
    let b = vec![9u8];
    let v = c2r(&b);
    neg("neg_c2r_truncated_tag", "ConnectorToRelay", b, v, "enum tag is 4 bytes", false);

    // Pong with trailing byte: wincode::deserialize accepts trailing bytes
    let mut b = wincode::serialize(&ConnectorToRelay::Pong(7)).unwrap();
    b.push(0xee);
    let v = c2r(&b);
    neg("neg_c2r_pong_trailing_byte", "ConnectorToRelay", b, v,
        "QUIRK: wincode::deserialize ignores trailing bytes (the relay and gravity-connector decode with it); C encoder must never emit them", true);
    let mut b = wincode::serialize(&RelayToConnector::Ping(7)).unwrap();
    b.push(0xee);
    let v = r2c(&b);
    neg("neg_r2c_ping_trailing_byte", "RelayToConnector", b, v, "QUIRK: trailing bytes ignored", true);

    // truncated Pong
    let b = wincode::serialize(&ConnectorToRelay::Pong(7)).unwrap()[..11].to_vec();
    let v = c2r(&b);
    neg("neg_c2r_pong_truncated", "ConnectorToRelay", b, v, "u64 cut short", false);

    // bool = 2 in HandshakeV2.filter_ofac
    let h = HandshakeV2 {
        identity: addr(7), conn_version: "x".into(), num_threads: 1, filter_ofac: false,
        blacklisted_accounts: vec![], jito_tip_weight_bps: 1,
    };
    let mut b = wincode::serialize(&ConnectorToRelay::HandshakeV2(h.clone())).unwrap();
    let off = 4 + 32 + 8 + 1 + 1; // tag, identity, len, "x", num_threads
    assert_eq!(b[off], 0);
    b[off] = 2;
    let v = c2r(&b);
    neg("neg_c2r_handshake_bool_2", "ConnectorToRelay", b, v, "bool byte must be 0 or 1", false);
    // invalid utf-8 conn_version
    let mut b = wincode::serialize(&ConnectorToRelay::HandshakeV2(h)).unwrap();
    b[4 + 32 + 8] = 0xff;
    let v = c2r(&b);
    neg("neg_c2r_handshake_bad_utf8", "ConnectorToRelay", b, v, "String must be UTF-8", false);

    // Transaction.source_uri Option tag 2
    let tx = ConnectorToRelay::Transaction {
        order: WireSharableTx { tx_bytes: &t.legacy }, sent_at: Nanos(0), received_at: Nanos(0),
        src_addr: [0; 16], source_uri: None,
    };
    let mut b = wincode::serialize(&tx).unwrap();
    *b.last_mut().unwrap() = 2;
    let v = c2r(&b);
    neg("neg_c2r_transaction_option_tag_2", "ConnectorToRelay", b, v, "Option tag must be 0 or 1", false);
    // Transaction.source_uri of 65 bytes (ArrayStr<64> capacity)
    let mut b = wincode::serialize(&tx).unwrap();
    *b.last_mut().unwrap() = 1;
    b.extend(65u64.to_le_bytes());
    b.extend([b'a'; 65]);
    let v = c2r(&b);
    neg("neg_c2r_transaction_uri_65", "ConnectorToRelay", b, v, "ArrayStr<64>: length > 64 is a decode error", false);

    // BundleV2 with 6 txs (ArrayVec<_, 5>)
    let mut b = 11u32.to_le_bytes().to_vec();
    b.extend([0xb0; 32]);
    b.extend(6u64.to_le_bytes());
    for _ in 0..6 {
        b.extend((t.legacy.len() as u64).to_le_bytes());
        b.extend(&t.legacy);
    }
    b.extend(0u64.to_le_bytes());
    b.extend(0u64.to_le_bytes());
    b.extend(0u64.to_le_bytes());
    let v = c2r(&b);
    neg("neg_c2r_bundle_6_txs", "ConnectorToRelay", b, v, "MAX_TXS_PER_BUNDLE = 5", false);

    // ExecutionResult with 17 sigs
    let mut b = 3u32.to_le_bytes().to_vec();
    b.extend(1u64.to_le_bytes());
    b.extend([0x22; 16]);
    b.extend(0u32.to_le_bytes());
    b.extend(17u64.to_le_bytes());
    for _ in 0..17 {
        b.extend([0x51; 16]);
    }
    b.extend(0u64.to_le_bytes());
    b.extend([0; 25]);
    let v = c2r(&b);
    neg("neg_c2r_exec_17_sigs", "ConnectorToRelay", b, v, "MAX_TXS_PER_MESSAGE = 16", false);

    // ExecutionResult with NotIncludedReason index 45
    let mut b = 3u32.to_le_bytes().to_vec();
    b.extend(1u64.to_le_bytes());
    b.extend([0x22; 16]);
    b.extend(0u32.to_le_bytes());
    b.extend(1u64.to_le_bytes());
    b.extend([0x51; 16]);
    b.extend(1u64.to_le_bytes());
    b.extend(1u32.to_le_bytes()); // NotIncluded
    b.extend(45u32.to_le_bytes()); // past SLOT_ENDED (44)
    b.extend([0; 25]);
    let v = c2r(&b);
    neg("neg_c2r_exec_reason_45", "ConnectorToRelay", b, v, "NotIncludedReason wire tag > 44", false);
    // ... and the same with repr value 222 (SLOT_ENDED's repr) instead of its index 44
    let mut b2 = 3u32.to_le_bytes().to_vec();
    b2.extend(1u64.to_le_bytes());
    b2.extend([0x22; 16]);
    b2.extend(0u32.to_le_bytes());
    b2.extend(1u64.to_le_bytes());
    b2.extend([0x51; 16]);
    b2.extend(1u64.to_le_bytes());
    b2.extend(1u32.to_le_bytes());
    b2.extend(222u32.to_le_bytes());
    b2.extend([0; 25]);
    let v = c2r(&b2);
    neg("neg_c2r_exec_reason_repr_222", "ConnectorToRelay", b2, v,
        "TRAP: encoding the repr(u8) value (SLOT_ENDED=222) instead of the variant index (44) is a decode error", false);

    // Progress FfiOption tag 2
    let mut b = wincode::serialize(&ConnectorToRelay::Progress(SlotProgress {
        slot_num: 1, observed_at: Nanos(0), current_slot_progress: 0,
        slot_duration_override_ms: FfiOption::None, next_leadership: FfiOption::None, latest_blockhash: FfiOption::None,
    })).unwrap();
    let n = b.len();
    b[n - 3] = 2;
    let v = c2r(&b);
    neg("neg_c2r_progress_ffioption_tag_2", "ConnectorToRelay", b, v, "FfiOption tag must be 0 (None) or 1 (Some)", false);

    // MiniBlockGraph: Vec length that runs past the buffer
    let mut b = 0u32.to_le_bytes().to_vec();
    b.extend(1u64.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b.extend([0; 16]);
    b.extend(u64::MAX.to_le_bytes());
    let v = r2c(&b);
    neg("neg_r2c_graph_huge_len", "RelayToConnector", b, v, "row_offsets length u64::MAX", false);
    // NodeOrderRef tag 2
    let mut b = 0u32.to_le_bytes().to_vec();
    b.extend(1u64.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b.extend([0; 16]);
    b.extend(2u64.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b.extend(0u64.to_le_bytes());
    b.extend(1u64.to_le_bytes());
    b.extend(2u32.to_le_bytes());
    b.extend([0; 20]);
    b.extend(0u64.to_le_bytes());
    b.extend(0u64.to_le_bytes());
    let v = r2c(&b);
    neg("neg_r2c_graph_node_tag_2", "RelayToConnector", b, v, "NodeOrderRef tag must be 0 (Tx) or 1 (Bundle)", false);
    // SocketAddr tag 2
    let mut b = 3u32.to_le_bytes().to_vec();
    b.extend(1u64.to_le_bytes());
    b.extend(2u32.to_le_bytes());
    b.extend([0; 6]);
    let v = r2c(&b);
    neg("neg_r2c_socketaddr_tag_2", "RelayToConnector", b, v, "SocketAddr tag must be 0 (V4) or 1 (V6)", false);

    // bootstrap negatives
    let b = b"SOLGTC0".to_vec();
    let v = boot(&b);
    neg("neg_boot_short_magic", "decode_bootstrap_frame", b, v, "missing/short magic", false);
    let mut b = BOOTSTRAP_MAGIC.to_vec();
    b.extend(5u32.to_le_bytes());
    let v = boot(&b);
    neg("neg_boot_tag_5", "decode_bootstrap_frame", b, v, "BootstrapFrame tag 5", false);
    let mut b = BOOTSTRAP_MAGIC.to_vec();
    b.extend(4u32.to_le_bytes());
    b.extend(4u32.to_le_bytes());
    let v = boot(&b);
    neg("neg_boot_reject_reason_4", "decode_bootstrap_frame", b, v, "RejectReason tag 4", false);
    let mut b = BOOTSTRAP_MAGIC.to_vec();
    b.extend(1u32.to_le_bytes());
    b.extend([0; 31]);
    let v = boot(&b);
    neg("neg_boot_server_hello_short", "decode_bootstrap_frame", b, v, "challenge must be 32 bytes", false);
    let mut b = encode_bootstrap_frame(&BootstrapFrame::Accepted);
    b.push(0);
    let v = boot(&b);
    neg("neg_boot_accepted_trailing", "decode_bootstrap_frame", b, v, "QUIRK: trailing bytes ignored", true);
    // a session message is not a bootstrap frame
    let b = wincode::serialize(&RelayToConnector::Ping(1)).unwrap();
    let v = boot(&b);
    neg("neg_boot_session_msg", "decode_bootstrap_frame", b, v, "no SOLGTC01 magic => NotBootstrap", false);
}

// ---------------------------------------------------------------------------
// flux-network loopback self-test (relay's TCP listener vs. a raw client)
// ---------------------------------------------------------------------------

fn flux_selftest(hello: &[u8], proof: &[u8], server_hello: &[u8]) {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let listen: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut net = Network::default();
    // a 64 MiB socket buffer per connector, as the relay configures
    let group = net.add_group(TcpGroupConfig {
        name: "connectors",
        socket_buf_size: Some(64 * 1024 * 1024),
        ..TcpGroupConfig::default()
    });
    net.listen(group, listen).unwrap();

    let mut client = TcpStream::connect(listen).unwrap();
    client.set_nodelay(true).unwrap();
    client.set_read_timeout(Some(StdDuration::from_secs(5))).unwrap();

    let deadline = StdInstant::now() + StdDuration::from_secs(5);
    let mut token = None;
    while token.is_none() && StdInstant::now() < deadline {
        net.poll_with(|ev| {
            if let NetworkEvent::Accepted { token: t, .. } = ev {
                token = Some(t);
            }
        });
    }
    let token = token.expect("flux accepted the raw client");

    // raw client -> flux: frame, zero-length keepalive frame, frame; dribbled
    // one byte at a time to exercise reassembly.
    let ts1 = 0x0102_0304_0506_0708u64;
    let ts2 = SEND_TS;
    let mut wire = frame(hello, ts1);
    wire.extend(frame(&[], 0xdead_beef));
    wire.extend(frame(proof, ts2));
    let mut got: Vec<(Vec<u8>, u64)> = vec![];
    for chunk in wire.chunks(1) {
        client.write_all(chunk).unwrap();
        net.poll_with(|ev| {
            if let NetworkEvent::Message { payload, send_ts, .. } = ev {
                got.push((payload.to_vec(), send_ts.0));
            }
        });
    }
    let deadline = StdInstant::now() + StdDuration::from_secs(5);
    while got.len() < 2 && StdInstant::now() < deadline {
        net.poll_with(|ev| {
            if let NetworkEvent::Message { payload, send_ts, .. } = ev {
                got.push((payload.to_vec(), send_ts.0));
            }
        });
    }
    assert_eq!(got.len(), 2, "two frames delivered, keepalive skipped");
    assert_eq!(got[0], (hello.to_vec(), ts1));
    assert_eq!(got[1], (proof.to_vec(), ts2));

    // flux -> raw client: check the header layout
    assert!(net.send_with(token, |buf| buf.extend_from_slice(server_hello)));
    for _ in 0..100 {
        net.poll_with(|_| {});
    }
    let mut hdr = [0u8; 12];
    client.read_exact(&mut hdr).unwrap();
    let len = u32::from_le_bytes(hdr[..4].try_into().unwrap()) as usize;
    let ts = u64::from_le_bytes(hdr[4..].try_into().unwrap());
    assert_eq!(len, server_hello.len());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    assert!(ts.abs_diff(now) < 60_000_000_000, "send_ts is wall-clock ns since epoch: {ts} vs {now}");
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).unwrap();
    assert_eq!(body, server_hello);
    println!(
        "flux selftest: OK (raw->flux 2 frames + 1 keepalive reassembled byte-by-byte; flux->raw header len={len} send_ts={ts} ~ now={now})"
    );
}

fn main() {
    let kp = Keypair::new_from_array([7u8; 32]);
    let rfc_seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let rfc = Keypair::new_from_array(rfc_seed);
    let second = Keypair::new_from_array([8u8; 32]);
    let txs = build_txs(&kp, &second);

    let mut o = Out::default();
    bootstrap(&mut o, &kp, &rfc);
    handshakes(&mut o, kp.pubkey());
    progress(&mut o);
    simple(&mut o);
    orders(&mut o, &txs);
    exec_results(&mut o);
    graphs(&mut o, &txs);
    reasons(&mut o);
    sig_prefixes(&mut o, &txs);
    for (name, b, kind) in [
        ("tx_legacy", &txs.legacy, "legacy, 1 sig, system transfer"),
        ("tx_legacy_2sig", &txs.legacy2, "legacy, 2 sigs"),
        ("tx_v0", &txs.v0, "v0, 1 sig, no lookups"),
        ("tx_v1", &txs.v1, "v1, 1 sig"),
        ("tx_v1_2sig", &txs.v1_2, "v1, 2 sigs"),
    ] {
        o.push("RAW", name, b.clone(), false, json!({"what": kind, "signers": "seed 07*32 (+ seed 08*32)", "blockhash": hex(&[0x42; 32])}));
    }
    negatives(&mut o, &txs);

    let find = |n: &str| o.recs.iter().find(|r| r.name == n).unwrap().bytes.clone();
    flux_selftest(&find("boot_client_hello"), &find("boot_auth_proof"), &find("boot_server_hello"));

    // wincode DefaultConfig rejects (on decode AND encode) any Vec whose
    // len * size_of::<T>() exceeds 4 MiB (wincode-0.6.1 src/len.rs:101-120).
    const LIM: usize = 4 << 20;
    for (n, sz) in [
        ("u8 (tx bytes, String, &str)", std::mem::size_of::<u8>()),
        ("u32 (row_offsets, col_indices)", std::mem::size_of::<u32>()),
        ("CsrNode", std::mem::size_of::<CsrNode>()),
        ("WireSharableTx", std::mem::size_of::<WireSharableTx>()),
        ("WireSharableBundle", std::mem::size_of::<WireSharableBundle>()),
        ("[u8; 32] (blacklisted_accounts)", 32),
        ("SocketAddr", std::mem::size_of::<SocketAddr>()),
        ("WireStat", std::mem::size_of::<gravity_types::wire::WireStat>()),
    ] {
        println!("prealloc limit: Vec<{n}> size_of={sz} max_len={}", LIM / sz);
    }
    let dir = env!("CARGO_MANIFEST_DIR");
    let txt = format!("{dir}/vectors.txt");
    let h = format!("{dir}/../../src/disco/pack/gravity/fixtures/test_gravity_wire_vectors.h");
    o.write_txt(&txt);
    o.write_h(&h);
    println!("wrote {} records to {txt} and {h}", o.recs.len());
}
