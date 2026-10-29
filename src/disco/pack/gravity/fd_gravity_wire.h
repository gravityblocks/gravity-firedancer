#ifndef HEADER_fd_src_disco_pack_gravity_fd_gravity_wire_h
#define HEADER_fd_src_disco_pack_gravity_fd_gravity_wire_h

/* fd_gravity_wire implements the subset of the Gravity relay <->
   connector wire protocol needed by an in-validator client.  The
   reference implementation is the gravity-types crate, shared by the
   relay and gravity-connector.

   Transport is a single TCP stream of frames:

     u32 LE payload_sz   (0 is a keepalive, skipped by the receiver)
     u64 LE send_ts      (sender wallclock ns, ignored by receivers)
     uchar  payload[ payload_sz ]

   Before the session starts, payloads are bootstrap frames:
   "SOLGTC01" || u32 LE tag || body.  After the bootstrap, payloads are
   wincode (DefaultConfig) encodings of the ConnectorToRelay and
   RelayToConnector enums: u32 LE tag followed by the variant fields.
   wincode encodes integers as fixed width little endian, sequence
   lengths as u64, enum tags as u32 (the variant index, not any Rust
   discriminant), Options as a u8 0/1 tag.

   Encoders write a message payload (without the frame header) into a
   caller provided buffer and return the number of bytes written, or 0
   if the buffer is too small or an argument is out of the protocol's
   range.  The relay closes the session on any malformed frame, so
   encoders validate everything the relay would.

   Decoders never trust the input: every length is bounds checked
   against the remaining bytes, and a decode error is reported to the
   caller (who should reset the session) rather than crashing. */

#include "../../../util/bits/fd_bits.h"

#define FD_GRAVITY_FRAME_HDR_SZ       (12UL)
#define FD_GRAVITY_MAGIC              "SOLGTC01"
#define FD_GRAVITY_MAGIC_SZ           (8UL)

/* Maximum frame payload either side will send (flux default). */
#define FD_GRAVITY_FRAME_MAX          (64UL<<20)

#define FD_GRAVITY_MAX_TXN_PER_BUNDLE (5UL)
#define FD_GRAVITY_MAX_TXN_PER_RESULT (16UL)
#define FD_GRAVITY_URI_MAX            (64UL)
#define FD_GRAVITY_SIG_PREFIX_SZ      (16UL)
#define FD_GRAVITY_BUNDLE_ID_SZ       (32UL)
#define FD_GRAVITY_UUID_SZ            (16UL)
#define FD_GRAVITY_BLACKLIST_MAX      (16UL) /* HandshakeV2 blacklisted accounts */

/* Bootstrap frame tags */

#define FD_GRAVITY_BOOT_CLIENT_HELLO  (0U)
#define FD_GRAVITY_BOOT_SERVER_HELLO  (1U)
#define FD_GRAVITY_BOOT_AUTH_PROOF    (2U)
#define FD_GRAVITY_BOOT_ACCEPTED      (3U)
#define FD_GRAVITY_BOOT_REJECTED      (4U)

#define FD_GRAVITY_REJECT_INVALID_HELLO    (0U)
#define FD_GRAVITY_REJECT_UNKNOWN_IDENTITY (1U)
#define FD_GRAVITY_REJECT_INVALID_PROOF    (2U)
#define FD_GRAVITY_REJECT_TIMEOUT          (3U)

/* The signed bootstrap message is "SOLGTC01" || identity || challenge */

#define FD_GRAVITY_AUTH_MSG_SZ        (72UL)

/* ConnectorToRelay tags */

#define FD_GRAVITY_C2R_TRANSACTION    ( 1U)
#define FD_GRAVITY_C2R_EXEC_RESULT    ( 3U)
#define FD_GRAVITY_C2R_PONG           ( 8U)
#define FD_GRAVITY_C2R_PROGRESS       ( 9U)
#define FD_GRAVITY_C2R_HANDSHAKE_V2   (10U)
#define FD_GRAVITY_C2R_BUNDLE_V2      (11U)

/* RelayToConnector tags */

#define FD_GRAVITY_R2C_MINI_BLOCK_GRAPH         (0U)
#define FD_GRAVITY_R2C_DELETE_FAILSAFE          (1U)
#define FD_GRAVITY_R2C_PREVIOUS_TIP_RECEIVER    (2U)
#define FD_GRAVITY_R2C_SHRED_RECEIVERS          (3U)
#define FD_GRAVITY_R2C_PING                     (4U)
#define FD_GRAVITY_R2C_SHRED_RETRANSMIT_RECEIVERS (5U)

/* NotIncludedReason wire tags (variant index in gravity-types, which is
   not the repr(u8) value).  Transaction errors map with
   fd_gravity_reason_from_txn_err below. */

#define FD_GRAVITY_NI_BANK_NOT_AVAILABLE          ( 1U)
#define FD_GRAVITY_NI_ALL_OR_NOTHING              ( 2U)
#define FD_GRAVITY_NI_ACCOUNT_IN_USE              ( 3U)
#define FD_GRAVITY_NI_ACCOUNT_LOADED_TWICE        ( 4U)
#define FD_GRAVITY_NI_INSUFFICIENT_FUNDS_FOR_FEE  ( 7U)
#define FD_GRAVITY_NI_ALREADY_PROCESSED           ( 9U)
#define FD_GRAVITY_NI_BLOCKHASH_NOT_FOUND         (10U)
#define FD_GRAVITY_NI_SANITIZE_FAILURE            (17U)
#define FD_GRAVITY_NI_WOULD_EXCEED_BLOCK_COST     (20U)
#define FD_GRAVITY_NI_WOULD_EXCEED_ACCOUNT_COST   (23U)
#define FD_GRAVITY_NI_WOULD_EXCEED_DATA_BLOCK     (24U)
#define FD_GRAVITY_NI_TOO_MANY_ACCOUNT_LOCKS      (25U)
#define FD_GRAVITY_NI_ALT_NOT_FOUND               (26U)
#define FD_GRAVITY_NI_MAX_WORKING_SLOT_EXCEEDED   (41U)
#define FD_GRAVITY_NI_NOT_SEQUENCING              (42U)
#define FD_GRAVITY_NI_UNKNOWN_ORDERS              (43U)
#define FD_GRAVITY_NI_SLOT_ENDED                  (44U)

/* Graph node kinds (NodeOrderRef) */

#define FD_GRAVITY_NODE_TX     (0U)
#define FD_GRAVITY_NODE_BUNDLE (1U)

/* Execution result kinds */

#define FD_GRAVITY_RESULT_INCLUDED     (0U)
#define FD_GRAVITY_RESULT_NOT_INCLUDED (1U)

/* Worker value used for results synthesized by the client rather than
   produced by an execution tile. */

#define FD_GRAVITY_WORKER_SYNTHETIC (255U)

/* fd_gravity_progress_t mirrors SlotProgress.  Optional fields are
   present when the matching has_ flag is non-zero. */

struct fd_gravity_progress {
  ulong slot;
  ulong observed_at;          /* wallclock ns */
  uchar current_slot_progress; /* in [0,100] */

  int   has_duration_override;
  ulong duration_override_ms;

  int   has_next_leadership;
  ulong next_leadership_start;
  ulong next_leadership_end;   /* inclusive */

  int   has_latest_blockhash;
  uchar latest_blockhash[ 32 ];
};

typedef struct fd_gravity_progress fd_gravity_progress_t;

/* fd_gravity_handshake_t mirrors HandshakeV2. */

struct fd_gravity_handshake {
  uchar         identity[ 32 ];
  char const *  version;        /* UTF-8, at most 64 bytes */
  uchar         num_threads;    /* must be non-zero */
  int           filter_ofac;
  ulong         blacklist_cnt;  /* at most FD_GRAVITY_BLACKLIST_MAX */
  uchar const * blacklist;      /* blacklist_cnt*32 bytes */
  ushort        jito_tip_weight_bps; /* in [0,10000] */
};

typedef struct fd_gravity_handshake fd_gravity_handshake_t;

/* fd_gravity_result_t is one ExecutionResult. */

struct fd_gravity_result {
  uint  kind;    /* FD_GRAVITY_RESULT_{INCLUDED,NOT_INCLUDED} */
  uint  reason;  /* FD_GRAVITY_NI_*, if NOT_INCLUDED */
  ulong slot;    /* execution slot, if INCLUDED */
  ulong cus;     /* consumed cost units, if INCLUDED */
};

typedef struct fd_gravity_result fd_gravity_result_t;

/* fd_gravity_exec_result_t mirrors BatchExecutionResult.  Exactly one
   of (sig_prefix_cnt>0) or (bundle_id!=NULL) describes the orders. */

struct fd_gravity_exec_result {
  ulong                       slot;              /* graph slot */
  uchar                       uuid[ FD_GRAVITY_UUID_SZ ]; /* graph uuid */
  ulong                       sig_prefix_cnt;    /* in [0,16] */
  uchar const *               sig_prefixes;      /* sig_prefix_cnt*16 bytes */
  uchar const *               bundle_id;         /* 32 bytes or NULL */
  ulong                       result_cnt;        /* in [1,16] */
  fd_gravity_result_t const * results;
  ulong                       batch_received_at;
  ulong                       forwarded_at;
  ulong                       res_received_at;
  uchar                       worker;
};

typedef struct fd_gravity_exec_result fd_gravity_exec_result_t;

/* fd_gravity_graph_t is a validated view of a MiniBlockGraph payload.
   Pointers point into the decoded payload, which must outlive the
   view.  The relay guarantees edges go forward (node index order is a
   topological order), so the client may ignore the edges entirely. */

struct fd_gravity_graph {
  ulong         slot;
  uint          index_in_slot;
  uchar         uuid[ FD_GRAVITY_UUID_SZ ];

  ulong         node_cnt;
  uchar const * nodes;        /* first CsrNode */
  uchar const * nodes_end;

  ulong         order_txn_cnt;
  uchar const * order_txns;   /* first WireSharableTx */
  uchar const * order_txns_end;

  ulong         order_bundle_cnt;
  uchar const * order_bundles; /* first WireSharableBundle */
  uchar const * order_bundles_end;
};

typedef struct fd_gravity_graph fd_gravity_graph_t;

/* fd_gravity_node_t is one decoded CsrNode. */

struct fd_gravity_node {
  uint          kind;  /* FD_GRAVITY_NODE_{TX,BUNDLE} */
  uchar const * id;    /* 16 byte SigPrefix or 32 byte BundleId */
  uint          depth;
};

typedef struct fd_gravity_node fd_gravity_node_t;

/* fd_gravity_bundle_t is one decoded WireSharableBundle. */

struct fd_gravity_bundle {
  uchar const * ext_uuid; /* 32 bytes */
  ulong         txn_cnt;  /* in [0,5] */
  uchar const * txn    [ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  ulong         txn_sz [ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
};

typedef struct fd_gravity_bundle fd_gravity_bundle_t;

FD_PROTOTYPES_BEGIN

/* Frame header ********************************************************/

static inline void
fd_gravity_frame_hdr_write( uchar * hdr,
                            ulong   payload_sz,
                            ulong   send_ts ) {
  FD_STORE( uint,  hdr,     (uint)payload_sz );
  FD_STORE( ulong, hdr+4UL, send_ts          );
}

static inline ulong
fd_gravity_frame_hdr_payload_sz( uchar const * hdr ) {
  return (ulong)FD_LOAD( uint, hdr );
}

/* Bootstrap ***********************************************************/

/* fd_gravity_encode_client_hello writes a ClientHello bootstrap payload
   (44 bytes).  fd_gravity_encode_auth_proof writes an AuthProof
   payload (76 bytes).  fd_gravity_auth_msg writes the 72 byte message
   the identity key must sign. */

ulong
fd_gravity_encode_client_hello( uchar *       buf,
                                ulong         buf_sz,
                                uchar const   identity[ static 32 ] );

ulong
fd_gravity_encode_auth_proof( uchar *       buf,
                              ulong         buf_sz,
                              uchar const   signature[ static 64 ] );

void
fd_gravity_auth_msg( uchar       msg[ static FD_GRAVITY_AUTH_MSG_SZ ],
                     uchar const identity [ static 32 ],
                     uchar const challenge[ static 32 ] );

/* fd_gravity_decode_bootstrap decodes a bootstrap payload from the
   relay.  On success returns 0, sets *tag, and for SERVER_HELLO copies
   the challenge into challenge (32 bytes), for REJECTED sets *reason
   (a FD_GRAVITY_REJECT_* value).  Returns -1 on any malformed input,
   including frames only a connector sends (CLIENT_HELLO, AUTH_PROOF).
   Like the Rust decoder, trailing bytes are ignored. */

int
fd_gravity_decode_bootstrap( uchar const * payload,
                             ulong         sz,
                             uint *        tag,
                             uchar         challenge[ static 32 ],
                             uint *        reason );

/* ConnectorToRelay encoders *******************************************/

ulong
fd_gravity_encode_handshake_v2( uchar *                        buf,
                                ulong                          buf_sz,
                                fd_gravity_handshake_t const * hs );

ulong
fd_gravity_encode_progress( uchar *                       buf,
                            ulong                         buf_sz,
                            fd_gravity_progress_t const * p );

ulong
fd_gravity_encode_pong( uchar * buf,
                        ulong   buf_sz,
                        ulong   seq );

/* fd_gravity_encode_transaction writes a Transaction message.  src_addr
   is a 16 byte IPv6 (or IPv4 mapped) address, or NULL for all zeros.
   source_uri may be NULL (None). */

ulong
fd_gravity_encode_transaction( uchar *       buf,
                               ulong         buf_sz,
                               uchar const * txn,
                               ulong         txn_sz,
                               ulong         sent_at,
                               ulong         received_at,
                               uchar const * src_addr,
                               char const *  source_uri );

/* fd_gravity_encode_bundle_v2 writes a BundleV2 message.  source_uri
   must be non-NULL (it is not optional on the wire), possibly "". */

ulong
fd_gravity_encode_bundle_v2( uchar *              buf,
                             ulong                buf_sz,
                             uchar const          ext_uuid[ static 32 ],
                             ulong                txn_cnt,
                             uchar const * const * txn,
                             ulong const *        txn_sz,
                             char const *         source_uri,
                             ulong                received_at,
                             ulong                sent_at );

ulong
fd_gravity_encode_exec_result( uchar *                          buf,
                               ulong                            buf_sz,
                               fd_gravity_exec_result_t const * r );

/* RelayToConnector decoders *******************************************/

/* fd_gravity_decode_tag reads the RelayToConnector tag.  Returns 0 on
   success and -1 if the payload is too short. */

static inline int
fd_gravity_decode_tag( uchar const * payload,
                       ulong         sz,
                       uint *        tag ) {
  if( FD_UNLIKELY( sz<4UL ) ) return -1;
  *tag = FD_LOAD( uint, payload );
  return 0;
}

/* fd_gravity_decode_ping decodes a Ping payload (including the tag) and
   sets *seq.  Returns 0 on success, -1 on error. */

int
fd_gravity_decode_ping( uchar const * payload,
                        ulong         sz,
                        ulong *       seq );

/* fd_gravity_decode_graph decodes and fully validates a MiniBlockGraph
   payload (including the tag).  Returns 0 on success and fills graph,
   -1 on any malformed input.  On success, the node and order iterators
   below cannot fail.  Builder transactions may be empty (zero bytes):
   that is well formed on the wire, and consumers reject such orders
   individually (fd_gravity_sig_prefix and fd_txn_parse both fail on
   them).  The CSR edges are only checked for size (row_offsets has
   node_cnt+1 entries), as the client executes in node index order. */

int
fd_gravity_decode_graph( uchar const *        payload,
                         ulong                sz,
                         fd_gravity_graph_t * graph );

/* fd_gravity_node_next decodes the node at cur and returns a pointer
   to the next node.  cur must be a node in a graph validated by
   fd_gravity_decode_graph. */

uchar const *
fd_gravity_node_next( uchar const *       cur,
                      fd_gravity_node_t * node );

/* fd_gravity_order_txn_next decodes the builder transaction at cur and
   returns a pointer to the next one. */

uchar const *
fd_gravity_order_txn_next( uchar const *  cur,
                           uchar const ** txn,
                           ulong *        txn_sz );

/* fd_gravity_order_bundle_next decodes the builder bundle at cur and
   returns a pointer to the next one. */

uchar const *
fd_gravity_order_bundle_next( uchar const *         cur,
                              fd_gravity_bundle_t * bundle );

/* Misc ****************************************************************/

/* fd_gravity_first_sig returns a pointer to the 64 byte first signature
   of a serialized legacy, v0 or v1 transaction, or NULL if the
   signature layout is invalid.  fd_gravity_sig_prefix computes the
   SigPrefix (its first 16 bytes).  Returns 0 on success and -1 if the
   signature layout is invalid. */

uchar const *
fd_gravity_first_sig( uchar const * txn,
                      ulong         txn_sz );

int
fd_gravity_sig_prefix( uchar const * txn,
                       ulong         txn_sz,
                       uchar         out[ static FD_GRAVITY_SIG_PREFIX_SZ ] );

/* fd_gravity_jito_bundle_id computes the id Jito gives a bundle of cnt
   transactions whose first signatures are sigs[0,cnt): the SHA-256 of
   their base58 encodings joined with "," (jito-solana
   derive_bundle_id).  Used as the BundleV2 ext_uuid of forwarded Jito
   bundles. */

void
fd_gravity_jito_bundle_id( uchar                 out[ static 32 ],
                           ulong                 cnt,
                           uchar const * const * sigs );

/* fd_gravity_reason_from_txn_err maps a Firedancer runtime transaction
   error (FD_RUNTIME_TXN_ERR_*, negative) to a NotIncludedReason wire
   tag.  Firedancer numbers transaction errors -(Agave index+1), and
   gravity puts Agave's index 0 at wire tag 3, so most errors map with
   2-err. */

uint
fd_gravity_reason_from_txn_err( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_pack_gravity_fd_gravity_wire_h */
