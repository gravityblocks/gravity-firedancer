#ifndef HEADER_fd_src_discof_gravity_fd_gravity_wire_h
#define HEADER_fd_src_discof_gravity_fd_gravity_wire_h

/* fd_gravity_wire encodes and decodes the messages a validator exchanges
   with a block building relay.

   The relay speaks over one TCP connection.  Every message is a frame
   of a 4 byte little endian payload length, an 8 byte send timestamp
   and the payload.  Payloads are wincode: little endian integers, u32
   enum tags, u64 sequence lengths, a 1 byte tag for options.

   The connection starts with a bootstrap exchange.  Each bootstrap
   payload starts with FD_GRAVITY_WIRE_MAGIC.  The validator sends a
   ClientHello with its identity, the relay answers with a challenge,
   the validator signs FD_GRAVITY_WIRE_MAGIC||identity||challenge and the
   relay accepts or rejects.  Then the validator sends a handshake and
   both sides exchange session messages.

   Decoders never read outside the given payload and reject anything
   malformed.

   The relay's Rust wire types (gravity-types) define the format.  When
   adding or changing a message, check its bytes against what wincode
   produces for the Rust type. */

#include "../../disco/fd_disco_base.h"

#define FD_GRAVITY_WIRE_MAGIC          "SOLGTC01"
#define FD_GRAVITY_WIRE_FRAME_HDR_SZ   (12UL)
#define FD_GRAVITY_WIRE_LOGIN_MSG_SZ   (72UL)  /* signed by the identity */

/* Bootstrap frame tags */

#define FD_GRAVITY_WIRE_BOOT_CLIENT_HELLO (0U)
#define FD_GRAVITY_WIRE_BOOT_SERVER_HELLO (1U)
#define FD_GRAVITY_WIRE_BOOT_AUTH_PROOF   (2U)
#define FD_GRAVITY_WIRE_BOOT_ACCEPTED     (3U)
#define FD_GRAVITY_WIRE_BOOT_REJECTED     (4U)

/* Relay to validator message tags */

#define FD_GRAVITY_WIRE_R2C_GRAPH           (0U)
#define FD_GRAVITY_WIRE_R2C_DELETE_FAILSAFE (1U)
#define FD_GRAVITY_WIRE_R2C_SHRED_RECV     (3U) /* receivers of our leader shreds */
#define FD_GRAVITY_WIRE_R2C_PING            (4U)
#define FD_GRAVITY_WIRE_R2C_SHRED_RTX_RECV  (5U) /* receivers of the shreds we retransmit */
#define FD_GRAVITY_WIRE_R2C_TPU_ADDRESS     (6U)
#define FD_GRAVITY_WIRE_R2C_BE_CHALLENGE    (7U) /* a block engine's login challenge to sign */
#define FD_GRAVITY_WIRE_R2C_BE_SUBS         (8U) /* ignored: the bundle tile drops its own subscriptions while relay_up */

#define FD_GRAVITY_WIRE_BE_CHALLENGE_SZ (9UL)

/* NotIncludedReason values this client reports.  The wire value is the
   variant's declaration index. */

#define FD_GRAVITY_WIRE_NI_BANK_NOT_AVAILABLE           ( 1U)
#define FD_GRAVITY_WIRE_NI_ALL_OR_NOTHING               ( 2U)
#define FD_GRAVITY_WIRE_NI_ACCOUNT_IN_USE               ( 3U)
#define FD_GRAVITY_WIRE_NI_BLOCKHASH_NOT_FOUND          (10U)
#define FD_GRAVITY_WIRE_NI_SANITIZE_FAILURE             (17U)
#define FD_GRAVITY_WIRE_NI_WOULD_EXCEED_MAX_BLOCK_COST  (20U)
#define FD_GRAVITY_WIRE_NI_UNKNOWN_ORDERS               (43U)
#define FD_GRAVITY_WIRE_NI_SLOT_ENDED                   (44U)

#define FD_GRAVITY_WIRE_BUNDLE_TXN_MAX (5UL)

/* fd_gravity_wire_ni_from_txn_err maps an FD_RUNTIME_TXN_ERR_* value to
   a NotIncludedReason. */

uint
fd_gravity_wire_ni_from_txn_err( int err );

/* Encoders write the payload of one message to buf, which has room for
   buf_sz bytes, and return its size, or 0 if it does not fit. */

ulong
fd_gravity_wire_client_hello( uchar *       buf,
                              ulong         buf_sz,
                              uchar const * identity );

ulong
fd_gravity_wire_auth_proof( uchar *       buf,
                            ulong         buf_sz,
                            uchar const * signature );

/* fd_gravity_wire_login_msg writes the 72 bytes the identity signs. */

void
fd_gravity_wire_login_msg( uchar *       msg,
                           uchar const * identity,
                           uchar const * challenge );

/* fd_gravity_wire_stats writes a Stats message of cnt name and value
   pairs, which the relay records. */

ulong
fd_gravity_wire_stats( uchar *              buf,
                       ulong                buf_sz,
                       char const * const * names,
                       ulong const *        values,
                       ulong                cnt );

ulong
fd_gravity_wire_handshake( uchar *       buf,
                           ulong         buf_sz,
                           uchar const * identity,
                           char const *  version,
                           uint          thread_cnt,
                           int           filter_ofac,
                           uchar const * blacklisted, /* blacklisted_cnt pubkeys */
                           ulong         blacklisted_cnt,
                           ushort        jito_tip_weight_bps );

struct fd_gravity_wire_progress {
  ulong         slot;
  ulong         observed_at;        /* wallclock ns */
  uint          slot_progress;      /* percent */
  ulong         next_leader_start;  /* ULONG_MAX if unknown */
  ulong         next_leader_end;    /* inclusive */
  uchar const * blockhash;          /* NULL if unknown */
};
typedef struct fd_gravity_wire_progress fd_gravity_wire_progress_t;

ulong
fd_gravity_wire_progress( uchar *                            buf,
                          ulong                              buf_sz,
                          fd_gravity_wire_progress_t const * progress );

ulong
fd_gravity_wire_pong( uchar * buf,
                      ulong   buf_sz,
                      ulong   seq );

ulong
fd_gravity_wire_ready_for_tips( uchar * buf,
                                ulong   buf_sz,
                                ulong   slot );

/* fd_gravity_wire_be_challenge_sig writes a BlockEngineChallengeSignature:
   the challenge and the identity's signature of base58(identity) "-"
   challenge. */

ulong
fd_gravity_wire_be_challenge_sig( uchar *       buf,
                                  ulong         buf_sz,
                                  uchar const * challenge,
                                  uchar const * signature );

/* fd_gravity_wire_result is one execution result for one graph node.
   For a loose transaction node, key is its 16 byte signature prefix,
   otherwise the 32 byte bundle id.  Each of the txn_cnt results is
   included if ni[i] is 0, in which case cus[i] are its cost units.
   worker is 255 if the node never reached an execle tile. */

struct fd_gravity_wire_result {
  ulong         slot;
  uchar const * graph_uuid;
  int           is_bundle;
  uchar const * key;
  ulong         txn_cnt;
  uint          ni [ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
  ulong         cus[ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
  ulong         graph_rx_at;
  ulong         run_at;
  ulong         done_at;
  uchar         worker;
};
typedef struct fd_gravity_wire_result fd_gravity_wire_result_t;

ulong
fd_gravity_wire_result( uchar *                          buf,
                        ulong                            buf_sz,
                        fd_gravity_wire_result_t const * result );

/* fd_gravity_wire_boot_decode decodes a bootstrap payload.  Returns its
   tag and points *challenge at the challenge of a ServerHello, or
   returns UINT_MAX if the payload is not a valid bootstrap frame. */

uint
fd_gravity_wire_boot_decode( uchar const *  payload,
                             ulong          sz,
                             uchar const ** challenge );

/* A decoded MiniBlockGraph.  It points into the payload, so it is
   valid while the payload is.  Graph nodes are visited with
   fd_gravity_wire_graph_node and the builder's orders with
   fd_gravity_wire_graph_order. */

struct fd_gravity_wire_graph {
  ulong         slot;
  uint          index_in_slot;
  uchar const * uuid;
  ulong         node_cnt;
  ulong         edge_cnt;
  uchar const * row_offsets; /* node_cnt+1 LE uints */
  uchar const * col_indices; /* edge_cnt LE uints */
  uchar const * nodes;
  ulong         nodes_sz;
  ulong         tx_cnt;
  uchar const * txs;
  ulong         txs_sz;
  ulong         bundle_cnt;
  uchar const * bundles;
  ulong         bundles_sz;
};
typedef struct fd_gravity_wire_graph fd_gravity_wire_graph_t;

/* A decoded relay message. */

struct fd_gravity_wire_msg {
  uint tag;
  union {
    ulong                   ping;
    fd_gravity_wire_graph_t graph[1];
    uchar                   be_challenge[ FD_GRAVITY_WIRE_BE_CHALLENGE_SZ ];
    struct {
      uint   ip4;  /* network order, 0 for None */
      ushort port;
    } tpu;
    struct {
      ulong  cnt;  /* IPv4 ones, at most 32 */
      uint   ip4 [ 32 ];
      ushort port[ 32 ];
    } shred_dests;
  };
};
typedef struct fd_gravity_wire_msg fd_gravity_wire_msg_t;

/* fd_gravity_wire_msg_decode decodes a relay session payload into msg.
   Returns 0 on success, 1 for a message this client ignores and -1 if
   the payload is malformed. */

int
fd_gravity_wire_msg_decode( uchar const *           payload,
                            ulong                   sz,
                            fd_gravity_wire_msg_t * msg );

/* fd_gravity_wire_graph_node decodes the node at *off of graph's node
   list and advances *off.  It sets *is_bundle, points *key at the 16
   byte signature prefix or the 32 byte bundle id, and sets *depth.
   Returns 0 on success, -1 if malformed. */

int
fd_gravity_wire_graph_node( fd_gravity_wire_graph_t const * graph,
                            ulong *                         off,
                            int *                           is_bundle,
                            uchar const **                  key,
                            uint *                          depth );

/* fd_gravity_wire_graph_tx decodes the transaction at *off of graph's
   loose transactions and advances *off.  fd_gravity_wire_graph_bundle
   decodes a bundle: its 32 byte id and up to 5 transactions.  Both
   return 0 on success, -1 if malformed. */

int
fd_gravity_wire_graph_tx( fd_gravity_wire_graph_t const * graph,
                          ulong *                         off,
                          uchar const **                  txn,
                          ulong *                         txn_sz );

int
fd_gravity_wire_graph_bundle( fd_gravity_wire_graph_t const * graph,
                              ulong *                         off,
                              uchar const **                  id,
                              ulong *                         txn_cnt,
                              uchar const **                  txn,
                              ulong *                         txn_sz );

/* fd_gravity_wire_sig_prefix returns a pointer to the 16 byte signature
   prefix the relay uses to refer to a transaction, or NULL if txn has
   no first signature. */

uchar const *
fd_gravity_wire_sig_prefix( uchar const * txn,
                            ulong         txn_sz );

#endif /* HEADER_fd_src_discof_gravity_fd_gravity_wire_h */
