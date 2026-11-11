#include "fd_gravity_wire.h"
#include "../../flamenco/runtime/fd_runtime_err.h"

/* Writer and reader cursors.  A cursor that runs out of space stays
   failed, so callers check once at the end. */

typedef struct {
  uchar * p;
  uchar * end;
  int     err;
} wr_t;

static inline void
wr_bytes( wr_t *        w,
          void const *  src,
          ulong         sz ) {
  if( FD_UNLIKELY( w->err || (ulong)(w->end-w->p)<sz ) ) { w->err = 1; return; }
  fd_memcpy( w->p, src, sz );
  w->p += sz;
}

static inline void wr_u8 ( wr_t * w, uchar  v ) { wr_bytes( w, &v, 1UL ); }
static inline void wr_u16( wr_t * w, ushort v ) { wr_bytes( w, &v, 2UL ); }
static inline void wr_u32( wr_t * w, uint   v ) { wr_bytes( w, &v, 4UL ); }
static inline void wr_u64( wr_t * w, ulong  v ) { wr_bytes( w, &v, 8UL ); }

static inline ulong
wr_fini( wr_t *  w,
         uchar * buf ) {
  return w->err ? 0UL : (ulong)(w->p-buf);
}

typedef struct {
  uchar const * p;
  uchar const * end;
  int           err;
} rd_t;

static inline uchar const *
rd_bytes( rd_t * r,
          ulong  sz ) {
  if( FD_UNLIKELY( r->err || (ulong)(r->end-r->p)<sz ) ) { r->err = 1; return NULL; }
  uchar const * p = r->p;
  r->p += sz;
  return p;
}

static inline uint
rd_u32( rd_t * r ) {
  uchar const * p = rd_bytes( r, 4UL );
  return p ? FD_LOAD( uint, p ) : 0U;
}

static inline ulong
rd_u64( rd_t * r ) {
  uchar const * p = rd_bytes( r, 8UL );
  return p ? FD_LOAD( ulong, p ) : 0UL;
}

/* rd_len reads a sequence length whose elements take at least elem_sz
   bytes each. */

static inline ulong
rd_len( rd_t * r,
        ulong  elem_sz ) {
  ulong n = rd_u64( r );
  if( FD_UNLIKELY( r->err || n>(ulong)(r->end-r->p)/elem_sz ) ) { r->err = 1; return 0UL; }
  return n;
}

uint
fd_gravity_wire_ni_from_txn_err( int err ) {
  /* FD_RUNTIME_TXN_ERR_* -1..-38 follow Agave's TransactionError order,
     which starts at NotIncludedReason ACCOUNT_IN_USE. */
  if( FD_LIKELY( err<=-1 && err>=-38 ) ) return FD_GRAVITY_WIRE_NI_ACCOUNT_IN_USE+(uint)(-err-1);
  if( err==FD_RUNTIME_TXN_ERR_BUNDLE_PEER ) return FD_GRAVITY_WIRE_NI_ALL_OR_NOTHING;
  if( err<=FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED ) return FD_GRAVITY_WIRE_NI_BLOCKHASH_NOT_FOUND;
  return FD_GRAVITY_WIRE_NI_SANITIZE_FAILURE;
}

static inline void
wr_boot_hdr( wr_t * w,
             uint   tag ) {
  wr_bytes( w, FD_GRAVITY_WIRE_MAGIC, 8UL );
  wr_u32( w, tag );
}

ulong
fd_gravity_wire_client_hello( uchar *       buf,
                              ulong         buf_sz,
                              uchar const * identity ) {
  wr_t w = { buf, buf+buf_sz, 0 };
  wr_boot_hdr( &w, FD_GRAVITY_WIRE_BOOT_CLIENT_HELLO );
  wr_bytes( &w, identity, 32UL );
  return wr_fini( &w, buf );
}

ulong
fd_gravity_wire_auth_proof( uchar *       buf,
                            ulong         buf_sz,
                            uchar const * signature ) {
  wr_t w = { buf, buf+buf_sz, 0 };
  wr_boot_hdr( &w, FD_GRAVITY_WIRE_BOOT_AUTH_PROOF );
  wr_bytes( &w, signature, 64UL );
  return wr_fini( &w, buf );
}

void
fd_gravity_wire_login_msg( uchar *       msg,
                           uchar const * identity,
                           uchar const * challenge ) {
  fd_memcpy( msg,      FD_GRAVITY_WIRE_MAGIC, 8UL  );
  fd_memcpy( msg+8UL,  identity,             32UL );
  fd_memcpy( msg+40UL, challenge,            32UL );
}

ulong
fd_gravity_wire_handshake( uchar *       buf,
                           ulong         buf_sz,
                           uchar const * identity,
                           char const *  version,
                           uint          thread_cnt,
                           int           filter_ofac,
                           uchar const * blacklisted,
                           ulong         blacklisted_cnt,
                           ushort        jito_tip_weight_bps ) {
  wr_t  w           = { buf, buf+buf_sz, 0 };
  ulong version_len = strlen( version );
  wr_u32  ( &w, 10U ); /* HandshakeV2 */
  wr_bytes( &w, identity, 32UL );
  wr_u64  ( &w, version_len );
  wr_bytes( &w, version, version_len );
  wr_u8   ( &w, (uchar)thread_cnt );
  wr_u8   ( &w, (uchar)!!filter_ofac );
  wr_u64  ( &w, blacklisted_cnt );
  wr_bytes( &w, blacklisted, 32UL*blacklisted_cnt );
  wr_u16  ( &w, jito_tip_weight_bps );
  return wr_fini( &w, buf );
}

ulong
fd_gravity_wire_stats( uchar *              buf,
                       ulong                buf_sz,
                       char const * const * names,
                       ulong const *        values,
                       ulong                cnt ) {
  wr_t w = { buf, buf+buf_sz, 0 };
  wr_u32( &w, 13U ); /* Stats */
  wr_u64( &w, cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    ulong name_len = strlen( names[ i ] );
    wr_u64  ( &w, name_len );
    wr_bytes( &w, names[ i ], name_len );
    wr_u64  ( &w, values[ i ] );
  }
  return wr_fini( &w, buf );
}

ulong
fd_gravity_wire_progress( uchar *                            buf,
                          ulong                              buf_sz,
                          fd_gravity_wire_progress_t const * progress ) {
  wr_t w = { buf, buf+buf_sz, 0 };
  wr_u32( &w, 9U ); /* Progress */
  wr_u64( &w, progress->slot );
  wr_u64( &w, progress->observed_at );
  wr_u8 ( &w, (uchar)fd_uint_min( progress->slot_progress, 100U ) );
  wr_u8 ( &w, 0 ); /* slot_duration_override_ms */
  if( FD_LIKELY( progress->next_leader_start!=ULONG_MAX ) ) {
    wr_u8 ( &w, 1 );
    wr_u64( &w, progress->next_leader_start );
    wr_u64( &w, progress->next_leader_end   );
  } else {
    wr_u8 ( &w, 0 );
  }
  if( FD_LIKELY( progress->blockhash ) ) {
    wr_u8   ( &w, 1 );
    wr_bytes( &w, progress->blockhash, 32UL );
  } else {
    wr_u8   ( &w, 0 );
  }
  return wr_fini( &w, buf );
}

ulong
fd_gravity_wire_be_challenge_sig( uchar *       buf,
                                  ulong         buf_sz,
                                  uchar const * challenge,
                                  uchar const * signature ) {
  wr_t w = { buf, buf+buf_sz, 0 };
  wr_u32( &w, 14U ); /* BlockEngineChallengeSignature */
  wr_bytes( &w, challenge, FD_GRAVITY_WIRE_BE_CHALLENGE_SZ );
  wr_bytes( &w, signature, 64UL );
  return wr_fini( &w, buf );
}

ulong
fd_gravity_wire_pong( uchar * buf,
                      ulong   buf_sz,
                      ulong   seq ) {
  wr_t w = { buf, buf+buf_sz, 0 };
  wr_u32( &w, 8U ); /* Pong */
  wr_u64( &w, seq );
  return wr_fini( &w, buf );
}

ulong
fd_gravity_wire_ready_for_tips( uchar * buf,
                                ulong   buf_sz,
                                ulong   slot ) {
  wr_t w = { buf, buf+buf_sz, 0 };
  wr_u32( &w, 4U ); /* ReadyForTips */
  wr_u64( &w, slot );
  return wr_fini( &w, buf );
}

ulong
fd_gravity_wire_result( uchar *                          buf,
                        ulong                            buf_sz,
                        fd_gravity_wire_result_t const * result ) {
  wr_t w = { buf, buf+buf_sz, 0 };
  wr_u32  ( &w, 3U ); /* ExecutionResult */
  wr_u64  ( &w, result->slot );
  wr_bytes( &w, result->graph_uuid, 16UL );
  if( result->is_bundle ) {
    wr_u32  ( &w, 1U ); /* BatchOrders::Bundle */
    wr_bytes( &w, result->key, 32UL );
  } else {
    wr_u32  ( &w, 0U ); /* BatchOrders::Transactions */
    wr_u64  ( &w, 1UL );
    wr_bytes( &w, result->key, 16UL );
  }
  wr_u64( &w, result->txn_cnt );
  for( ulong i=0UL; i<result->txn_cnt; i++ ) {
    if( FD_LIKELY( !result->ni[ i ] ) ) {
      wr_u32( &w, 0U ); /* Included */
      wr_u64( &w, result->slot );
      wr_u64( &w, result->cus[ i ] );
    } else {
      wr_u32( &w, 1U ); /* NotIncluded */
      wr_u32( &w, result->ni[ i ] );
    }
  }
  wr_u64( &w, result->graph_rx_at );
  wr_u64( &w, result->run_at      );
  wr_u64( &w, result->done_at     );
  wr_u8 ( &w, result->worker      );
  return wr_fini( &w, buf );
}

uint
fd_gravity_wire_boot_decode( uchar const *  payload,
                             ulong          sz,
                             uchar const ** challenge ) {
  rd_t r = { payload, payload+sz, 0 };
  uchar const * magic = rd_bytes( &r, 8UL );
  if( FD_UNLIKELY( !magic || memcmp( magic, FD_GRAVITY_WIRE_MAGIC, 8UL ) ) ) return UINT_MAX;
  uint tag = rd_u32( &r );
  switch( tag ) {
    case FD_GRAVITY_WIRE_BOOT_SERVER_HELLO: *challenge = rd_bytes( &r, 32UL ); break;
    case FD_GRAVITY_WIRE_BOOT_REJECTED:     rd_u32( &r );                      break;
    case FD_GRAVITY_WIRE_BOOT_ACCEPTED:                                        break;
    default: return UINT_MAX;
  }
  return r.err ? UINT_MAX : tag;
}

/* Sizes of encoded elements, used to skip them and as lower bounds for
   sequence lengths. */

#define CSR_NODE_MIN_SZ (4UL+16UL+4UL)
#define TX_MIN_SZ       (8UL)
#define BUNDLE_MIN_SZ   (32UL+8UL)

static int
skip_tx( rd_t * r ) {
  ulong sz = rd_len( r, 1UL );
  rd_bytes( r, sz );
  return r->err;
}

int
fd_gravity_wire_msg_decode( uchar const *           payload,
                            ulong                   sz,
                            fd_gravity_wire_msg_t * msg ) {
  rd_t r = { payload, payload+sz, 0 };
  msg->tag = rd_u32( &r );
  if( FD_UNLIKELY( r.err ) ) return -1;

  switch( msg->tag ) {
  case FD_GRAVITY_WIRE_R2C_GRAPH: {
    fd_gravity_wire_graph_t * g = msg->graph;
    g->slot          = rd_u64( &r );
    g->index_in_slot = rd_u32( &r );
    g->uuid          = rd_bytes( &r, 16UL );
    ulong row_cnt    = rd_len( &r, 4UL );
    g->row_offsets   = rd_bytes( &r, row_cnt*4UL );
    g->edge_cnt      = rd_len( &r, 4UL );
    g->col_indices   = rd_bytes( &r, g->edge_cnt*4UL );
    g->node_cnt      = rd_len( &r, CSR_NODE_MIN_SZ );
    if( FD_UNLIKELY( r.err || row_cnt!=g->node_cnt+1UL ) ) return -1;

    g->nodes = r.p;
    for( ulong i=0UL; i<g->node_cnt; i++ ) {
      uint kind = rd_u32( &r );
      if( FD_UNLIKELY( kind>1U ) ) return -1;
      rd_bytes( &r, kind ? 32UL : 16UL );
      rd_u32( &r );
    }
    g->nodes_sz = (ulong)(r.p-g->nodes);

    g->tx_cnt = rd_len( &r, TX_MIN_SZ );
    g->txs    = r.p;
    for( ulong i=0UL; i<g->tx_cnt && !r.err; i++ ) skip_tx( &r );
    g->txs_sz = (ulong)(r.p-g->txs);

    g->bundle_cnt = rd_len( &r, BUNDLE_MIN_SZ );
    g->bundles    = r.p;
    for( ulong i=0UL; i<g->bundle_cnt && !r.err; i++ ) {
      rd_bytes( &r, 32UL );
      ulong n = rd_len( &r, TX_MIN_SZ );
      if( FD_UNLIKELY( n>FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ) ) return -1;
      for( ulong j=0UL; j<n && !r.err; j++ ) skip_tx( &r );
    }
    g->bundles_sz = (ulong)(r.p-g->bundles);
    return r.err ? -1 : 0;
  }
  case FD_GRAVITY_WIRE_R2C_PING:
    msg->ping = rd_u64( &r );
    return r.err ? -1 : 0;
  case FD_GRAVITY_WIRE_R2C_DELETE_FAILSAFE:
    return 0;
  case FD_GRAVITY_WIRE_R2C_TPU_ADDRESS: {
    uchar const * some = rd_bytes( &r, 1UL );
    if( FD_UNLIKELY( !some || some[0]>1 ) ) return -1;
    msg->tpu.ip4  = 0U;
    msg->tpu.port = 0;
    if( !some[0] ) return 0;
    uint family = rd_u32( &r );
    if( FD_UNLIKELY( r.err || family>1U ) ) return -1;
    uchar const * ip = rd_bytes( &r, family ? 16UL : 4UL );
    uchar const * port = rd_bytes( &r, 2UL );
    if( FD_UNLIKELY( r.err ) ) return -1;
    if( FD_UNLIKELY( family ) ) return 1; /* IPv6 is not supported, keep our own */
    msg->tpu.ip4  = FD_LOAD( uint,   ip   );
    msg->tpu.port = FD_LOAD( ushort, port );
    return 0;
  }
  case FD_GRAVITY_WIRE_R2C_BE_CHALLENGE: {
    uchar const * challenge = rd_bytes( &r, FD_GRAVITY_WIRE_BE_CHALLENGE_SZ );
    if( FD_UNLIKELY( r.err || r.p!=r.end ) ) return -1;
    fd_memcpy( msg->be_challenge, challenge, FD_GRAVITY_WIRE_BE_CHALLENGE_SZ );
    return 0;
  }
  case FD_GRAVITY_WIRE_R2C_BE_SUBS:
    return 1;
  case FD_GRAVITY_WIRE_R2C_SHRED_RECV:
  case FD_GRAVITY_WIRE_R2C_SHRED_RTX_RECV: {
    ulong cnt = rd_len( &r, 4UL+4UL+2UL );
    msg->shred_dests.cnt = 0UL;
    for( ulong i=0UL; i<cnt && !r.err; i++ ) {
      uint family = rd_u32( &r );
      if( FD_UNLIKELY( r.err || family>1U ) ) return -1;
      uchar const * ip   = rd_bytes( &r, family ? 16UL : 4UL );
      uchar const * port = rd_bytes( &r, 2UL );
      if( FD_UNLIKELY( r.err || family || msg->shred_dests.cnt==32UL ) ) continue; /* IPv6 is not supported */
      msg->shred_dests.ip4 [ msg->shred_dests.cnt   ] = FD_LOAD( uint,   ip   );
      msg->shred_dests.port[ msg->shred_dests.cnt++ ] = FD_LOAD( ushort, port );
    }
    return r.err ? -1 : 0;
  }
  default:
    return 1;
  }
}

int
fd_gravity_wire_graph_node( fd_gravity_wire_graph_t const * graph,
                            ulong *                         off,
                            int *                           is_bundle,
                            uchar const **                  key,
                            uint *                          depth ) {
  rd_t r = { graph->nodes+*off, graph->nodes+graph->nodes_sz, 0 };
  *is_bundle = !!rd_u32( &r );
  *key       = rd_bytes( &r, *is_bundle ? 32UL : 16UL );
  *depth     = rd_u32( &r );
  *off       = (ulong)(r.p-graph->nodes);
  return r.err ? -1 : 0;
}

int
fd_gravity_wire_graph_tx( fd_gravity_wire_graph_t const * graph,
                          ulong *                         off,
                          uchar const **                  txn,
                          ulong *                         txn_sz ) {
  rd_t r = { graph->txs+*off, graph->txs+graph->txs_sz, 0 };
  *txn_sz = rd_len( &r, 1UL );
  *txn    = rd_bytes( &r, *txn_sz );
  *off    = (ulong)(r.p-graph->txs);
  return r.err ? -1 : 0;
}

int
fd_gravity_wire_graph_bundle( fd_gravity_wire_graph_t const * graph,
                              ulong *                         off,
                              uchar const **                  id,
                              ulong *                         txn_cnt,
                              uchar const **                  txn,
                              ulong *                         txn_sz ) {
  rd_t r = { graph->bundles+*off, graph->bundles+graph->bundles_sz, 0 };
  *id      = rd_bytes( &r, 32UL );
  *txn_cnt = rd_len( &r, TX_MIN_SZ );
  if( FD_UNLIKELY( *txn_cnt>FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ) ) return -1;
  for( ulong i=0UL; i<*txn_cnt; i++ ) {
    txn_sz[ i ] = rd_len( &r, 1UL );
    txn   [ i ] = rd_bytes( &r, txn_sz[ i ] );
  }
  *off = (ulong)(r.p-graph->bundles);
  return r.err ? -1 : 0;
}

uchar const *
fd_gravity_wire_sig_prefix( uchar const * txn,
                            ulong         txn_sz ) {
  if( FD_UNLIKELY( txn_sz<2UL ) ) return NULL;
  if( txn[0]==0x81 ) { /* v1: signatures at the end */
    ulong sig_cnt = txn[1];
    if( FD_UNLIKELY( !sig_cnt || sig_cnt*64UL>txn_sz ) ) return NULL;
    return txn+txn_sz-sig_cnt*64UL;
  }
  if( FD_UNLIKELY( !txn[0] || (txn[0]&0x80) || txn_sz<65UL ) ) return NULL;
  return txn+1UL;
}
