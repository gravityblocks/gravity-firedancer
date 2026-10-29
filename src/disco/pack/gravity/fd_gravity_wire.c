#include "fd_gravity_wire.h"
#include "../../../util/fd_util.h"
#include "../../../flamenco/runtime/fd_runtime_err.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/sha256/fd_sha256.h"

/* Encoder cursor.  Writes are bounds checked; the first failing write
   latches err and later writes are no-ops. */

typedef struct {
  uchar * p;
  uchar * end;
  int     err;
} enc_t;

static inline void
enc_bytes( enc_t * e, void const * src, ulong sz ) {
  if( FD_UNLIKELY( e->err || (ulong)(e->end-e->p)<sz ) ) { e->err = 1; return; }
  if( FD_UNLIKELY( !sz ) ) return; /* src may be NULL (empty string / list) */
  fd_memcpy( e->p, src, sz );
  e->p += sz;
}

static inline void enc_u8 ( enc_t * e, uchar  v ) { enc_bytes( e, &v, 1UL ); }
static inline void enc_u16( enc_t * e, ushort v ) { enc_bytes( e, &v, 2UL ); }
static inline void enc_u32( enc_t * e, uint   v ) { enc_bytes( e, &v, 4UL ); }
static inline void enc_u64( enc_t * e, ulong  v ) { enc_bytes( e, &v, 8UL ); }

static inline ulong
enc_fini( enc_t * e, uchar * buf ) {
  return e->err ? 0UL : (ulong)(e->p-buf);
}

/* Decoder cursor, with the same latching error semantics. */

typedef struct {
  uchar const * p;
  uchar const * end;
  int           err;
} dec_t;

static inline uchar const *
dec_skip( dec_t * d, ulong sz ) {
  if( FD_UNLIKELY( d->err || (ulong)(d->end-d->p)<sz ) ) { d->err = 1; return NULL; }
  uchar const * r = d->p;
  d->p += sz;
  return r;
}

static inline uint
dec_u32( dec_t * d ) {
  uchar const * r = dec_skip( d, 4UL );
  return r ? FD_LOAD( uint, r ) : 0U;
}

static inline ulong
dec_u64( dec_t * d ) {
  uchar const * r = dec_skip( d, 8UL );
  return r ? FD_LOAD( ulong, r ) : 0UL;
}

/* Bootstrap ***********************************************************/

ulong
fd_gravity_encode_client_hello( uchar *     buf,
                                ulong       buf_sz,
                                uchar const identity[ static 32 ] ) {
  enc_t e = { buf, buf+buf_sz, 0 };
  enc_bytes( &e, FD_GRAVITY_MAGIC, FD_GRAVITY_MAGIC_SZ );
  enc_u32  ( &e, FD_GRAVITY_BOOT_CLIENT_HELLO );
  enc_bytes( &e, identity, 32UL );
  return enc_fini( &e, buf );
}

ulong
fd_gravity_encode_auth_proof( uchar *     buf,
                              ulong       buf_sz,
                              uchar const signature[ static 64 ] ) {
  enc_t e = { buf, buf+buf_sz, 0 };
  enc_bytes( &e, FD_GRAVITY_MAGIC, FD_GRAVITY_MAGIC_SZ );
  enc_u32  ( &e, FD_GRAVITY_BOOT_AUTH_PROOF );
  enc_bytes( &e, signature, 64UL );
  return enc_fini( &e, buf );
}

void
fd_gravity_auth_msg( uchar       msg[ static FD_GRAVITY_AUTH_MSG_SZ ],
                     uchar const identity [ static 32 ],
                     uchar const challenge[ static 32 ] ) {
  fd_memcpy( msg,                        FD_GRAVITY_MAGIC, FD_GRAVITY_MAGIC_SZ );
  fd_memcpy( msg+FD_GRAVITY_MAGIC_SZ,     identity,        32UL );
  fd_memcpy( msg+FD_GRAVITY_MAGIC_SZ+32UL, challenge,      32UL );
}

int
fd_gravity_decode_bootstrap( uchar const * payload,
                             ulong         sz,
                             uint *        tag,
                             uchar         challenge[ static 32 ],
                             uint *        reason ) {
  dec_t d = { payload, payload+sz, 0 };
  uchar const * magic = dec_skip( &d, FD_GRAVITY_MAGIC_SZ );
  if( FD_UNLIKELY( !magic || memcmp( magic, FD_GRAVITY_MAGIC, FD_GRAVITY_MAGIC_SZ ) ) ) return -1;
  uint t = dec_u32( &d );
  if( FD_UNLIKELY( d.err ) ) return -1;
  switch( t ) {
  case FD_GRAVITY_BOOT_SERVER_HELLO: {
    uchar const * c = dec_skip( &d, 32UL );
    if( FD_UNLIKELY( !c ) ) return -1;
    fd_memcpy( challenge, c, 32UL );
    break;
  }
  case FD_GRAVITY_BOOT_ACCEPTED:
    break;
  case FD_GRAVITY_BOOT_REJECTED:
    /* RejectReason is a closed enum: unknown tags are a decode error */
    *reason = dec_u32( &d );
    if( FD_UNLIKELY( d.err || *reason>FD_GRAVITY_REJECT_TIMEOUT ) ) return -1;
    break;
  default:
    return -1;
  }
  *tag = t;
  return 0;
}

/* ConnectorToRelay encoders *******************************************/

/* is_utf8 returns 1 if s[0,sz) is well formed UTF-8 (no overlongs,
   surrogates or code points above U+10FFFF), matching Rust's
   str::from_utf8. */

static int
is_utf8( uchar const * s,
         ulong         sz ) {
  ulong i = 0UL;
  while( i<sz ) {
    uchar c = s[i];
    if( c<0x80U ) { i++; continue; }
    ulong n; uint min; uint cp;
    if(      (c&0xE0U)==0xC0U ) { n = 1UL; min = 0x80U;    cp = c&0x1FU; }
    else if( (c&0xF0U)==0xE0U ) { n = 2UL; min = 0x800U;   cp = c&0x0FU; }
    else if( (c&0xF8U)==0xF0U ) { n = 3UL; min = 0x10000U; cp = c&0x07U; }
    else return 0;
    if( FD_UNLIKELY( i+n>=sz ) ) return 0;
    for( ulong j=1UL; j<=n; j++ ) {
      uchar cc = s[i+j];
      if( (cc&0xC0U)!=0x80U ) return 0;
      cp = (cp<<6) | (cc&0x3FU);
    }
    if( cp<min || cp>0x10FFFFU || (cp>=0xD800U && cp<=0xDFFFU) ) return 0;
    i += n+1UL;
  }
  return 1;
}

ulong
fd_gravity_encode_handshake_v2( uchar *                        buf,
                                ulong                          buf_sz,
                                fd_gravity_handshake_t const * hs ) {
  ulong ver_sz = hs->version ? strlen( hs->version ) : 0UL;
  if( FD_UNLIKELY( !hs->num_threads                          ) ) return 0UL;
  if( FD_UNLIKELY( hs->jito_tip_weight_bps>10000U            ) ) return 0UL;
  if( FD_UNLIKELY( hs->blacklist_cnt>FD_GRAVITY_BLACKLIST_MAX ) ) return 0UL;
  if( FD_UNLIKELY( hs->blacklist_cnt && !hs->blacklist       ) ) return 0UL;
  if( FD_UNLIKELY( !is_utf8( (uchar const *)hs->version, ver_sz ) ) ) return 0UL;

  enc_t e = { buf, buf+buf_sz, 0 };
  enc_u32  ( &e, FD_GRAVITY_C2R_HANDSHAKE_V2 );
  enc_bytes( &e, hs->identity, 32UL );
  enc_u64  ( &e, ver_sz );
  enc_bytes( &e, hs->version, ver_sz );
  enc_u8   ( &e, hs->num_threads );
  enc_u8   ( &e, (uchar)!!hs->filter_ofac );
  enc_u64  ( &e, hs->blacklist_cnt );
  enc_bytes( &e, hs->blacklist, 32UL*hs->blacklist_cnt );
  enc_u16  ( &e, hs->jito_tip_weight_bps );
  return enc_fini( &e, buf );
}

ulong
fd_gravity_encode_progress( uchar *                       buf,
                            ulong                         buf_sz,
                            fd_gravity_progress_t const * p ) {
  if( FD_UNLIKELY( p->current_slot_progress>100U ) ) return 0UL;

  enc_t e = { buf, buf+buf_sz, 0 };
  enc_u32( &e, FD_GRAVITY_C2R_PROGRESS );
  enc_u64( &e, p->slot );
  enc_u64( &e, p->observed_at );
  enc_u8 ( &e, p->current_slot_progress );

  enc_u8( &e, (uchar)!!p->has_duration_override );
  if( p->has_duration_override ) enc_u64( &e, p->duration_override_ms );

  enc_u8( &e, (uchar)!!p->has_next_leadership );
  if( p->has_next_leadership ) {
    enc_u64( &e, p->next_leadership_start );
    enc_u64( &e, p->next_leadership_end   );
  }

  enc_u8( &e, (uchar)!!p->has_latest_blockhash );
  if( p->has_latest_blockhash ) enc_bytes( &e, p->latest_blockhash, 32UL );
  return enc_fini( &e, buf );
}

ulong
fd_gravity_encode_pong( uchar * buf,
                        ulong   buf_sz,
                        ulong   seq ) {
  enc_t e = { buf, buf+buf_sz, 0 };
  enc_u32( &e, FD_GRAVITY_C2R_PONG );
  enc_u64( &e, seq );
  return enc_fini( &e, buf );
}

ulong
fd_gravity_encode_transaction( uchar *       buf,
                               ulong         buf_sz,
                               uchar const * txn,
                               ulong         txn_sz,
                               ulong         sent_at,
                               ulong         received_at,
                               uchar const * src_addr,
                               char const *  source_uri ) {
  static uchar const zero_addr[ 16 ] = {0};
  ulong uri_sz = source_uri ? strlen( source_uri ) : 0UL;
  if( FD_UNLIKELY( !txn_sz ) ) return 0UL;
  if( FD_UNLIKELY( uri_sz>FD_GRAVITY_URI_MAX ) ) return 0UL;
  if( FD_UNLIKELY( source_uri && !is_utf8( (uchar const *)source_uri, uri_sz ) ) ) return 0UL;

  enc_t e = { buf, buf+buf_sz, 0 };
  enc_u32  ( &e, FD_GRAVITY_C2R_TRANSACTION );
  enc_u64  ( &e, txn_sz );
  enc_bytes( &e, txn, txn_sz );
  enc_u64  ( &e, sent_at );
  enc_u64  ( &e, received_at );
  enc_bytes( &e, src_addr ? src_addr : zero_addr, 16UL );
  enc_u8   ( &e, (uchar)!!source_uri );
  if( source_uri ) {
    enc_u64  ( &e, uri_sz );
    enc_bytes( &e, source_uri, uri_sz );
  }
  return enc_fini( &e, buf );
}

ulong
fd_gravity_encode_bundle_v2( uchar *               buf,
                             ulong                 buf_sz,
                             uchar const           ext_uuid[ static 32 ],
                             ulong                 txn_cnt,
                             uchar const * const * txn,
                             ulong const *         txn_sz,
                             char const *          source_uri,
                             ulong                 received_at,
                             ulong                 sent_at ) {
  if( FD_UNLIKELY( !txn_cnt || txn_cnt>FD_GRAVITY_MAX_TXN_PER_BUNDLE ) ) return 0UL;
  if( FD_UNLIKELY( !source_uri ) ) return 0UL;
  ulong uri_sz = strlen( source_uri );
  if( FD_UNLIKELY( uri_sz>FD_GRAVITY_URI_MAX ) ) return 0UL;
  if( FD_UNLIKELY( !is_utf8( (uchar const *)source_uri, uri_sz ) ) ) return 0UL;

  enc_t e = { buf, buf+buf_sz, 0 };
  enc_u32  ( &e, FD_GRAVITY_C2R_BUNDLE_V2 );
  enc_bytes( &e, ext_uuid, 32UL );
  enc_u64  ( &e, txn_cnt );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    if( FD_UNLIKELY( !txn_sz[i] ) ) return 0UL;
    enc_u64  ( &e, txn_sz[i] );
    enc_bytes( &e, txn[i], txn_sz[i] );
  }
  enc_u64  ( &e, uri_sz );
  enc_bytes( &e, source_uri, uri_sz );
  enc_u64  ( &e, received_at );
  enc_u64  ( &e, sent_at );
  return enc_fini( &e, buf );
}

ulong
fd_gravity_encode_exec_result( uchar *                          buf,
                               ulong                            buf_sz,
                               fd_gravity_exec_result_t const * r ) {
  int is_bundle = !!r->bundle_id;
  if( FD_UNLIKELY( is_bundle==!!r->sig_prefix_cnt ) ) return 0UL;
  if( FD_UNLIKELY( r->sig_prefix_cnt>FD_GRAVITY_MAX_TXN_PER_RESULT ) ) return 0UL;
  if( FD_UNLIKELY( !r->result_cnt || r->result_cnt>FD_GRAVITY_MAX_TXN_PER_RESULT ) ) return 0UL;

  enc_t e = { buf, buf+buf_sz, 0 };
  enc_u32  ( &e, FD_GRAVITY_C2R_EXEC_RESULT );
  enc_u64  ( &e, r->slot );
  enc_bytes( &e, r->uuid, FD_GRAVITY_UUID_SZ );
  if( is_bundle ) {
    enc_u32  ( &e, 1U );
    enc_bytes( &e, r->bundle_id, FD_GRAVITY_BUNDLE_ID_SZ );
  } else {
    enc_u32  ( &e, 0U );
    enc_u64  ( &e, r->sig_prefix_cnt );
    enc_bytes( &e, r->sig_prefixes, FD_GRAVITY_SIG_PREFIX_SZ*r->sig_prefix_cnt );
  }
  enc_u64( &e, r->result_cnt );
  for( ulong i=0UL; i<r->result_cnt; i++ ) {
    fd_gravity_result_t const * res = r->results+i;
    if( res->kind==FD_GRAVITY_RESULT_INCLUDED ) {
      enc_u32( &e, FD_GRAVITY_RESULT_INCLUDED );
      enc_u64( &e, res->slot );
      enc_u64( &e, res->cus  );
    } else {
      /* NONE (0) is not a valid NotIncluded reason and tags above
         SLOT_ENDED do not exist. */
      if( FD_UNLIKELY( res->kind!=FD_GRAVITY_RESULT_NOT_INCLUDED ) ) return 0UL;
      if( FD_UNLIKELY( !res->reason || res->reason>FD_GRAVITY_NI_SLOT_ENDED ) ) return 0UL;
      enc_u32( &e, FD_GRAVITY_RESULT_NOT_INCLUDED );
      enc_u32( &e, res->reason );
    }
  }
  enc_u64( &e, r->batch_received_at );
  enc_u64( &e, r->forwarded_at      );
  enc_u64( &e, r->res_received_at   );
  enc_u8 ( &e, r->worker            );
  return enc_fini( &e, buf );
}

/* RelayToConnector decoders *******************************************/

int
fd_gravity_decode_ping( uchar const * payload,
                        ulong         sz,
                        ulong *       seq ) {
  dec_t d = { payload, payload+sz, 0 };
  uint tag = dec_u32( &d );
  ulong s  = dec_u64( &d );
  if( FD_UNLIKELY( d.err || tag!=FD_GRAVITY_R2C_PING ) ) return -1;
  *seq = s;
  return 0;
}

/* dec_txn validates one WireSharableTx (u64 len, bytes).  An empty
   transaction is well formed on the wire (wincode accepts it and the
   relay forwards builder orders verbatim); like the Agave connector,
   it is rejected per order by the consumer, not per graph. */

static inline void
dec_txn( dec_t * d ) {
  ulong sz = dec_u64( d );
  if( FD_UNLIKELY( d->err ) ) return;
  dec_skip( d, sz );
}

int
fd_gravity_decode_graph( uchar const *        payload,
                         ulong                sz,
                         fd_gravity_graph_t * g ) {
  dec_t d = { payload, payload+sz, 0 };
  uint tag = dec_u32( &d );
  if( FD_UNLIKELY( d.err || tag!=FD_GRAVITY_R2C_MINI_BLOCK_GRAPH ) ) return -1;

  g->slot          = dec_u64( &d );
  g->index_in_slot = dec_u32( &d );
  uchar const * uuid = dec_skip( &d, FD_GRAVITY_UUID_SZ );
  if( FD_UNLIKELY( d.err ) ) return -1;
  fd_memcpy( g->uuid, uuid, FD_GRAVITY_UUID_SZ );

  /* CSR row offsets and column indices.  Counts are checked against the
     remaining bytes before multiplying, so they can't overflow. */
  ulong row_cnt = dec_u64( &d );
  if( FD_UNLIKELY( d.err || row_cnt>(ulong)(d.end-d.p)/4UL ) ) return -1;
  dec_skip( &d, 4UL*row_cnt );
  ulong col_cnt = dec_u64( &d );
  if( FD_UNLIKELY( d.err || col_cnt>(ulong)(d.end-d.p)/4UL ) ) return -1;
  dec_skip( &d, 4UL*col_cnt );

  ulong node_cnt = dec_u64( &d );
  if( FD_UNLIKELY( d.err || !node_cnt || node_cnt>(ulong)(d.end-d.p)/24UL ) ) return -1;
  if( FD_UNLIKELY( row_cnt!=node_cnt+1UL ) ) return -1;
  g->node_cnt = node_cnt;
  g->nodes    = d.p;
  for( ulong i=0UL; i<node_cnt; i++ ) {
    uint kind = dec_u32( &d );
    if( FD_UNLIKELY( d.err ) ) return -1;
    switch( kind ) {
    case FD_GRAVITY_NODE_TX:     dec_skip( &d, FD_GRAVITY_SIG_PREFIX_SZ ); break;
    case FD_GRAVITY_NODE_BUNDLE: dec_skip( &d, FD_GRAVITY_BUNDLE_ID_SZ  ); break;
    default: return -1;
    }
    dec_u32( &d ); /* depth */
    if( FD_UNLIKELY( d.err ) ) return -1;
  }
  g->nodes_end = d.p;

  ulong txn_cnt = dec_u64( &d );
  if( FD_UNLIKELY( d.err || txn_cnt>(ulong)(d.end-d.p)/8UL ) ) return -1;
  g->order_txn_cnt = txn_cnt;
  g->order_txns    = d.p;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    dec_txn( &d );
    if( FD_UNLIKELY( d.err ) ) return -1;
  }
  g->order_txns_end = d.p;

  ulong bundle_cnt = dec_u64( &d );
  if( FD_UNLIKELY( d.err || bundle_cnt>(ulong)(d.end-d.p)/40UL ) ) return -1;
  g->order_bundle_cnt = bundle_cnt;
  g->order_bundles    = d.p;
  for( ulong i=0UL; i<bundle_cnt; i++ ) {
    dec_skip( &d, FD_GRAVITY_BUNDLE_ID_SZ );
    ulong cnt = dec_u64( &d );
    if( FD_UNLIKELY( d.err || cnt>FD_GRAVITY_MAX_TXN_PER_BUNDLE ) ) return -1;
    for( ulong j=0UL; j<cnt; j++ ) {
      dec_txn( &d );
      if( FD_UNLIKELY( d.err ) ) return -1;
    }
  }
  g->order_bundles_end = d.p;

  /* wincode accepts trailing bytes, so we do too. */
  return 0;
}

uchar const *
fd_gravity_node_next( uchar const *       cur,
                      fd_gravity_node_t * node ) {
  node->kind = FD_LOAD( uint, cur );
  node->id   = cur+4UL;
  ulong id_sz = node->kind==FD_GRAVITY_NODE_TX ? FD_GRAVITY_SIG_PREFIX_SZ : FD_GRAVITY_BUNDLE_ID_SZ;
  node->depth = FD_LOAD( uint, cur+4UL+id_sz );
  return cur+4UL+id_sz+4UL;
}

uchar const *
fd_gravity_order_txn_next( uchar const *  cur,
                           uchar const ** txn,
                           ulong *        txn_sz ) {
  *txn_sz = FD_LOAD( ulong, cur );
  *txn    = cur+8UL;
  return cur+8UL+*txn_sz;
}

uchar const *
fd_gravity_order_bundle_next( uchar const *         cur,
                              fd_gravity_bundle_t * bundle ) {
  bundle->ext_uuid = cur;
  cur += FD_GRAVITY_BUNDLE_ID_SZ;
  bundle->txn_cnt = FD_LOAD( ulong, cur );
  cur += 8UL;
  for( ulong i=0UL; i<bundle->txn_cnt; i++ ) {
    cur = fd_gravity_order_txn_next( cur, bundle->txn+i, bundle->txn_sz+i );
  }
  return cur;
}

/* Misc ****************************************************************/

/* first_sig_off returns the offset of the first signature of a
   serialized legacy, v0 or v1 transaction (whose first need bytes must
   be in bounds), or ULONG_MAX if the layout is invalid. */

static ulong
first_sig_off( uchar const * txn,
               ulong         txn_sz,
               ulong         need ) {
  if( FD_UNLIKELY( !txn_sz ) ) return ULONG_MAX;
  uchar b0 = txn[0];
  ulong off;
  if( b0!=0U && !(b0&0x80U) ) {
    /* legacy or v0: one byte compact-u16 signature count, followed
       immediately by the signatures */
    off = 1UL;
  } else if( b0==0x81U ) {
    /* v1: version byte, signature count, signatures at the end */
    if( FD_UNLIKELY( txn_sz<2UL ) ) return ULONG_MAX;
    ulong nsig = (ulong)txn[1];
    if( FD_UNLIKELY( !nsig || 64UL*nsig>txn_sz ) ) return ULONG_MAX;
    off = txn_sz-64UL*nsig;
  } else {
    return ULONG_MAX;
  }
  if( FD_UNLIKELY( off+need>txn_sz ) ) return ULONG_MAX;
  return off;
}

uchar const *
fd_gravity_first_sig( uchar const * txn,
                      ulong         txn_sz ) {
  ulong off = first_sig_off( txn, txn_sz, 64UL );
  return off==ULONG_MAX ? NULL : txn+off;
}

int
fd_gravity_sig_prefix( uchar const * txn,
                       ulong         txn_sz,
                       uchar         out[ static FD_GRAVITY_SIG_PREFIX_SZ ] ) {
  ulong off = first_sig_off( txn, txn_sz, FD_GRAVITY_SIG_PREFIX_SZ );
  if( FD_UNLIKELY( off==ULONG_MAX ) ) return -1;
  fd_memcpy( out, txn+off, FD_GRAVITY_SIG_PREFIX_SZ );
  return 0;
}

void
fd_gravity_jito_bundle_id( uchar                 out[ static 32 ],
                           ulong                 cnt,
                           uchar const * const * sigs ) {
  fd_sha256_t sha[1];
  fd_sha256_init( sha );
  for( ulong i=0UL; i<cnt; i++ ) {
    char  b58[ FD_BASE58_ENCODED_64_SZ ];
    ulong b58_len;
    fd_base58_encode_64( sigs[i], &b58_len, b58 );
    if( i ) fd_sha256_append( sha, ",", 1UL );
    fd_sha256_append( sha, b58, b58_len );
  }
  fd_sha256_fini( sha, out );
}

uint
fd_gravity_reason_from_txn_err( int err ) {
  if( err>=-38 && err<=-1 ) return (uint)(2-err);
  switch( err ) {
  case FD_RUNTIME_TXN_ERR_BUNDLE_PEER:                       return FD_GRAVITY_NI_ALL_OR_NOTHING;
  case FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED:
  case FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR:
  case FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE:        return FD_GRAVITY_NI_BLOCKHASH_NOT_FOUND;
  default:                                                   return FD_GRAVITY_NI_SANITIZE_FAILURE;
  }
}
