/* test_gravity drives fd_gravity against a real fd_pack object.  The
   relay is never polled: the session is forced READY (with no socket)
   so the client queues ConnectorToRelay frames in the session transmit
   buffer, which the test decodes after each step.  Relay frames are
   injected with fd_gravity_handle_frame.  The execle tiles are
   emulated by calling fd_gravity_on_executed the way the pack tile does
   for execle_poh frags: one frag per microblock, one frag per bundle
   transaction (pack_idx+i). */

#include "fd_gravity.h"
#include "../fd_pack_cost.h"
#include "../fd_compute_budget_program.h"
#include "../../fd_txn_m.h"
#include "../../metrics/fd_metrics.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../../flamenco/runtime/fd_runtime_err.h"
#include "../../../util/net/fd_ip4.h"

#include <stdlib.h>

#define PACK_DEPTH   (1024UL)
#define BANK_CNT     (2UL)
#define RX_MAX       (1UL<<20)
#define TX_MAX       (1UL<<20)
#define RET_SZ       (1UL<<20)
#define SLOT_NS      (400000000L)
#define JITO_TEST_REFWD_NS (10000000000L) /* fd_gravity.c's JITO_REFWD_NS */
#define T0           (1700000000000000000L)
#define WORKER       ((uchar)3)
#define MAX_COST     (48000000UL)

#define OK_FLAGS     (FD_TXN_P_FLAGS_EXECUTE_SUCCESS | FD_TXN_P_FLAGS_SANITIZE_SUCCESS)
#define ERR_FLAGS(e) (((uint)(-(e)))<<24)

static uchar     metrics_scratch[ FD_METRICS_FOOTPRINT( 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
static fd_rng_t  _rng[1];
static fd_rng_t * rng;

static long slot_start( ulong slot ) { return T0 + (long)slot*SLOT_NS; }
static long slot_end  ( ulong slot ) { return slot_start( slot+1UL ); }

/* Transactions ********************************************************/

static void
compact_u16( uchar ** p,
             ulong    v ) {
  FD_TEST( v<0x4000UL );
  if( v<0x80UL ) { *(*p)++ = (uchar)v; return; }
  *(*p)++ = (uchar)( (v&0x7FUL)|0x80UL );
  *(*p)++ = (uchar)( v>>7 );
}

#define MK_ALT (1)  /* v0 transaction with one address lookup table */
#define MK_DUP (2)  /* writable account duplicates the fee payer */

/* make_txn serializes a valid transaction into out and returns its
   size: fee payer, one writable account (32 bytes of w), the compute
   budget program (unit limit and price) and a dummy program called
   with pad+1 bytes of data.  The signature and fee payer derive from
   id, so different ids never collide. */

static ulong
make_txn( uchar * out,
          ulong   id,
          uchar   w,
          ulong   pad,
          int     opt ) {
  uchar * p = out;
  *p++ = 1; /* signature count */
  memset( p, 0x5A, 64UL ); FD_STORE( ulong, p, id ); FD_STORE( ulong, p+56, id ); p += 64UL;
  if( opt & MK_ALT ) *p++ = 0x80;
  *p++ = 1; *p++ = 0; *p++ = 2; /* 1 signer, 0 readonly signed, 2 readonly unsigned */
  *p++ = 4;
  uchar * payer = p;
  memset( p, 'F', 32UL ); FD_STORE( ulong, p, id ); p += 32UL;
  if( opt & MK_DUP ) fd_memcpy( p, payer, 32UL );
  else               memset( p, w, 32UL );
  p += 32UL;
  fd_memcpy( p, FD_COMPUTE_BUDGET_PROGRAM_ID, 32UL ); p += 32UL;
  memset( p, 'P', 32UL ); p += 32UL;
  memset( p, 'B', 32UL ); p += 32UL; /* recent blockhash */
  *p++ = 3;
  *p++ = 2; *p++ = 0; *p++ = 5; *p++ = 2; FD_STORE( uint,  p, 50000U ); p += 4UL; /* SetComputeUnitLimit */
  *p++ = 2; *p++ = 0; *p++ = 9; *p++ = 3; FD_STORE( ulong, p, 1000UL ); p += 8UL; /* SetComputeUnitPrice */
  *p++ = 3; *p++ = 1; *p++ = 1; compact_u16( &p, pad+1UL ); memset( p, 0x77, pad+1UL ); p += pad+1UL;
  if( opt & MK_ALT ) {
    *p++ = 1;
    memset( p, 'T', 32UL ); p += 32UL;
    *p++ = 1; *p++ = 0; /* one writable lookup */
    *p++ = 0;           /* no readonly lookups */
  }
  ulong sz = (ulong)(p-out);
  uchar txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  FD_TEST( fd_txn_parse( out, sz, txn_buf, NULL ) );
  return sz;
}

/* The SigPrefix of a transaction built by make_txn */

static uchar const *
prefix_of( uchar const * txn ) {
  return txn+1UL;
}

/* Builder transaction bytes */

struct btxn {
  uchar b[ FD_TPU_MTU ];
  ulong sz;
};
typedef struct btxn btxn_t;

static void
btxn( btxn_t * t,
      ulong    id,
      uchar    w,
      int      opt ) {
  t->sz = make_txn( t->b, id, w, 0UL, opt );
}

/* make_txne builds a fully populated pack transaction, as pack gets it
   from resolv. */

static void
make_txne( fd_txn_e_t * e,
           ulong        id,
           uchar        w,
           ulong        pad,
           int          opt ) {
  fd_txn_p_t * t = e->txnp;
  t->payload_sz = (ushort)make_txn( t->payload, id, w, pad, opt );
  FD_TEST( fd_txn_parse( t->payload, t->payload_sz, TXN( t ), NULL ) );
  t->source_tpu       = (uchar)FD_TXN_M_TPU_SOURCE_QUIC;
  t->source_ipv4      = FD_IP4_ADDR( 10, 0, 0, 1 );
  t->first_seen_nanos = 111L;
  t->flags            = 0U;
  if( opt & MK_ALT ) memset( e->alt_accts[0].b, 'A', 32UL );
}

static int
insert_native( fd_pack_t *        pack,
               fd_txn_e_t const * e ) {
  fd_txn_e_t * slot = fd_pack_insert_txn_init( pack );
  fd_memcpy( slot, e, sizeof(fd_txn_e_t) );
  ulong deleted;
  return fd_pack_insert_txn_fini( pack, slot, 100000UL, &deleted );
}

/* Relay frames ********************************************************/

typedef struct { uchar * p; } wr_t;

static void w_u32  ( wr_t * w, uint  v ) { FD_STORE( uint,  w->p, v ); w->p += 4UL; }
static void w_u64  ( wr_t * w, ulong v ) { FD_STORE( ulong, w->p, v ); w->p += 8UL; }
static void w_bytes( wr_t * w, void const * b, ulong sz ) { fd_memcpy( w->p, b, sz ); w->p += sz; }

/* graph_hdr writes a MiniBlockGraph up to and including the node count
   (CSR without edges). */

static void
graph_hdr( wr_t *      w,
           ulong       slot,
           uchar const uuid[ 16 ],
           ulong       node_cnt ) {
  w_u32  ( w, FD_GRAVITY_R2C_MINI_BLOCK_GRAPH );
  w_u64  ( w, slot );
  w_u32  ( w, 0U );
  w_bytes( w, uuid, 16UL );
  w_u64  ( w, node_cnt+1UL );
  for( ulong i=0UL; i<=node_cnt; i++ ) w_u32( w, 0U );
  w_u64  ( w, 0UL );
  w_u64  ( w, node_cnt );
}

static void
graph_node( wr_t *        w,
            uint          kind,
            uchar const * id ) {
  w_u32  ( w, kind );
  w_bytes( w, id, kind==FD_GRAVITY_NODE_TX ? 16UL : 32UL );
  w_u32  ( w, 1U ); /* depth */
}

static void
graph_txn( wr_t *         w,
           btxn_t const * t ) {
  w_u64  ( w, t->sz );
  w_bytes( w, t->b, t->sz );
}

static void
graph_bundle( wr_t *         w,
              uchar const    id[ 32 ],
              btxn_t const * t,
              ulong          cnt ) {
  w_bytes( w, id, 32UL );
  w_u64  ( w, cnt );
  for( ulong i=0UL; i<cnt; i++ ) graph_txn( w, t+i );
}

static uchar frame[ 1UL<<16 ];

static void
send_frame( fd_gravity_t * g,
            fd_pack_t *    pack,
            wr_t *         w,
            long           now ) {
  fd_gravity_handle_frame( g, pack, NULL, frame, (ulong)(w->p-frame), now );
}

/* Client frames *******************************************************/

typedef struct {
  uint          tag;
  ulong         sz;
  uchar const * p;
} msg_t;

#define MSG_MAX (1024UL)
static msg_t msgs[ MSG_MAX ];
static uchar msg_buf[ TX_MAX ];

/* take_msgs moves every frame the client queued for the relay out of
   the session transmit buffer and returns how many there were. */

static ulong
take_msgs( fd_gravity_sess_t * sess ) {
  ulong rem = sess->tx_hi-sess->tx_lo;
  fd_memcpy( msg_buf, sess->tx+sess->tx_lo, rem );
  sess->tx_lo = 0UL;
  sess->tx_hi = 0UL;
  ulong cnt = 0UL;
  ulong off = 0UL;
  while( off<rem ) {
    FD_TEST( rem-off>=FD_GRAVITY_FRAME_HDR_SZ );
    ulong sz = fd_gravity_frame_hdr_payload_sz( msg_buf+off );
    FD_TEST( sz>=4UL && rem-off-FD_GRAVITY_FRAME_HDR_SZ>=sz );
    FD_TEST( cnt<MSG_MAX );
    msgs[ cnt ].p   = msg_buf+off+FD_GRAVITY_FRAME_HDR_SZ;
    msgs[ cnt ].sz  = sz;
    msgs[ cnt ].tag = FD_LOAD( uint, msgs[ cnt ].p );
    cnt++;
    off += FD_GRAVITY_FRAME_HDR_SZ+sz;
  }
  return cnt;
}

typedef struct { uchar const * p; uchar const * end; } rd_t;

static uchar const * rd_skip( rd_t * r, ulong sz ) { FD_TEST( (ulong)(r->end-r->p)>=sz ); uchar const * q = r->p; r->p += sz; return q; }
static uchar rd_u8 ( rd_t * r ) { return *rd_skip( r, 1UL ); }
static uint  rd_u32( rd_t * r ) { return FD_LOAD( uint,  rd_skip( r, 4UL ) ); }
static ulong rd_u64( rd_t * r ) { return FD_LOAD( ulong, rd_skip( r, 8UL ) ); }

typedef struct {
  ulong slot;
  ulong observed_at;
  uchar pct;
  int   has_dur;
  int   has_next;
  ulong next_start;
  ulong next_end;
  int   has_bh;
  uchar bh[ 32 ];
} progress_t;

static void
dec_progress( msg_t const * m,
              progress_t *  out ) {
  rd_t r = { m->p, m->p+m->sz };
  FD_TEST( rd_u32( &r )==FD_GRAVITY_C2R_PROGRESS );
  out->slot        = rd_u64( &r );
  out->observed_at = rd_u64( &r );
  out->pct         = rd_u8 ( &r );
  out->has_dur     = rd_u8 ( &r ); FD_TEST( out->has_dur<=1 );
  if( out->has_dur ) rd_u64( &r );
  out->has_next    = rd_u8 ( &r ); FD_TEST( out->has_next<=1 );
  if( out->has_next ) { out->next_start = rd_u64( &r ); out->next_end = rd_u64( &r ); }
  out->has_bh      = rd_u8 ( &r ); FD_TEST( out->has_bh<=1 );
  if( out->has_bh ) fd_memcpy( out->bh, rd_skip( &r, 32UL ), 32UL );
  FD_TEST( r.p==r.end );
}

typedef struct {
  ulong slot;
  uchar uuid[ 16 ];
  int   is_bundle;
  uchar bundle_id[ 32 ];
  ulong sig_cnt;
  uchar sig[ 16 ][ 16 ];
  ulong res_cnt;
  uint  kind  [ 16 ];
  uint  reason[ 16 ];
  ulong rslot [ 16 ];
  ulong cus   [ 16 ];
  ulong batch_received_at;
  ulong forwarded_at;
  ulong res_received_at;
  uchar worker;
} result_t;

static void
dec_result( msg_t const * m,
            result_t *    out ) {
  rd_t r = { m->p, m->p+m->sz };
  FD_TEST( rd_u32( &r )==FD_GRAVITY_C2R_EXEC_RESULT );
  out->slot = rd_u64( &r );
  fd_memcpy( out->uuid, rd_skip( &r, 16UL ), 16UL );
  uint orders = rd_u32( &r );
  FD_TEST( orders<=1U );
  out->is_bundle = (int)orders;
  out->sig_cnt   = 0UL;
  if( orders ) {
    fd_memcpy( out->bundle_id, rd_skip( &r, 32UL ), 32UL );
  } else {
    out->sig_cnt = rd_u64( &r ); FD_TEST( out->sig_cnt>=1UL && out->sig_cnt<=16UL );
    for( ulong i=0UL; i<out->sig_cnt; i++ ) fd_memcpy( out->sig[i], rd_skip( &r, 16UL ), 16UL );
  }
  out->res_cnt = rd_u64( &r ); FD_TEST( out->res_cnt>=1UL && out->res_cnt<=16UL );
  for( ulong i=0UL; i<out->res_cnt; i++ ) {
    out->kind[i] = rd_u32( &r );
    if( out->kind[i]==FD_GRAVITY_RESULT_INCLUDED ) {
      out->rslot[i] = rd_u64( &r );
      out->cus  [i] = rd_u64( &r );
    } else {
      FD_TEST( out->kind[i]==FD_GRAVITY_RESULT_NOT_INCLUDED );
      out->reason[i] = rd_u32( &r );
      FD_TEST( out->reason[i]>=1U && out->reason[i]<=FD_GRAVITY_NI_SLOT_ENDED );
    }
  }
  out->batch_received_at = rd_u64( &r );
  out->forwarded_at      = rd_u64( &r );
  out->res_received_at   = rd_u64( &r );
  out->worker            = rd_u8 ( &r );
  FD_TEST( r.p==r.end );
}

typedef struct {
  ulong         txn_sz;
  uchar const * txn;
  ulong         sent_at;
  ulong         received_at;
  uchar         src[ 16 ];
  int           has_uri;
} fwd_t;

static void
dec_transaction( msg_t const * m,
                 fwd_t *       out ) {
  rd_t r = { m->p, m->p+m->sz };
  FD_TEST( rd_u32( &r )==FD_GRAVITY_C2R_TRANSACTION );
  out->txn_sz      = rd_u64( &r );
  out->txn         = rd_skip( &r, out->txn_sz );
  out->sent_at     = rd_u64( &r );
  out->received_at = rd_u64( &r );
  fd_memcpy( out->src, rd_skip( &r, 16UL ), 16UL );
  out->has_uri     = rd_u8( &r );
  FD_TEST( !out->has_uri );
  FD_TEST( r.p==r.end );
}

static int
msg_is_bundle_result( msg_t const * m ) {
  FD_TEST( m->tag==FD_GRAVITY_C2R_EXEC_RESULT && m->sz>=32UL );
  return FD_LOAD( uint, m->p+28UL )==1U;
}

/* check_tx_result checks m is a result for the transaction node with
   SigPrefix prefix from graph (slot,uuid) with a single result. */

static void
check_tx_result( msg_t const * m,
                 ulong         slot,
                 uchar const * uuid,
                 uchar const * prefix,
                 result_t *    r ) {
  dec_result( m, r );
  FD_TEST( r->slot==slot );
  FD_TEST( !memcmp( r->uuid, uuid, 16UL ) );
  FD_TEST( !r->is_bundle && r->sig_cnt==1UL && !memcmp( r->sig[0], prefix, 16UL ) );
  FD_TEST( r->res_cnt==1UL );
}

static void
check_tx_reject( msg_t const * m,
                 ulong         slot,
                 uchar const * uuid,
                 uchar const * prefix,
                 uint          reason ) {
  result_t r;
  check_tx_result( m, slot, uuid, prefix, &r );
  FD_TEST( r.kind[0]==FD_GRAVITY_RESULT_NOT_INCLUDED && r.reason[0]==reason );
  FD_TEST( r.worker==FD_GRAVITY_WORKER_SYNTHETIC && !r.forwarded_at && !r.res_received_at );
}

/* check_bundle_reject checks a bundle node result whose reasons are
   reasons[0,cnt). */

static void
check_bundle_reject( msg_t const * m,
                     ulong         slot,
                     uchar const * uuid,
                     uchar const * id,
                     ulong         cnt,
                     uint const *  reasons ) {
  result_t r;
  dec_result( m, &r );
  FD_TEST( r.slot==slot && !memcmp( r.uuid, uuid, 16UL ) );
  FD_TEST( r.is_bundle && !memcmp( r.bundle_id, id, 32UL ) );
  FD_TEST( r.res_cnt==cnt );
  for( ulong i=0UL; i<cnt; i++ ) FD_TEST( r.kind[i]==FD_GRAVITY_RESULT_NOT_INCLUDED && r.reason[i]==reasons[i] );
}

/* Environment *********************************************************/

typedef struct {
  void *              pack_mem;
  void *              verify_mem;
  fd_pack_t *         pack;
  void *              g_mem;
  fd_gravity_t *      g;
  fd_gravity_sess_t * sess;
} env_t;

static long env_warmup_ns = 0L; /* warmup_ns of new envs */

static void
env_new( env_t * env,
         ulong   retention_sz,
         ulong   node_max ) {
  fd_pack_limits_t limits[1] = {{
    .max_cost_per_block           = MAX_COST,
    .max_write_cost_per_acct      = 12000000UL,
    .max_data_bytes_per_block     = 5UL<<20,
    .max_txn_per_microblock       = 31UL,
    .max_microblocks_per_block    = 32768UL,
    .max_allocated_data_per_block = FD_PACK_MAX_ALLOCATED_DATA_PER_BLOCK,
  }};
  ulong pack_fp = fd_ulong_align_up( fd_pack_footprint( PACK_DEPTH, 1UL, BANK_CNT, limits ), fd_pack_align() );
  env->pack_mem   = aligned_alloc( fd_pack_align(), pack_fp );
  env->verify_mem = aligned_alloc( fd_pack_align(), pack_fp );
  FD_TEST( env->pack_mem && env->verify_mem );
  env->pack = fd_pack_join( fd_pack_new( env->pack_mem, PACK_DEPTH, 1UL, BANK_CNT, limits, NULL, 0UL, rng ) );
  FD_TEST( env->pack );

  fd_gravity_cfg_t cfg[1];
  memset( cfg, 0, sizeof(cfg) );
  memset( cfg->identity, 'I', 32UL );
  cfg->relay_cnt           = 1UL;
  cfg->relay_ip4[0]        = FD_IP4_ADDR( 127, 0, 0, 1 );
  cfg->relay_port[0]       = 1;
  cfg->rx_max              = RX_MAX;
  cfg->tx_max              = TX_MAX;
  cfg->retention_sz        = retention_sz;
  cfg->node_max            = node_max;
  cfg->order_max           = 64UL;
  cfg->num_threads         = 2;
  cfg->jito_tip_weight_bps = 10000;
  cfg->warmup_ns           = env_warmup_ns;
  cfg->bundle_meta_sz      = 1UL; /* as the test's pack */
  fd_cstr_ncpy( cfg->version,    "test",           sizeof(cfg->version)    );
  fd_cstr_ncpy( cfg->bundle_uri, "http://be.test", sizeof(cfg->bundle_uri) );
  cfg->blacklist_cnt       = 1UL;
  memset( cfg->blacklist[0], 'B', 32UL );

  ulong g_fp = fd_ulong_align_up( fd_gravity_footprint( cfg ), fd_gravity_align() );
  env->g_mem = aligned_alloc( fd_gravity_align(), g_fp );
  FD_TEST( env->g_mem );
  FD_TEST( !fd_gravity_new( (uchar *)env->g_mem+8UL, cfg ) ); /* misaligned */
  env->g = fd_gravity_new( env->g_mem, cfg );
  FD_TEST( env->g );
  env->sess = fd_gravity_sess( env->g );
  FD_TEST( env->sess->state==FD_GRAVITY_SESS_STATE_IDLE && env->sess->fd==-1 );
}

static void
env_delete( env_t * env ) {
  FD_TEST( !fd_pack_verify( env->pack, env->verify_mem ) );
  fd_pack_delete( fd_pack_leave( env->pack ) );
  free( env->pack_mem   );
  free( env->verify_mem );
  free( env->g_mem      );
}

/* env_ready forces the session READY (or not) without a socket */

static void
env_ready( env_t * env,
           int     ready ) {
  env->sess->state = ready ? FD_GRAVITY_SESS_STATE_READY : FD_GRAVITY_SESS_STATE_IDLE;
  env->sess->fd    = -1;
}

static int
lead( env_t * env,
      ulong   slot ) {
  return fd_gravity_became_leader( env->g, env->pack, slot, slot_start( slot ), slot_end( slot ),
                                   1000UL+slot, 0, slot_start( slot )+1000L );
}

/* end_slot ends a leader slot the way the pack tile does */

static void
end_slot( env_t * env,
          ulong   slot ) {
  fd_pack_end_block( env->pack );
  fd_gravity_slot_end( env->g, env->pack, 0, slot_end( slot ) );
}

static fd_txn_e_t sched_out[ 64 ];
static long       sched_now = 7000L; /* dispatch time sched reports */

/* sched schedules the next bundle on execle 0 and reports it to
   gravity, as the pack tile's after_credit does. */

static ulong
sched( env_t * env,
       uint    pack_idx ) {
  fd_pack_microblock_complete( env->pack, 0UL );
  ulong cnt = fd_pack_schedule_next_microblock( env->pack, MAX_COST, 0UL, FD_PACK_SCHEDULE_BUNDLE, sched_out );
  if( cnt && (sched_out[0].txnp->flags & FD_TXN_P_FLAGS_BUNDLE) ) {
    fd_gravity_on_schedule( env->g, env->pack, sched_out, cnt, pack_idx, sched_now );
  }
  return cnt;
}

static void
exec1( env_t * env,
       ulong   slot,
       uint    pack_idx,
       uint    flags,
       uint    cus,
       long    now ) {
  fd_gravity_on_executed( env->g, slot, pack_idx, 1UL, &flags, &cus, WORKER, now );
}

static fd_gravity_metrics_t const *
metrics( env_t * env ) {
  return fd_gravity_metrics( env->g );
}

static uchar const uuid1[ 16 ] = { 0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11 };
static uchar const uuid2[ 16 ] = { 0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22 };
static uchar const uuid3[ 16 ] = { 0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33 };

static void
bundle_id( uchar id[ 32 ],
           uchar v ) {
  memset( id, v, 32UL );
}

static fd_txn_e_t txne[ 8 ];

/* a. Leader windows ***************************************************/

static void
test_window_mode( void ) {
  FD_LOG_NOTICE(( "TEST WINDOW MODE" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  progress_t p;

  /* Not leader yet */
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );

  /* Window 8..11 starts with a READY session: GRAVITY */
  env_ready( env, 1 );
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( take_msgs( env->sess )==1UL );
  dec_progress( msgs, &p );
  FD_TEST( p.slot==8UL && p.observed_at==(ulong)slot_start( 8UL ) && p.pct==0 && !p.has_dur && !p.has_bh );
  FD_TEST( p.has_next && p.next_start==8UL && p.next_end==11UL );
  end_slot( env, 8UL );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( take_msgs( env->sess )==0UL );

  /* Same window keeps the mode */
  FD_TEST( lead( env, 9UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( take_msgs( env->sess )==1UL );
  dec_progress( msgs, &p );
  FD_TEST( p.slot==9UL && p.observed_at==(ulong)slot_start( 9UL ) && p.has_next && p.next_start==8UL && p.next_end==11UL );
  end_slot( env, 9UL );
  FD_TEST( metrics( env )->windows_gravity==1UL && metrics( env )->windows_native==0UL );

  /* Window 12..15 starts without a session: NATIVE for the whole window,
     even once the session is back */
  env_ready( env, 0 );
  FD_TEST( lead( env, 12UL )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  end_slot( env, 12UL );
  FD_TEST( take_msgs( env->sess )==0UL );
  env_ready( env, 1 );
  FD_TEST( lead( env, 13UL )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( take_msgs( env->sess )==1UL ); /* Progress keeps the relay's clock right in NATIVE windows */
  dec_progress( msgs, &p );
  FD_TEST( p.slot==13UL && p.next_start==12UL && p.next_end==15UL );
  end_slot( env, 13UL );
  FD_TEST( lead( env, 15UL )==FD_GRAVITY_MODE_NATIVE );
  end_slot( env, 15UL );
  FD_TEST( metrics( env )->windows_gravity==1UL && metrics( env )->windows_native==1UL );

  /* The next window re-decides */
  FD_TEST( lead( env, 16UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( metrics( env )->windows_gravity==2UL );
  end_slot( env, 16UL );

  /* The session drops between two slots of a GRAVITY window: the rest
     of the window is NATIVE right from the next slot */
  env_ready( env, 0 );
  FD_TEST( lead( env, 17UL )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( metrics( env )->fallback_session==1UL );
  end_slot( env, 17UL );
  env_ready( env, 1 );
  FD_TEST( lead( env, 18UL )==FD_GRAVITY_MODE_NATIVE );
  end_slot( env, 18UL );
  FD_TEST( lead( env, 20UL )==FD_GRAVITY_MODE_GRAVITY );
  end_slot( env, 20UL );
  FD_TEST( metrics( env )->windows_gravity==3UL && metrics( env )->windows_native==1UL );
  FD_TEST( metrics( env )->fallback_session==1UL );
  take_msgs( env->sess );

  env_delete( env );
}

/* b. Forwarding and retention *****************************************/

static void
test_forwarding( void ) {
  FD_LOG_NOTICE(( "TEST FORWARDING" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );

  /* A forwarded transaction carries its payload and source address */
  make_txne( txne+0, 1UL, 'a', 0UL, 0 );
  fd_gravity_on_txn( env->g, txne+0, 0UL, 222L );
  FD_TEST( take_msgs( env->sess )==1UL );
  fwd_t f;
  dec_transaction( msgs, &f );
  FD_TEST( f.txn_sz==txne[0].txnp->payload_sz && !memcmp( f.txn, txne[0].txnp->payload, f.txn_sz ) );
  FD_TEST( f.sent_at==222UL && f.received_at==111UL );
  static uchar const src[ 16 ] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,10,0,0,1 };
  FD_TEST( !memcmp( f.src, src, 16UL ) );
  FD_TEST( metrics( env )->txn_forwarded==1UL );

  /* An unknown source address is all zeros */
  static fd_txn_e_t anon[1];
  make_txne( anon, 900UL, 'z', 0UL, 0 );
  anon->txnp->source_ipv4 = 0U;
  fd_gravity_on_txn( env->g, anon, 0UL, 222L );
  FD_TEST( take_msgs( env->sess )==1UL );
  dec_transaction( msgs, &f );
  static uchar const zero[ 16 ] = {0};
  FD_TEST( !memcmp( f.src, zero, 16UL ) );
  FD_TEST( metrics( env )->txn_forwarded==2UL );

  /* Without a session it is retained but not forwarded */
  env_ready( env, 0 );
  make_txne( txne+1, 2UL, 'b', 0UL, 0 );
  fd_gravity_on_txn( env->g, txne+1, 0UL, 223L );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( metrics( env )->txn_forwarded==2UL );
  env_ready( env, 1 );

  /* A v0 transaction with resolved lookup table accounts */
  make_txne( txne+2, 3UL, 'c', 0UL, MK_ALT );
  fd_gravity_on_txn( env->g, txne+2, 0UL, 224L );
  FD_TEST( take_msgs( env->sess )==1UL );

  /* All three resolve by SigPrefix */
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  wr_t w = { frame };
  graph_hdr( &w, 8UL, uuid1, 3UL );
  for( ulong i=0UL; i<3UL; i++ ) graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( txne[i].txnp->payload ) );
  w_u64( &w, 0UL ); w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, slot_start( 8UL )+10L );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( metrics( env )->retention_hit==3UL && metrics( env )->nodes_inserted==3UL );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==3UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( sched( env, (uint)i )==1UL );
    fd_txn_p_t const * t = sched_out[0].txnp;
    FD_TEST( t->payload_sz==txne[i].txnp->payload_sz && !memcmp( t->payload, txne[i].txnp->payload, t->payload_sz ) );
    FD_TEST( t->source_ipv4==txne[i].txnp->source_ipv4 && t->source_tpu==txne[i].txnp->source_tpu );
    FD_TEST( t->first_seen_nanos==111L );
    FD_TEST( TXN( t )->instr_cnt==3 && TXN( t )->addr_table_lookup_cnt==(i==2UL ? 1 : 0) );
    if( i==2UL ) FD_TEST( !memcmp( sched_out[0].alt_accts[0].b, txne[2].alt_accts[0].b, 32UL ) );
  }
  end_slot( env, 8UL );
  env_delete( env );

  /* Retention ring wrap: 1 MiB ring, ~1.3 KB records */
  env_new( env, RET_SZ, 64UL );
  make_txne( txne+0, 100UL, 'a', 900UL, 0 );
  fd_gravity_on_txn( env->g, txne+0, 0UL, 1L );
  ulong const fill = 1000UL;
  for( ulong i=0UL; i<fill; i++ ) {
    make_txne( txne+1, 1000UL+i, 'b', 900UL, 0 );
    fd_gravity_on_txn( env->g, txne+1, 0UL, 2L );
  }
  env_ready( env, 1 );
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  uchar newest[ 2 ][ 16 ];
  make_txne( txne+1, 1000UL+fill-1UL, 'b', 900UL, 0 ); fd_memcpy( newest[0], prefix_of( txne[1].txnp->payload ), 16UL );
  make_txne( txne+1, 1000UL+fill-2UL, 'b', 900UL, 0 ); fd_memcpy( newest[1], prefix_of( txne[1].txnp->payload ), 16UL );
  w.p = frame;
  graph_hdr( &w, 8UL, uuid1, 3UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( txne[0].txnp->payload ) );
  graph_node( &w, FD_GRAVITY_NODE_TX, newest[0] );
  graph_node( &w, FD_GRAVITY_NODE_TX, newest[1] );
  w_u64( &w, 0UL ); w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, slot_start( 8UL )+10L );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_reject( msgs, 8UL, uuid1, prefix_of( txne[0].txnp->payload ), FD_GRAVITY_NI_UNKNOWN_ORDERS );
  FD_TEST( metrics( env )->retention_miss==1UL && metrics( env )->retention_hit==2UL );
  FD_TEST( metrics( env )->nodes_inserted==2UL && fd_pack_avail_txn_cnt( env->pack )==2UL );
  end_slot( env, 8UL );
  /* The purged lane nodes' forwarded transactions are back in pack as
     native transactions */
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==2UL );
  env_delete( env );
}

/* c. Graph intake and results *****************************************/

static void
test_graph_intake( void ) {
  FD_LOG_NOTICE(( "TEST GRAPH INTAKE" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );
  result_t r;

  /* T1 is forwarded and also pending in pack natively */
  make_txne( txne+0, 1UL, 'a', 0UL, 0 );
  fd_gravity_on_txn( env->g, txne+0, 0UL, 1L );
  FD_TEST( insert_native( env->pack, txne+0 )>=0 );
  take_msgs( env->sess );

  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );

  static btxn_t t2, b1[ 2 ];
  btxn( &t2,   2UL, 'b', 0 );
  btxn( b1+0,  3UL, 'c', 0 );
  btxn( b1+1,  4UL, 'd', 0 );
  uchar id1[ 32 ]; bundle_id( id1, 0xB1 );

  /* (1) forwarded Tx, (2) Tx with builder bytes, (3) 2 txn bundle */
  long recv = slot_start( 8UL )+5000L;
  wr_t w = { frame };
  graph_hdr ( &w, 8UL, uuid1, 3UL );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( txne[0].txnp->payload ) );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t2.b ) );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id1 );
  w_u64( &w, 1UL ); graph_txn( &w, &t2 );
  w_u64( &w, 1UL ); graph_bundle( &w, id1, b1, 2UL );
  send_frame( env->g, env->pack, &w, recv );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( metrics( env )->graphs==1UL && metrics( env )->nodes_inserted==3UL && metrics( env )->nodes_rejected==0UL );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==5UL ); /* native T1 + lane T1, T2, T3, T4 */

  /* Bundles schedule in node order.  Tx nodes lose the bundle flag. */
  FD_TEST( sched( env, 100U )==1UL );
  FD_TEST( !memcmp( sched_out[0].txnp->payload, txne[0].txnp->payload, txne[0].txnp->payload_sz ) );
  FD_TEST( !(sched_out[0].txnp->flags & FD_TXN_P_FLAGS_BUNDLE) );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==3UL ); /* native T1 deleted */
  FD_TEST( sched( env, 101U )==1UL );
  FD_TEST( sched_out[0].txnp->payload_sz==t2.sz && !memcmp( sched_out[0].txnp->payload, t2.b, t2.sz ) );
  FD_TEST( !(sched_out[0].txnp->flags & FD_TXN_P_FLAGS_BUNDLE) );
  FD_TEST( sched_out[0].txnp->source_tpu==FD_TXN_M_TPU_SOURCE_BUNDLE );
  FD_TEST( sched( env, 102U )==2UL );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( !memcmp( sched_out[i].txnp->payload, b1[i].b, b1[i].sz ) );
    FD_TEST( sched_out[i].txnp->flags & FD_TXN_P_FLAGS_BUNDLE );
  }
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==0UL );
  FD_TEST( sched( env, 104U )==0UL );
  FD_TEST( !fd_gravity_is_inflight( env->g, 99U  ) );
  for( uint i=100U; i<104U; i++ ) FD_TEST( fd_gravity_is_inflight( env->g, i ) );
  FD_TEST( !fd_gravity_is_inflight( env->g, 104U ) );

  /* (1) lands */
  long now = slot_start( 8UL )+9000L;
  exec1( env, 8UL, 100U, OK_FLAGS, 1500U, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_result( msgs, 8UL, uuid1, prefix_of( txne[0].txnp->payload ), &r );
  FD_TEST( r.kind[0]==FD_GRAVITY_RESULT_INCLUDED && r.rslot[0]==8UL && r.cus[0]==1500UL );
  FD_TEST( r.worker==WORKER && r.batch_received_at==(ulong)recv && r.res_received_at==(ulong)now );
  FD_TEST( r.forwarded_at==(ulong)sched_now );
  FD_TEST( !fd_gravity_is_inflight( env->g, 100U ) );

  /* (2) fails before paying fees */
  exec1( env, 8UL, 101U, ERR_FLAGS( FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE ), 0U, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_result( msgs, 8UL, uuid1, prefix_of( t2.b ), &r );
  FD_TEST( r.kind[0]==FD_GRAVITY_RESULT_NOT_INCLUDED && r.reason[0]==FD_GRAVITY_NI_INSUFFICIENT_FUNDS_FOR_FEE );

  /* (3) execle publishes each bundle transaction separately: one
     result with both outcomes once the second arrives */
  exec1( env, 8UL, 102U, OK_FLAGS, 2000U, now );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( fd_gravity_is_inflight( env->g, 103U ) );
  exec1( env, 8UL, 103U, OK_FLAGS, 3000U, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  dec_result( msgs, &r );
  FD_TEST( r.slot==8UL && !memcmp( r.uuid, uuid1, 16UL ) && r.is_bundle && !memcmp( r.bundle_id, id1, 32UL ) );
  FD_TEST( r.res_cnt==2UL );
  FD_TEST( r.kind[0]==FD_GRAVITY_RESULT_INCLUDED && r.rslot[0]==8UL && r.cus[0]==2000UL );
  FD_TEST( r.kind[1]==FD_GRAVITY_RESULT_INCLUDED && r.rslot[1]==8UL && r.cus[1]==3000UL );
  FD_TEST( !fd_gravity_is_inflight( env->g, 102U ) && !fd_gravity_is_inflight( env->g, 103U ) );

  /* Results are reported once */
  exec1( env, 8UL, 103U, OK_FLAGS, 3000U, now );
  exec1( env, 8UL, 100U, OK_FLAGS, 1500U, now );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( metrics( env )->results_included==3UL && metrics( env )->results_not_included==1UL );

  /* Failed bundles: real reason at the failing transaction,
     ALL_OR_NOTHING elsewhere.  If every transaction is a bundle peer
     failure, the first one gets a real reason. */
  static btxn_t b2[ 3 ], b3[ 2 ];
  for( ulong i=0UL; i<3UL; i++ ) btxn( b2+i, 10UL+i, (uchar)('e'+i), 0 );
  for( ulong i=0UL; i<2UL; i++ ) btxn( b3+i, 20UL+i, (uchar)('k'+i), 0 );
  uchar id2[ 32 ]; bundle_id( id2, 0xB2 );
  uchar id3[ 32 ]; bundle_id( id3, 0xB3 );
  w.p = frame;
  graph_hdr ( &w, 8UL, uuid2, 2UL );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id2 );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id3 );
  w_u64( &w, 0UL );
  w_u64( &w, 2UL ); graph_bundle( &w, id2, b2, 3UL ); graph_bundle( &w, id3, b3, 2UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( sched( env, 200U )==3UL );
  FD_TEST( sched( env, 203U )==2UL );
  exec1( env, 8UL, 200U, ERR_FLAGS( FD_RUNTIME_TXN_ERR_BUNDLE_PEER       ), 0U, now );
  exec1( env, 8UL, 201U, ERR_FLAGS( FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ), 0U, now );
  FD_TEST( take_msgs( env->sess )==0UL );
  exec1( env, 8UL, 202U, ERR_FLAGS( FD_RUNTIME_TXN_ERR_BUNDLE_PEER       ), 0U, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  uint const exp2[ 3 ] = { FD_GRAVITY_NI_ALL_OR_NOTHING, 11U /* InstructionError */, FD_GRAVITY_NI_ALL_OR_NOTHING };
  check_bundle_reject( msgs, 8UL, uuid2, id2, 3UL, exp2 );
  dec_result( msgs, &r );
  FD_TEST( r.worker==WORKER );
  /* Both transactions in one call works too */
  uint const flags3[ 2 ] = { ERR_FLAGS( FD_RUNTIME_TXN_ERR_BUNDLE_PEER ), ERR_FLAGS( FD_RUNTIME_TXN_ERR_BUNDLE_PEER ) };
  uint const cus3  [ 2 ] = { 0U, 0U };
  fd_gravity_on_executed( env->g, 8UL, 203U, 2UL, flags3, cus3, WORKER, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  uint const exp3[ 2 ] = { FD_GRAVITY_NI_SANITIZE_FAILURE, FD_GRAVITY_NI_ALL_OR_NOTHING };
  check_bundle_reject( msgs, 8UL, uuid2, id3, 2UL, exp3 );

  end_slot( env, 8UL );
  FD_TEST( take_msgs( env->sess )==0UL );
  env_delete( env );
}

/* d. Rejections *******************************************************/

static void
test_rejections( void ) {
  FD_LOG_NOTICE(( "TEST REJECTIONS" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );
  long now = slot_start( 8UL )+1000L;

  static btxn_t t[ 8 ];
  btxn( t+0, 30UL, 'a', 0 );
  btxn( t+7, 37UL, 'h', 0 );
  uchar id[ 32 ]; bundle_id( id, 0xC0 );

  /* Not leader: SLOT_ENDED for every node, one result per node, with
     one entry per bundle transaction */
  wr_t w = { frame };
  graph_hdr ( &w, 7UL, uuid1, 2UL );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t[0].b ) );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id );
  w_u64( &w, 1UL ); graph_txn( &w, t+0 );
  static btxn_t rb[ 2 ];
  rb[0] = t[0]; rb[1] = t[7];
  w_u64( &w, 1UL ); graph_bundle( &w, id, rb, 2UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==2UL );
  check_tx_reject( msgs+0, 7UL, uuid1, prefix_of( t[0].b ), FD_GRAVITY_NI_SLOT_ENDED );
  uint const slot_ended[ 2 ] = { FD_GRAVITY_NI_SLOT_ENDED, FD_GRAVITY_NI_ALL_OR_NOTHING };
  check_bundle_reject( msgs+1, 7UL, uuid1, id, 2UL, slot_ended );
  FD_TEST( metrics( env )->graphs_rejected==1UL && fd_pack_avail_txn_cnt( env->pack )==0UL );

  /* Leader in a GRAVITY window, graph for another slot */
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  FD_STORE( ulong, frame+4UL, 9UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==2UL );
  check_tx_reject( msgs+0, 9UL, uuid1, prefix_of( t[0].b ), FD_GRAVITY_NI_SLOT_ENDED );
  check_bundle_reject( msgs+1, 9UL, uuid1, id, 2UL, slot_ended );
  FD_TEST( metrics( env )->graphs_rejected==2UL && fd_pack_avail_txn_cnt( env->pack )==0UL );

  /* Unknown SigPrefix and BundleId */
  uchar unknown_prefix[ 16 ]; memset( unknown_prefix, 0xEE, 16UL );
  w.p = frame;
  graph_hdr ( &w, 8UL, uuid1, 2UL );
  graph_node( &w, FD_GRAVITY_NODE_TX,     unknown_prefix );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id );
  w_u64( &w, 0UL ); w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==2UL );
  check_tx_reject( msgs+0, 8UL, uuid1, unknown_prefix, FD_GRAVITY_NI_UNKNOWN_ORDERS );
  uint const unknown[ 1 ] = { FD_GRAVITY_NI_UNKNOWN_ORDERS };
  check_bundle_reject( msgs+1, 8UL, uuid1, id, 1UL, unknown );
  FD_TEST( metrics( env )->nodes_unknown==2UL && metrics( env )->retention_miss==1UL );

  /* Builder bytes: with address lookup tables (26), unparseable (17),
     rejected by pack for a duplicate account (4) */
  btxn( t+1, 31UL, 'b', MK_ALT );
  btxn( t+2, 32UL, 'c', MK_DUP );
  t[3].sz = 200UL; memset( t[3].b, 0xEE, 200UL ); t[3].b[0] = 1;
  w.p = frame;
  graph_hdr ( &w, 8UL, uuid2, 3UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[1].b ) );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[3].b ) );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[2].b ) );
  w_u64( &w, 3UL ); graph_txn( &w, t+1 ); graph_txn( &w, t+2 ); graph_txn( &w, t+3 );
  w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==3UL );
  check_tx_reject( msgs+0, 8UL, uuid2, prefix_of( t[1].b ), FD_GRAVITY_NI_ALT_NOT_FOUND );
  check_tx_reject( msgs+1, 8UL, uuid2, prefix_of( t[3].b ), FD_GRAVITY_NI_SANITIZE_FAILURE );
  check_tx_reject( msgs+2, 8UL, uuid2, prefix_of( t[2].b ), FD_GRAVITY_NI_ACCOUNT_LOADED_TWICE );
  FD_TEST( metrics( env )->nodes_alt==1UL && fd_pack_avail_txn_cnt( env->pack )==0UL );

  /* Duplicate first signatures across nodes, and a bundle with the same
     transaction twice */
  btxn( t+4, 33UL, 'd', 0 );
  btxn( t+5, 34UL, 'e', 0 );
  btxn( t+6, 35UL, 'f', 0 );
  static btxn_t bdup[ 2 ], bfirst[ 2 ];
  bfirst[0] = t[5]; bfirst[1] = t[6];
  bdup  [0] = t[6]; bdup  [1] = t[6];
  uchar id_first[ 32 ]; bundle_id( id_first, 0xC1 );
  uchar id_dup  [ 32 ]; bundle_id( id_dup,   0xC2 );
  w.p = frame;
  graph_hdr ( &w, 8UL, uuid3, 5UL );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t[4].b ) );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t[4].b ) );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id_first );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t[5].b ) );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id_dup );
  w_u64( &w, 2UL ); graph_txn( &w, t+4 ); graph_txn( &w, t+5 );
  w_u64( &w, 2UL ); graph_bundle( &w, id_first, bfirst, 2UL ); graph_bundle( &w, id_dup, bdup, 2UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==3UL );
  check_tx_reject( msgs+0, 8UL, uuid3, prefix_of( t[4].b ), FD_GRAVITY_NI_ALREADY_PROCESSED );
  check_tx_reject( msgs+1, 8UL, uuid3, prefix_of( t[5].b ), FD_GRAVITY_NI_ALREADY_PROCESSED );
  uint const dup[ 2 ] = { FD_GRAVITY_NI_ALL_OR_NOTHING, FD_GRAVITY_NI_ALREADY_PROCESSED };
  check_bundle_reject( msgs+2, 8UL, uuid3, id_dup, 2UL, dup );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==3UL ); /* t4, bundle {t5,t6} */
  FD_TEST( !fd_pack_verify( env->pack, env->verify_mem ) );

  /* A malformed graph resets the session.  The window falls back at the
     next check and the pending lane goes. */
  w.p = frame;
  graph_hdr ( &w, 8UL, uuid1, 2UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[0].b ) );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( env->sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( env->sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ]==1UL );
  ulong not_included = metrics( env )->results_not_included;
  fd_gravity_check_fallback( env->g, env->pack, now );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( metrics( env )->fallback_session==1UL );
  FD_TEST( metrics( env )->results_not_included==not_included+3UL ); /* t4 [44], bundle [44,2] */
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==0UL );
  end_slot( env, 8UL );

  /* NATIVE window: SLOT_ENDED */
  FD_TEST( lead( env, 9UL )==FD_GRAVITY_MODE_NATIVE );
  env_ready( env, 1 );
  take_msgs( env->sess );
  w.p = frame;
  graph_hdr ( &w, 9UL, uuid1, 1UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[0].b ) );
  w_u64( &w, 1UL ); graph_txn( &w, t+0 );
  w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_reject( msgs+0, 9UL, uuid1, prefix_of( t[0].b ), FD_GRAVITY_NI_SLOT_ENDED );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==0UL );
  end_slot( env, 9UL );

  /* Other relay messages: Ping is answered, the rest is ignored, a
     payload too short for a tag resets */
  w.p = frame; w_u32( &w, FD_GRAVITY_R2C_PING ); w_u64( &w, 77UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  FD_TEST( msgs[0].tag==FD_GRAVITY_C2R_PONG && msgs[0].sz==12UL && FD_LOAD( ulong, msgs[0].p+4UL )==77UL );
  w.p = frame; w_u32( &w, FD_GRAVITY_R2C_DELETE_FAILSAFE );                 send_frame( env->g, env->pack, &w, now );
  w.p = frame; w_u32( &w, FD_GRAVITY_R2C_SHRED_RECEIVERS ); w_u64( &w, 0UL ); send_frame( env->g, env->pack, &w, now );
  w.p = frame; w_u32( &w, 99U );                                            send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==0UL && env->sess->state==FD_GRAVITY_SESS_STATE_READY );
  fd_gravity_handle_frame( env->g, env->pack, NULL, frame, 2UL, now );
  FD_TEST( env->sess->state==FD_GRAVITY_SESS_STATE_IDLE );

  env_delete( env );
}

/* e. Slot end, sweep, inflight table **********************************/

static void
test_slot_end( void ) {
  FD_LOG_NOTICE(( "TEST SLOT END" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );
  long now = slot_start( 8UL )+1000L;
  result_t r;

  static btxn_t t[ 6 ];
  for( ulong i=0UL; i<6UL; i++ ) btxn( t+i, 40UL+i, (uchar)('a'+i), 0 );
  uchar id[ 32 ]; bundle_id( id, 0xD0 );

  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  wr_t w = { frame };
  graph_hdr ( &w, 8UL, uuid1, 4UL );
  for( ulong i=0UL; i<3UL; i++ ) graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[i].b ) );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id );
  w_u64( &w, 3UL ); for( ulong i=0UL; i<3UL; i++ ) graph_txn( &w, t+i );
  w_u64( &w, 1UL ); graph_bundle( &w, id, t+3, 2UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( sched( env, 10U )==1UL );
  FD_TEST( sched( env, 11U )==1UL );

  /* Undispatched nodes leave pack and are reported */
  end_slot( env, 8UL );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( take_msgs( env->sess )==2UL );
  ulong bi = msg_is_bundle_result( msgs+0 ) ? 0UL : 1UL; /* pending nodes are unordered */
  check_tx_reject( msgs+(1UL-bi), 8UL, uuid1, prefix_of( t[2].b ), FD_GRAVITY_NI_SLOT_ENDED );
  uint const ended[ 2 ] = { FD_GRAVITY_NI_SLOT_ENDED, FD_GRAVITY_NI_ALL_OR_NOTHING };
  check_bundle_reject( msgs+bi, 8UL, uuid1, id, 2UL, ended );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==0UL );
  fd_pack_set_initializer_bundles_ready( env->pack );
  FD_TEST( fd_pack_schedule_next_microblock( env->pack, MAX_COST, 1UL, FD_PACK_SCHEDULE_BUNDLE|FD_PACK_SCHEDULE_TXN, sched_out )==0UL );

  /* Dispatched nodes still report */
  exec1( env, 8UL, 10U, OK_FLAGS, 100U, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_result( msgs, 8UL, uuid1, prefix_of( t[0].b ), &r );
  FD_TEST( r.kind[0]==FD_GRAVITY_RESULT_INCLUDED );

  /* Missed results are synthesized two leader slots later */
  ulong synth = metrics( env )->results_synthetic;
  FD_TEST( lead( env, 9UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( take_msgs( env->sess )==1UL && msgs[0].tag==FD_GRAVITY_C2R_PROGRESS );
  FD_TEST( fd_gravity_is_inflight( env->g, 11U ) );
  end_slot( env, 9UL );
  FD_TEST( lead( env, 10UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( take_msgs( env->sess )==2UL );
  check_tx_reject( msgs+0, 8UL, uuid1, prefix_of( t[1].b ), FD_GRAVITY_NI_SLOT_ENDED );
  FD_TEST( msgs[1].tag==FD_GRAVITY_C2R_PROGRESS );
  FD_TEST( metrics( env )->results_synthetic==synth+1UL );
  FD_TEST( !fd_gravity_is_inflight( env->g, 11U ) );
  exec1( env, 8UL, 11U, OK_FLAGS, 100U, now );
  FD_TEST( take_msgs( env->sess )==0UL );

  /* pack_idx collides in the inflight table after
     FD_GRAVITY_INFLIGHT_CNT: the old node is given up */
  w.p = frame;
  graph_hdr ( &w, 10UL, uuid2, 3UL );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t[0].b ) );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t[1].b ) );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id );
  w_u64( &w, 2UL ); graph_txn( &w, t+0 ); graph_txn( &w, t+1 );
  w_u64( &w, 1UL ); graph_bundle( &w, id, t+3, 2UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( sched( env, 20U )==1UL );
  FD_TEST( sched( env, 20U+(uint)FD_GRAVITY_INFLIGHT_CNT )==1UL );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_reject( msgs+0, 10UL, uuid2, prefix_of( t[0].b ), FD_GRAVITY_NI_SLOT_ENDED );
  exec1( env, 10UL, 20U, OK_FLAGS, 100U, now );
  FD_TEST( take_msgs( env->sess )==0UL );
  exec1( env, 10UL, 20U+(uint)FD_GRAVITY_INFLIGHT_CNT, OK_FLAGS, 100U, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_result( msgs, 10UL, uuid2, prefix_of( t[1].b ), &r );
  FD_TEST( r.kind[0]==FD_GRAVITY_RESULT_INCLUDED );

  /* A bundle's pack_idx range can wrap around */
  FD_TEST( sched( env, UINT_MAX )==2UL );
  FD_TEST( fd_gravity_is_inflight( env->g, UINT_MAX ) && fd_gravity_is_inflight( env->g, 0U ) );
  exec1( env, 10UL, 0U, OK_FLAGS, 7U, now );
  FD_TEST( take_msgs( env->sess )==0UL );
  exec1( env, 10UL, UINT_MAX, OK_FLAGS, 6U, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  dec_result( msgs, &r );
  FD_TEST( r.is_bundle && r.res_cnt==2UL && r.cus[0]==6UL && r.cus[1]==7UL );
  end_slot( env, 10UL );

  /* became_leader without slot_end doesn't leak the previous lane */
  FD_TEST( lead( env, 11UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  w.p = frame;
  graph_hdr ( &w, 11UL, uuid3, 1UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[2].b ) );
  w_u64( &w, 1UL ); graph_txn( &w, t+2 );
  w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==1UL );
  fd_pack_end_block( env->pack );
  FD_TEST( lead( env, 12UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( take_msgs( env->sess )==2UL );
  check_tx_reject( msgs+0, 11UL, uuid3, prefix_of( t[2].b ), FD_GRAVITY_NI_SLOT_ENDED );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==0UL );
  end_slot( env, 12UL );
  env_delete( env );

  /* The pending list stays bounded by node_max when nodes execute and
     their pool slots are reused within a slot */
  env_new( env, RET_SZ, 4UL );
  make_txne( txne+0, 50UL, 'z', 0UL, 0 );
  fd_gravity_on_txn( env->g, txne+0, 0UL, 1L ); /* retained at ring offset 0 */
  env_ready( env, 1 );
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  uint pack_idx = 0U;
  for( ulong round=0UL; round<32UL; round++ ) {
    static btxn_t rt[ 4 ];
    for( ulong i=0UL; i<4UL; i++ ) btxn( rt+i, 1000UL+round*4UL+i, (uchar)('a'+i), 0 );
    w.p = frame;
    graph_hdr( &w, 8UL, uuid1, 4UL );
    for( ulong i=0UL; i<4UL; i++ ) graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( rt[i].b ) );
    w_u64( &w, 4UL ); for( ulong i=0UL; i<4UL; i++ ) graph_txn( &w, rt+i );
    w_u64( &w, 0UL );
    send_frame( env->g, env->pack, &w, now );
    FD_TEST( take_msgs( env->sess )==0UL );
    for( ulong i=0UL; i<4UL; i++ ) {
      FD_TEST( sched( env, pack_idx )==1UL );
      exec1( env, 8UL, pack_idx, OK_FLAGS, 100U, now );
      pack_idx++;
    }
    FD_TEST( take_msgs( env->sess )==4UL );
  }
  w.p = frame;
  graph_hdr ( &w, 8UL, uuid2, 1UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( txne[0].txnp->payload ) );
  w_u64( &w, 0UL ); w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==0UL ); /* still retained */
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==1UL );
  end_slot( env, 8UL );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_reject( msgs+0, 8UL, uuid2, prefix_of( txne[0].txnp->payload ), FD_GRAVITY_NI_SLOT_ENDED );
  env_delete( env );
}

/* f. Failsafe *********************************************************/

/* fwd forwards one fresh transaction, so the current slot has orders */

static void
fwd( env_t * env,
     ulong   seed,
     long    now ) {
  make_txne( txne+7, seed, 'f', 0UL, 0 );
  fd_gravity_on_txn( env->g, txne+7, 0UL, now );
}

static uchar const zero_hash[ 32 ];

static void
graph1( env_t *        env,
        ulong          slot,
        uchar const *  uuid,
        btxn_t const * t ) {
  wr_t w = { frame };
  graph_hdr ( &w, slot, uuid, 1UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t->b ) );
  w_u64( &w, 1UL ); graph_txn( &w, t );
  w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, slot_start( slot )+1000L );
}

static void
delete_failsafe( env_t * env,
                 long    now ) {
  wr_t w = { frame };
  w_u32( &w, FD_GRAVITY_R2C_DELETE_FAILSAFE );
  send_frame( env->g, env->pack, &w, now );
}

static void
test_failsafe( void ) {
  FD_LOG_NOTICE(( "TEST FAILSAFE" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );
  static btxn_t t[ 8 ];
  for( ulong i=0UL; i<8UL; i++ ) btxn( t+i, 60UL+i, (uchar)('a'+i), 0 );
  wr_t w = { frame };

  /* An idle window (nothing forwarded) stays GRAVITY for the whole slot
     and is not a miss */
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  fd_gravity_check_fallback( env->g, env->pack, slot_end( 8UL )-1L );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_GRAVITY );
  end_slot( env, 8UL );
  for( ulong s=9UL; s<12UL; s++ ) { FD_TEST( lead( env, s )==FD_GRAVITY_MODE_GRAVITY ); end_slot( env, s ); }
  FD_TEST( !metrics( env )->slots_missed && !fd_gravity_failsafe( env->g ) );
  take_msgs( env->sess );

  /* Orders forwarded but nothing scheduled: a miss.  A later slot that
     schedules clears it, so no failsafe. */
  FD_TEST( lead( env, 12UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 200UL, slot_start( 12UL )+10L );
  fd_gravity_check_fallback( env->g, env->pack, slot_end( 12UL )-1L );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_GRAVITY );
  end_slot( env, 12UL );
  FD_TEST( metrics( env )->slots_missed==1UL );
  FD_TEST( lead( env, 13UL )==FD_GRAVITY_MODE_GRAVITY );
  graph1( env, 13UL, uuid1, t+0 );
  FD_TEST( sched( env, 100U )==1UL );
  fwd( env, 201UL, slot_start( 13UL )+2000L );
  end_slot( env, 13UL );
  FD_TEST( lead( env, 14UL )==FD_GRAVITY_MODE_GRAVITY ); end_slot( env, 14UL ); /* no orders: neutral */
  FD_TEST( lead( env, 15UL )==FD_GRAVITY_MODE_GRAVITY ); end_slot( env, 15UL );
  FD_TEST( metrics( env )->slots_missed==1UL );

  /* A slot cut short by consensus (abandoned) is neutral */
  FD_TEST( lead( env, 16UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 202UL, slot_start( 16UL )+10L );
  fd_pack_end_block( env->pack );
  fd_gravity_slot_end( env->g, env->pack, 1, slot_start( 16UL )+20L );
  FD_TEST( metrics( env )->slots_missed==1UL );

  /* A miss followed by neutral slots, the window cut short (no leader
     slots 18 and 19): the failsafe trips once a later window's slot
     completes, not while one of ours may still come.  The session is
     reset. */
  FD_TEST( lead( env, 17UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 203UL, slot_start( 17UL )+10L );
  end_slot( env, 17UL );
  take_msgs( env->sess );
  fd_gravity_slot_completed( env->g, 17UL, zero_hash, slot_end( 17UL ) );
  fd_gravity_next_leader( env->g, 18UL, slot_end( 17UL ) );
  fd_gravity_slot_completed( env->g, 20UL, zero_hash, slot_end( 20UL ) ); /* another fork, 18 may still be ours */
  FD_TEST( !fd_gravity_failsafe( env->g ) );
  fd_gravity_next_leader( env->g, 40UL, slot_end( 20UL ) );
  ulong caller = env->sess->reset_cnt[ FD_GRAVITY_SESS_RESET_CALLER ];
  fd_gravity_slot_completed( env->g, 21UL, zero_hash, slot_end( 21UL ) );
  FD_TEST( fd_gravity_failsafe( env->g ) && metrics( env )->failsafe_trips==1UL && metrics( env )->slots_missed==2UL );
  FD_TEST( env->sess->state==FD_GRAVITY_SESS_STATE_IDLE && env->sess->reset_cnt[ FD_GRAVITY_SESS_RESET_CALLER ]==caller+1UL );

  /* While tripped: NATIVE windows even with a session, no Progress, no
     forwarding (but still retained) */
  env_ready( env, 1 );
  take_msgs( env->sess );
  fd_gravity_next_leader( env->g, 24UL, slot_end( 21UL ) );
  fd_gravity_slot_completed( env->g, 22UL, zero_hash, slot_end( 22UL ) );
  fd_gravity_next_leader( env->g, 24UL, slot_end( 22UL ) );
  FD_TEST( lead( env, 24UL )==FD_GRAVITY_MODE_NATIVE );
  ulong forwarded = metrics( env )->txn_forwarded;
  make_txne( txne+0, 210UL, 'r', 0UL, 0 );
  fd_gravity_on_txn( env->g, txne+0, 0UL, slot_start( 24UL )+10L );
  FD_TEST( metrics( env )->txn_forwarded==forwarded );
  FD_TEST( take_msgs( env->sess )==0UL );
  end_slot( env, 24UL );
  FD_TEST( metrics( env )->failsafe_trips==1UL );

  /* DeleteFailsafe clears it and announces right away.  The next window
     is GRAVITY, and the retained transaction is still found. */
  delete_failsafe( env, slot_end( 24UL ) );
  FD_TEST( !fd_gravity_failsafe( env->g ) );
  FD_TEST( take_msgs( env->sess )==1UL && msgs[0].tag==FD_GRAVITY_C2R_PROGRESS );
  delete_failsafe( env, slot_end( 24UL ) ); /* not tripped: ignored */
  FD_TEST( take_msgs( env->sess )==0UL );
  fd_gravity_slot_completed( env->g, 25UL, zero_hash, slot_end( 25UL ) );
  fd_gravity_next_leader( env->g, 28UL, slot_end( 25UL ) );
  FD_TEST( take_msgs( env->sess )==1UL && msgs[0].tag==FD_GRAVITY_C2R_PROGRESS );
  FD_TEST( lead( env, 28UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  w.p = frame;
  graph_hdr ( &w, 28UL, uuid2, 1UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( txne[0].txnp->payload ) );
  w_u64( &w, 0UL ); w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, slot_start( 28UL )+1000L );
  FD_TEST( take_msgs( env->sess )==0UL && fd_pack_avail_txn_cnt( env->pack )==1UL );
  FD_TEST( sched( env, 200U )==1UL );
  end_slot( env, 28UL );
  for( ulong s=29UL; s<32UL; s++ ) { FD_TEST( lead( env, s )==FD_GRAVITY_MODE_GRAVITY ); end_slot( env, s ); }

  /* Adjacent windows are one leadership: a miss in a window's last slot
     is cleared by the next window's first slot */
  FD_TEST( lead( env, 32UL )==FD_GRAVITY_MODE_GRAVITY ); end_slot( env, 32UL );
  FD_TEST( lead( env, 35UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 204UL, slot_start( 35UL )+10L );
  end_slot( env, 35UL );
  FD_TEST( !fd_gravity_failsafe( env->g ) && metrics( env )->slots_missed==3UL );
  FD_TEST( lead( env, 36UL )==FD_GRAVITY_MODE_GRAVITY );
  graph1( env, 36UL, uuid1, t+1 );
  FD_TEST( sched( env, 300U )==1UL );
  end_slot( env, 36UL );
  /* ... but carried over and tripped if no later slot schedules */
  FD_TEST( lead( env, 39UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 205UL, slot_start( 39UL )+10L );
  end_slot( env, 39UL );
  FD_TEST( lead( env, 40UL )==FD_GRAVITY_MODE_GRAVITY );
  end_slot( env, 40UL );
  FD_TEST( !fd_gravity_failsafe( env->g ) && metrics( env )->slots_missed==4UL );
  fd_gravity_next_leader( env->g, 60UL, slot_end( 40UL ) );
  fd_gravity_slot_completed( env->g, 44UL, zero_hash, slot_end( 44UL ) );
  FD_TEST( fd_gravity_failsafe( env->g ) && metrics( env )->failsafe_trips==2UL );
  env_ready( env, 1 );
  delete_failsafe( env, slot_end( 44UL ) );
  FD_TEST( !fd_gravity_failsafe( env->g ) );
  take_msgs( env->sess );

  /* Session reset mid-slot: NATIVE for the rest of the window, and the
     pending lane is purged.  The slot itself is not judged. */
  FD_TEST( lead( env, 48UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  fwd( env, 206UL, slot_start( 48UL )+10L );
  w.p = frame;
  graph_hdr ( &w, 48UL, uuid2, 2UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[2].b ) );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[3].b ) );
  w_u64( &w, 2UL ); graph_txn( &w, t+2 ); graph_txn( &w, t+3 );
  w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, slot_start( 48UL )+2000L );
  take_msgs( env->sess );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==2UL );
  ulong synth = metrics( env )->results_synthetic;
  ulong ni    = metrics( env )->results_not_included;
  fd_gravity_sess_reset( env->sess, FD_GRAVITY_SESS_RESET_CALLER, slot_start( 48UL )+3000L );
  fd_gravity_check_fallback( env->g, env->pack, slot_start( 48UL )+3000L );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( metrics( env )->fallback_session==1UL );
  FD_TEST( metrics( env )->results_synthetic==synth+2UL && metrics( env )->results_not_included==ni+2UL );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==0UL ); /* builder bytes: nothing to put back natively */
  FD_TEST( take_msgs( env->sess )==0UL ); /* nowhere to send them */
  end_slot( env, 48UL );
  env_ready( env, 1 );
  FD_TEST( lead( env, 49UL )==FD_GRAVITY_MODE_NATIVE ); end_slot( env, 49UL );
  FD_TEST( lead( env, 51UL )==FD_GRAVITY_MODE_NATIVE ); end_slot( env, 51UL );
  fd_gravity_slot_completed( env->g, 52UL, zero_hash, slot_end( 52UL ) );
  FD_TEST( !fd_gravity_failsafe( env->g ) && metrics( env )->slots_missed==4UL );

  /* A miss is not erased by a later session loss (as for the connector,
     whose missed slot survives a relay disconnect) */
  FD_TEST( lead( env, 56UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 207UL, slot_start( 56UL )+10L );
  end_slot( env, 56UL );
  env_ready( env, 0 );
  FD_TEST( lead( env, 57UL )==FD_GRAVITY_MODE_NATIVE );
  end_slot( env, 57UL );
  fd_gravity_slot_completed( env->g, 60UL, zero_hash, slot_end( 60UL ) );
  FD_TEST( fd_gravity_failsafe( env->g ) && metrics( env )->failsafe_trips==3UL && metrics( env )->slots_missed==5UL );
  env_ready( env, 1 );
  delete_failsafe( env, slot_end( 60UL ) );
  take_msgs( env->sess );

  /* Released but never dispatched: the slot end puts the forwarded
     transaction the lane node used back in pack natively */
  make_txne( txne+0, 70UL, 'q', 0UL, 0 );
  fd_gravity_on_txn( env->g, txne+0, 0UL, 1L );
  FD_TEST( insert_native( env->pack, txne+0 )>=0 );
  FD_TEST( lead( env, 64UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  w.p = frame;
  graph_hdr ( &w, 64UL, uuid1, 1UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( txne[0].txnp->payload ) );
  w_u64( &w, 0UL ); w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, slot_start( 64UL )+1000L );
  ulong avail = fd_pack_avail_txn_cnt( env->pack );
  end_slot( env, 64UL );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==avail-1UL ); /* only the native copy */
  FD_TEST( fd_pack_schedule_next_microblock( env->pack, MAX_COST, 0UL, FD_PACK_SCHEDULE_TXN, sched_out )>=1UL );
  FD_TEST( !(sched_out[0].txnp->flags & FD_TXN_P_FLAGS_BUNDLE) );
  fd_pack_microblock_complete( env->pack, 0UL );
  end_slot( env, 64UL );

  /* A leadership that ends right after a slot cleared its miss does not
     trip, within a window ... */
  ulong missed = metrics( env )->slots_missed;
  FD_TEST( lead( env, 68UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 208UL, slot_start( 68UL )+10L );
  end_slot( env, 68UL );
  FD_TEST( lead( env, 69UL )==FD_GRAVITY_MODE_GRAVITY );
  graph1( env, 69UL, uuid1, t+4 );
  FD_TEST( sched( env, 400U )==1UL );
  end_slot( env, 69UL );
  fd_gravity_next_leader( env->g, 100UL, slot_end( 69UL ) );
  fd_gravity_slot_completed( env->g, 72UL, zero_hash, slot_end( 72UL ) );
  FD_TEST( !fd_gravity_failsafe( env->g ) && metrics( env )->slots_missed==missed+1UL );

  /* ... and across adjacent windows */
  FD_TEST( lead( env, 79UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 209UL, slot_start( 79UL )+10L );
  end_slot( env, 79UL );
  FD_TEST( lead( env, 80UL )==FD_GRAVITY_MODE_GRAVITY );
  graph1( env, 80UL, uuid1, t+5 );
  FD_TEST( sched( env, 401U )==1UL );
  end_slot( env, 80UL );
  fd_gravity_slot_completed( env->g, 84UL, zero_hash, slot_end( 84UL ) );
  FD_TEST( !fd_gravity_failsafe( env->g ) && metrics( env )->slots_missed==missed+2UL );

  /* A slot pack switched away from (no slot end) is not judged, and a
     missed leadership with no later completion trips when the next
     non-adjacent window starts */
  FD_TEST( lead( env, 88UL )==FD_GRAVITY_MODE_GRAVITY );
  fwd( env, 210UL, slot_start( 88UL )+10L );
  fd_pack_end_block( env->pack );
  FD_TEST( lead( env, 89UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( metrics( env )->slots_missed==missed+2UL );
  fwd( env, 211UL, slot_start( 89UL )+10L );
  end_slot( env, 89UL );
  FD_TEST( metrics( env )->slots_missed==missed+3UL && !fd_gravity_failsafe( env->g ) );
  ulong trips = metrics( env )->failsafe_trips;
  FD_TEST( lead( env, 96UL )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( fd_gravity_failsafe( env->g ) && metrics( env )->failsafe_trips==trips+1UL );
  end_slot( env, 96UL );
  env_delete( env );
}

/* A window is GRAVITY only once the relay has known the session as
   active (Progress sent) for warmup_ns */

static void
test_warmup( void ) {
  FD_LOG_NOTICE(( "TEST WARMUP" ));
  env_warmup_ns = 5L*SLOT_NS;
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_warmup_ns = 0L;
  env_ready( env, 1 );
  env->sess->session_cnt = 1UL;

  /* No Progress sent yet: NATIVE, and the leader Progress starts the
     clock */
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( take_msgs( env->sess )==1UL && msgs[0].tag==FD_GRAVITY_C2R_PROGRESS );
  end_slot( env, 8UL );
  FD_TEST( lead( env, 12UL )==FD_GRAVITY_MODE_NATIVE ); /* 4 slots later */
  end_slot( env, 12UL );
  FD_TEST( lead( env, 16UL )==FD_GRAVITY_MODE_GRAVITY ); /* 8 slots later */
  end_slot( env, 16UL );

  /* A new session starts over */
  env->sess->session_cnt = 2UL;
  FD_TEST( lead( env, 20UL )==FD_GRAVITY_MODE_NATIVE );
  end_slot( env, 20UL );
  FD_TEST( lead( env, 28UL )==FD_GRAVITY_MODE_GRAVITY );
  end_slot( env, 28UL );
  take_msgs( env->sess );
  env_delete( env );
}

/* g. Jito bundles ****************************************************/

static fd_txn_e_t jb_txne[ 4 ][ 2 ];   /* four Jito bundles of two transactions */
static uchar      jb_meta = 0x42;

static fd_txn_e_t * const *
jb( ulong i ) {
  static fd_txn_e_t * ptrs[ 4 ][ 2 ];
  for( ulong j=0UL; j<2UL; j++ ) ptrs[ i ][ j ] = jb_txne[ i ]+j;
  return ptrs[ i ];
}

static void
jb_make( ulong i,
         long  received_at ) {
  for( ulong j=0UL; j<2UL; j++ ) {
    make_txne( jb_txne[ i ]+j, 900UL+10UL*i+j, (uchar)('j'+i), 0UL, 0 );
    jb_txne[ i ][ j ].txnp->source_tpu       = (uchar)FD_TXN_M_TPU_SOURCE_BUNDLE;
    jb_txne[ i ][ j ].txnp->first_seen_nanos = received_at;
  }
}

static void
jb_id( ulong i,
       uchar out[ 32 ] ) {
  uchar const * sigs[ 2 ] = { jb_txne[ i ][ 0 ].txnp->payload+1UL, jb_txne[ i ][ 1 ].txnp->payload+1UL };
  fd_gravity_jito_bundle_id( out, 2UL, sigs );
}

/* jb_native inserts Jito bundle i into pack as the pack tile does when
   fd_gravity_on_bundle returns 0 */

static void
jb_native( env_t * env,
           ulong   i,
           int     initializer ) {
  fd_txn_e_t * _b[ 2 ];
  fd_txn_e_t * const * b = fd_pack_insert_bundle_init( env->pack, _b, 2UL );
  for( ulong j=0UL; j<2UL; j++ ) fd_memcpy( b[ j ], jb_txne[ i ]+j, sizeof(fd_txn_e_t) );
  ulong deleted;
  FD_TEST( fd_pack_insert_bundle_fini( env->pack, b, 2UL, 100000UL, initializer, &jb_meta, &deleted )>=0 );
}

/* check_bundle_v2 checks m is BundleV2 of Jito bundle i */

static void
check_bundle_v2( msg_t const * m,
                 ulong         i,
                 long          sent_at ) {
  rd_t r = { m->p, m->p+m->sz };
  FD_TEST( rd_u32( &r )==FD_GRAVITY_C2R_BUNDLE_V2 );
  uchar id[ 32 ]; jb_id( i, id );
  FD_TEST( !memcmp( rd_skip( &r, 32UL ), id, 32UL ) );
  FD_TEST( rd_u64( &r )==2UL );
  for( ulong j=0UL; j<2UL; j++ ) {
    fd_txn_p_t const * t = jb_txne[ i ][ j ].txnp;
    FD_TEST( rd_u64( &r )==t->payload_sz );
    FD_TEST( !memcmp( rd_skip( &r, t->payload_sz ), t->payload, t->payload_sz ) );
  }
  ulong uri_sz = rd_u64( &r );
  FD_TEST( uri_sz==strlen( "http://be.test" ) && !memcmp( rd_skip( &r, uri_sz ), "http://be.test", uri_sz ) );
  FD_TEST( rd_u64( &r )==(ulong)jb_txne[ i ][ 0 ].txnp->first_seen_nanos );
  ulong s = rd_u64( &r );
  FD_TEST( sent_at<0L || s==(ulong)sent_at );
  FD_TEST( r.p==r.end );
}

static void
test_jito( void ) {
  FD_LOG_NOTICE(( "TEST JITO" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  long now = slot_start( 8UL )-1000L;
  for( ulong i=0UL; i<4UL; i++ ) jb_make( i, now-100L );

  /* Outside windows with a session: forwarded, not inserted */
  env_ready( env, 1 );
  FD_TEST( fd_gravity_on_bundle( env->g, jb( 0 ), 2UL, 100000UL, &jb_meta, now )==1 );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_bundle_v2( msgs, 0UL, now );
  FD_TEST( metrics( env )->jito_rx==1UL && metrics( env )->jito_fwd==1UL );
  FD_TEST( fd_gravity_on_bundle( env->g, jb( 0 ), 2UL, 100000UL, &jb_meta, now )==1 ); /* duplicate: dropped */
  FD_TEST( take_msgs( env->sess )==0UL && metrics( env )->jito_dup==1UL );

  /* Without a session: native */
  env_ready( env, 0 );
  FD_TEST( fd_gravity_on_bundle( env->g, jb( 1 ), 2UL, 100000UL, &jb_meta, now )==0 );
  jb_native( env, 1UL, 0 );
  FD_TEST( metrics( env )->jito_native==1UL && fd_pack_avail_txn_cnt( env->pack )==2UL );

  /* GRAVITY slot with the tip crank: the native bundle leaves pack (not
     the crank's initializer bundle) and is forwarded, bundle 0 is
     re-forwarded (the relay only passes it on near a leader), and the
     lane waits for the crank */
  env_ready( env, 1 );
  jb_native( env, 2UL, 1 ); /* stands in for the crank's initializer bundle */
  FD_TEST( fd_gravity_became_leader( env->g, env->pack, 8UL, slot_start( 8UL ), slot_end( 8UL ), 1008UL, 1,
                                     slot_start( 8UL )+1000L )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==2UL && metrics( env )->jito_pulled==2UL );
  ulong n = take_msgs( env->sess );
  FD_TEST( n==3UL && msgs[0].tag==FD_GRAVITY_C2R_PROGRESS );
  check_bundle_v2( msgs+1, 0UL, -1L );
  check_bundle_v2( msgs+2, 1UL, -1L );
  FD_TEST( metrics( env )->jito_fwd==3UL );

  /* A graph referencing bundle 0 by id without bytes (the builder omits
     bytes it got from us), and bundle 1 under another connector's id
     with bytes: both resolve to the retained copies */
  uchar id0[ 32 ]; jb_id( 0UL, id0 );
  uchar other[ 32 ]; memset( other, 0xEE, 32UL );
  static btxn_t b1[ 2 ];
  for( ulong j=0UL; j<2UL; j++ ) { b1[ j ].sz = jb_txne[ 1 ][ j ].txnp->payload_sz; fd_memcpy( b1[ j ].b, jb_txne[ 1 ][ j ].txnp->payload, b1[ j ].sz ); }
  wr_t w = { frame };
  graph_hdr ( &w, 8UL, uuid1, 2UL );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id0 );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, other );
  w_u64( &w, 0UL );
  w_u64( &w, 1UL ); graph_bundle( &w, other, b1, 2UL );
  send_frame( env->g, env->pack, &w, slot_start( 8UL )+2000L );
  FD_TEST( take_msgs( env->sess )==0UL && metrics( env )->jito_hit==2UL && metrics( env )->nodes_inserted==2UL );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==6UL );
  FD_TEST( fd_pack_schedule_next_microblock( env->pack, MAX_COST, 0UL, FD_PACK_SCHEDULE_BUNDLE, sched_out )==2UL );
  FD_TEST( sched_out[0].txnp->flags & FD_TXN_P_FLAGS_INITIALIZER_BUNDLE ); /* the crank first */
  fd_pack_microblock_complete( env->pack, 0UL );
  fd_gravity_on_schedule( env->g, env->pack, sched_out, 2UL, 50U, sched_now );
  FD_TEST( fd_pack_schedule_next_microblock( env->pack, MAX_COST, 0UL, FD_PACK_SCHEDULE_BUNDLE, sched_out )==0UL ); /* pending */
  fd_pack_set_initializer_bundles_ready( env->pack ); /* the crank landed */
  FD_TEST( sched( env, 52U )==2UL );
  uint flags[ 2 ] = { OK_FLAGS, OK_FLAGS }; uint cus[ 2 ] = { 10U, 11U };
  fd_gravity_on_executed( env->g, 8UL, 52U, 1UL, flags,   cus,   WORKER, now );
  fd_gravity_on_executed( env->g, 8UL, 53U, 1UL, flags+1, cus+1, WORKER, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  result_t r;
  dec_result( msgs, &r );
  FD_TEST( r.is_bundle && !memcmp( r.bundle_id, id0, 32UL ) && r.res_cnt==2UL && r.kind[0]==FD_GRAVITY_RESULT_INCLUDED );
  end_slot( env, 8UL ); /* bundle 1's lane node is purged */
  FD_TEST( take_msgs( env->sess )==1UL );

  /* A NATIVE window: the retained bundles that bypassed pack go back,
     except the one that executed */
  env_ready( env, 0 );
  fd_gravity_slot_completed( env->g, 12UL, zero_hash, slot_end( 12UL ) ); /* ends the leadership */
  FD_TEST( lead( env, 16UL )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( metrics( env )->jito_reinserted==1UL && fd_pack_avail_txn_cnt( env->pack )==2UL );
  fd_pack_set_initializer_bundles_ready( env->pack ); /* pack's own crank, up to date */
  FD_TEST( fd_pack_schedule_next_microblock( env->pack, MAX_COST, 0UL, FD_PACK_SCHEDULE_BUNDLE, sched_out )==2UL );
  FD_TEST( !memcmp( sched_out[0].txnp->payload, jb_txne[ 1 ][ 0 ].txnp->payload, jb_txne[ 1 ][ 0 ].txnp->payload_sz ) );
  fd_pack_microblock_complete( env->pack, 0UL );
  fd_gravity_on_schedule( env->g, env->pack, sched_out, 2UL, 60U, sched_now ); /* executed natively: done */
  end_slot( env, 16UL );

  /* Neither comes back at the next NATIVE transition, and a session
     loss in a GRAVITY slot puts a bundle diverted in the slot back */
  env_ready( env, 1 );
  fd_gravity_slot_completed( env->g, 20UL, zero_hash, slot_end( 20UL ) );
  FD_TEST( lead( env, 24UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( take_msgs( env->sess )==1UL && msgs[0].tag==FD_GRAVITY_C2R_PROGRESS ); /* executed bundles are not re-forwarded */
  FD_TEST( fd_gravity_on_bundle( env->g, jb( 3 ), 2UL, 100000UL, &jb_meta, slot_start( 24UL )+10L )==1 );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_bundle_v2( msgs, 3UL, slot_start( 24UL )+10L );
  fd_gravity_sess_reset( env->sess, FD_GRAVITY_SESS_RESET_CALLER, slot_start( 24UL )+20L );
  fd_gravity_check_fallback( env->g, env->pack, slot_start( 24UL )+20L );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( metrics( env )->jito_reinserted==2UL && fd_pack_avail_txn_cnt( env->pack )==2UL );
  end_slot( env, 24UL );
  env_delete( env );
}

/* Native Jito bundles that a GRAVITY slot pulled out of pack, and the
   modes that keep bundles native */

static uchar jb_meta2 = 0x37;

static void
test_jito_lifecycle( void ) {
  FD_LOG_NOTICE(( "TEST JITO LIFECYCLE" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  /* Old enough to be forwarded at slot 8 but not re-forwarded at slot
     16 */
  long rx = slot_start( 8UL )-JITO_TEST_REFWD_NS+SLOT_NS/2L;
  for( ulong i=0UL; i<4UL; i++ ) jb_make( i, rx );

  /* Two bundles native without a session.  The GRAVITY slot pulls both
     and forwards them. */
  env_ready( env, 0 );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_gravity_on_bundle( env->g, jb( i ), 2UL, 100000UL, &jb_meta2, rx )==0 );
    jb_native( env, i, 0 );
  }
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==4UL );
  env_ready( env, 1 );
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==0UL && metrics( env )->jito_pulled==4UL ); /* transactions */
  FD_TEST( take_msgs( env->sess )==3UL && msgs[0].tag==FD_GRAVITY_C2R_PROGRESS );
  check_bundle_v2( msgs+1, 0UL, -1L );
  check_bundle_v2( msgs+2, 1UL, -1L );

  /* Session lost mid-slot: both go back to pack, with their meta */
  fd_gravity_sess_reset( env->sess, FD_GRAVITY_SESS_RESET_CALLER, slot_start( 8UL )+2000L );
  fd_gravity_check_fallback( env->g, env->pack, slot_start( 8UL )+2000L );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( metrics( env )->jito_reinserted==2UL && fd_pack_avail_txn_cnt( env->pack )==4UL );
  FD_TEST( *(uchar const *)fd_pack_peek_bundle_meta( env->pack )==jb_meta2 );
  end_slot( env, 8UL );
  fd_gravity_slot_completed( env->g, 12UL, zero_hash, slot_end( 12UL ) );
  FD_TEST( !fd_gravity_failsafe( env->g ) );

  /* The next GRAVITY window pulls them again, too old to re-forward (so
     the slot has no orders and is no miss).  Then a NATIVE window puts
     them back, and a bundle already in pack is not inserted twice. */
  env_ready( env, 1 );
  FD_TEST( lead( env, 16UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==0UL && metrics( env )->jito_pulled==8UL );
  FD_TEST( take_msgs( env->sess )==1UL && msgs[0].tag==FD_GRAVITY_C2R_PROGRESS );
  end_slot( env, 16UL );
  fd_gravity_slot_completed( env->g, 20UL, zero_hash, slot_end( 20UL ) );
  FD_TEST( !fd_gravity_failsafe( env->g ) && !metrics( env )->slots_missed );
  env_ready( env, 0 );
  FD_TEST( fd_gravity_on_bundle( env->g, jb( 2 ), 2UL, 100000UL, &jb_meta, slot_start( 24UL ) )==0 );
  jb_native( env, 2UL, 0 );
  FD_TEST( lead( env, 24UL )==FD_GRAVITY_MODE_NATIVE );
  FD_TEST( metrics( env )->jito_reinserted==4UL && fd_pack_avail_txn_cnt( env->pack )==6UL );
  end_slot( env, 24UL );
  fd_gravity_slot_completed( env->g, 28UL, zero_hash, slot_end( 28UL ) );
  env_delete( env );

  /* A NATIVE window with a session (warming up): bundles stay native */
  env_warmup_ns = 5L*SLOT_NS;
  env_new( env, RET_SZ, 64UL );
  env_warmup_ns = 0L;
  env_ready( env, 1 );
  env->sess->session_cnt = 1UL;
  jb_make( 0UL, slot_start( 8UL ) );
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_NATIVE );
  take_msgs( env->sess );
  ulong native = metrics( env )->jito_native;
  FD_TEST( fd_gravity_on_bundle( env->g, jb( 0 ), 2UL, 100000UL, &jb_meta, slot_start( 8UL )+10L )==0 );
  jb_native( env, 0UL, 0 );
  FD_TEST( metrics( env )->jito_native==native+1UL && take_msgs( env->sess )==0UL );
  end_slot( env, 8UL );
  env_delete( env );

  /* A GRAVITY slot whose only order is a forwarded Jito bundle is a
     miss, as is one whose transactions were all shed.  While the
     failsafe is tripped, bundles stay native even outside windows. */
  env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );
  jb_make( 0UL, slot_start( 8UL ) );
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  FD_TEST( fd_gravity_on_bundle( env->g, jb( 0 ), 2UL, 100000UL, &jb_meta, slot_start( 8UL )+10L )==1 );
  end_slot( env, 8UL );
  FD_TEST( metrics( env )->slots_missed==1UL );
  take_msgs( env->sess );
  FD_TEST( lead( env, 9UL )==FD_GRAVITY_MODE_GRAVITY );
  for( ulong i=0UL; i<100000UL && !metrics( env )->txn_fwd_dropped; i++ ) fwd( env, 1000UL+i, 0L );
  FD_TEST( metrics( env )->txn_fwd_dropped );
  end_slot( env, 9UL );
  FD_TEST( lead( env, 10UL )==FD_GRAVITY_MODE_GRAVITY );
  ulong dropped = metrics( env )->txn_fwd_dropped;
  fwd( env, 999UL, slot_start( 10UL )+10L );
  FD_TEST( metrics( env )->txn_fwd_dropped==dropped+1UL );
  end_slot( env, 10UL );
  FD_TEST( metrics( env )->slots_missed==3UL );
  env->sess->tx_lo = env->sess->tx_hi = 0UL; /* more than take_msgs holds */
  fd_gravity_next_leader( env->g, 40UL, slot_end( 10UL ) );
  fd_gravity_slot_completed( env->g, 12UL, zero_hash, slot_end( 12UL ) );
  FD_TEST( fd_gravity_failsafe( env->g ) );
  env_ready( env, 1 );
  take_msgs( env->sess );
  jb_make( 1UL, slot_end( 12UL ) );
  FD_TEST( fd_gravity_on_bundle( env->g, jb( 1 ), 2UL, 100000UL, &jb_meta, slot_end( 12UL ) )==0 );
  jb_native( env, 1UL, 0 );
  FD_TEST( take_msgs( env->sess )==0UL );
  env_delete( env );
}

/* A bundle that starts with a lane node's transaction ****************/

static void
test_lookalike_bundle( void ) {
  FD_LOG_NOTICE(( "TEST LOOKALIKE BUNDLE" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );

  make_txne( txne+0, 80UL, 'x', 0UL, 0 );
  make_txne( txne+1, 81UL, 'y', 0UL, 0 );
  fd_gravity_on_txn( env->g, txne+0, 0UL, 1L );
  FD_TEST( lead( env, 24UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  wr_t w = { frame };
  graph_hdr ( &w, 24UL, uuid1, 1UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( txne[0].txnp->payload ) );
  w_u64( &w, 0UL ); w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, slot_start( 24UL )+1000L );
  FD_TEST( metrics( env )->nodes_inserted==1UL );

  /* A (Jito) bundle [X,Y] scheduled while lane node [X] is pending is
     not the lane node: it keeps its bundle flag and the node stays
     pending. */
  static fd_txn_e_t fake[ 2 ];
  fd_memcpy( fake+0, txne+0, sizeof(fd_txn_e_t) );
  fd_memcpy( fake+1, txne+1, sizeof(fd_txn_e_t) );
  fake[0].txnp->flags = FD_TXN_P_FLAGS_BUNDLE;
  fake[1].txnp->flags = FD_TXN_P_FLAGS_BUNDLE;
  fd_gravity_on_schedule( env->g, env->pack, fake, 2UL, 500U, sched_now );
  FD_TEST( fake[0].txnp->flags & FD_TXN_P_FLAGS_BUNDLE );
  FD_TEST( !fd_gravity_is_inflight( env->g, 500U ) );

  /* The real lane node still dispatches and reports */
  FD_TEST( sched( env, 501U )==1UL );
  FD_TEST( fd_gravity_is_inflight( env->g, 501U ) );
  end_slot( env, 24UL );
  env_delete( env );
}

/* g. Progress *********************************************************/

static void
test_progress( void ) {
  FD_LOG_NOTICE(( "TEST PROGRESS" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );
  progress_t p;
  uchar h[ 32 ][ 32 ];
  for( ulong i=0UL; i<32UL; i++ ) memset( h[i], (int)(0x40+i), 32UL );
  ulong sent[ 32 ]; ulong sent_cnt = 0UL;

# define EXPECT_PROGRESS( _slot, _obs, _next, _bh ) do {                                  \
    FD_TEST( take_msgs( env->sess )==1UL );                                              \
    dec_progress( msgs, &p );                                                             \
    FD_TEST( p.slot==(_slot) && p.observed_at==(ulong)(_obs) );                           \
    if( (_next)==ULONG_MAX ) FD_TEST( !p.has_next );                                      \
    else FD_TEST( p.has_next && p.next_start==(_next) && p.next_end==(_next)+3UL );       \
    FD_TEST( p.has_bh && !memcmp( p.bh, h[ _bh ], 32UL ) );                               \
    sent[ sent_cnt++ ] = p.slot;                                                          \
  } while(0)

  fd_gravity_reset( env->g, 4UL, h[4], 8UL, 10L );
  EXPECT_PROGRESS( 5UL, 10L, 8UL, 4 );
  fd_gravity_slot_completed( env->g, 5UL, h[5], 11L );
  FD_TEST( take_msgs( env->sess )==0UL ); /* waits for the next leader */
  fd_gravity_next_leader( env->g, 8UL, 11L );
  EXPECT_PROGRESS( 6UL, 11L, 8UL, 5 );
  fd_gravity_slot_completed( env->g, 5UL, h[5], 12L );
  fd_gravity_slot_completed( env->g, 3UL, h[3], 12L );
  fd_gravity_next_leader( env->g, 8UL, 12L );
  FD_TEST( take_msgs( env->sess )==0UL ); /* strictly increasing */
  fd_gravity_slot_completed( env->g, 6UL, h[6], 13L );
  fd_gravity_next_leader( env->g, 8UL, 13L );
  EXPECT_PROGRESS( 7UL, 13L, 8UL, 6 ); /* slot 3 did not move the blockhash back */
  fd_gravity_reset( env->g, 7UL, h[7], 8UL, 14L );
  FD_TEST( take_msgs( env->sess )==0UL ); /* our leader slot is next */

  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 8UL, slot_start( 8UL ), 8UL, 7 );
  fd_gravity_slot_completed( env->g, 8UL, h[8], 15L );
  fd_gravity_next_leader( env->g, 9UL, 15L );
  FD_TEST( take_msgs( env->sess )==0UL ); /* inside our window */
  end_slot( env, 8UL );
  fd_gravity_reset( env->g, 8UL, h[8], 9UL, 16L );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( lead( env, 9UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 9UL, slot_start( 9UL ), 8UL, 8 );
  fd_gravity_slot_completed( env->g, 9UL, h[9], 17L );
  fd_gravity_next_leader( env->g, 10UL, 17L );
  FD_TEST( take_msgs( env->sess )==0UL );
  end_slot( env, 9UL );
  FD_TEST( lead( env, 10UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 10UL, slot_start( 10UL ), 8UL, 9 );
  end_slot( env, 10UL );
  FD_TEST( lead( env, 11UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 11UL, slot_start( 11UL ), 8UL, 9 );
  end_slot( env, 11UL );

  /* After the window */
  fd_gravity_reset( env->g, 11UL, h[11], 20UL, 18L );
  EXPECT_PROGRESS( 12UL, 18L, 20UL, 11 );
  fd_gravity_reset( env->g, 12UL, h[12], ULONG_MAX, 19L );
  EXPECT_PROGRESS( 13UL, 19L, ULONG_MAX, 12 );

  /* No session: nothing is sent, and nothing is skipped later */
  env_ready( env, 0 );
  fd_gravity_slot_completed( env->g, 13UL, h[13], 20L );
  fd_gravity_next_leader( env->g, ULONG_MAX, 20L );
  env_ready( env, 1 );
  FD_TEST( take_msgs( env->sess )==0UL );
  fd_gravity_slot_completed( env->g, 13UL, h[13], 21L );
  fd_gravity_next_leader( env->g, ULONG_MAX, 21L );
  EXPECT_PROGRESS( 14UL, 21L, ULONG_MAX, 13 );

  /* Back to back windows: when slot 14 completes, the next leader slot
     known from the last reset is stale.  Progress for 15 must wait for
     replay's next leader message, which says 15 is ours, and only be
     sent once we are leader for it. */
  fd_gravity_slot_completed( env->g, 14UL, h[14], 22L );
  FD_TEST( take_msgs( env->sess )==0UL );
  fd_gravity_next_leader( env->g, 15UL, 22L );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( lead( env, 15UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 15UL, slot_start( 15UL ), 12UL, 14 );
  end_slot( env, 15UL );

  /* Right after our own slot completes, replay may still report the
     leader bank that just finished as the next leader slot.  That is
     stale: wait for the reset, which says whether 16 is ours. */
  fd_gravity_slot_completed( env->g, 15UL, h[15], 23L );
  fd_gravity_next_leader( env->g, 15UL, 23L );
  FD_TEST( take_msgs( env->sess )==0UL );
  fd_gravity_reset( env->g, 15UL, h[15], 40UL, 24L );
  EXPECT_PROGRESS( 16UL, 24L, 40UL, 15 );

  /* Stale next leader and no reset: sent anyway after the wait */
  fd_gravity_slot_completed( env->g, 16UL, h[16], 25L );
  fd_gravity_next_leader( env->g, 15UL, 25L );
  FD_TEST( take_msgs( env->sess )==0UL );
  fd_gravity_poll( env->g, env->pack, NULL, 25L+19999999L );
  FD_TEST( take_msgs( env->sess )==0UL );
  fd_gravity_poll( env->g, env->pack, NULL, 25L+20000000L );
  EXPECT_PROGRESS( 17UL, 25L+20000000L, ULONG_MAX, 16 );

  /* On a real cluster, when a slot of ours completes, replay reports
     that slot as the next leader slot, and sends no RESET until it
     makes us leader again, which can take much longer than the wait.
     The next slot must not be announced as a non-leader slot if it may
     be ours: inside our window it is ours... */
  fd_gravity_slot_completed( env->g, 19UL, h[19], 30L );
  fd_gravity_next_leader( env->g, 20UL, 30L );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( lead( env, 20UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 20UL, slot_start( 20UL ), 20UL, 19 );
  end_slot( env, 20UL );
  fd_gravity_slot_completed( env->g, 20UL, h[20], 31L );
  fd_gravity_next_leader( env->g, 20UL, 31L );
  fd_gravity_poll( env->g, env->pack, NULL, 31L+40000000L );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( lead( env, 21UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 21UL, slot_start( 21UL ), 20UL, 20 );
  end_slot( env, 21UL );
  FD_TEST( lead( env, 22UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 22UL, slot_start( 22UL ), 20UL, 20 );
  end_slot( env, 22UL );
  FD_TEST( lead( env, 23UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 23UL, slot_start( 23UL ), 20UL, 20 );
  end_slot( env, 23UL );

  /* ... right after it, it may be ours.  Wait without deadline. */
  fd_gravity_slot_completed( env->g, 23UL, h[23], 40L );
  fd_gravity_next_leader( env->g, 23UL, 40L );
  fd_gravity_poll( env->g, env->pack, NULL, 40L+40000000L );
  fd_gravity_poll( env->g, env->pack, NULL, 40L+1000000000L );
  FD_TEST( take_msgs( env->sess )==0UL );
  /* It is ours: the RESET says so, then became_leader announces it */
  fd_gravity_reset( env->g, 23UL, h[23], 24UL, 50L );
  FD_TEST( take_msgs( env->sess )==0UL );
  FD_TEST( lead( env, 24UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 24UL, slot_start( 24UL ), 24UL, 23 );
  end_slot( env, 24UL );
  FD_TEST( lead( env, 27UL )==FD_GRAVITY_MODE_GRAVITY );
  EXPECT_PROGRESS( 27UL, slot_start( 27UL ), 24UL, 23 );
  end_slot( env, 27UL );

  /* Not ours: nothing (not even a new session) announces 28 until the
     next leader's slot 28 completes, then 29 is announced */
  fd_gravity_slot_completed( env->g, 27UL, h[27], 60L );
  fd_gravity_next_leader( env->g, 27UL, 60L );
  env->sess->session_new = 1;
  fd_gravity_poll( env->g, env->pack, NULL, 60L+40000000L );
  FD_TEST( take_msgs( env->sess )==0UL );
  fd_gravity_slot_completed( env->g, 28UL, h[28], 70L );
  fd_gravity_next_leader( env->g, 40UL, 70L );
  EXPECT_PROGRESS( 29UL, 70L, 40UL, 28 );

  FD_TEST( sent_cnt==20UL );
  for( ulong i=1UL; i<sent_cnt; i++ ) FD_TEST( sent[i]>sent[i-1UL] );
  FD_TEST( metrics( env )->progress_sent==sent_cnt );
# undef EXPECT_PROGRESS
  env_delete( env );
}

/* Large graphs are inserted over several polls ************************/

static void
test_graph_budget( void ) {
  FD_LOG_NOTICE(( "TEST GRAPH BUDGET" ));
  env_t env[1]; env_new( env, RET_SZ, 512UL );
  env_ready( env, 1 );
  long now = slot_start( 8UL );
  env->sess->last_rx = now;

  static fd_txn_e_t fw[ 200 ];
  for( ulong i=0UL; i<200UL; i++ ) {
    make_txne( fw+i, 7000UL+i, (uchar)('a'+(i%26UL)), 0UL, 0 );
    fd_gravity_on_txn( env->g, fw+i, 0UL, now );
  }
  take_msgs( env->sess );
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );

  /* A 200 node graph, then a Ping, in the receive buffer */
  wr_t w = { frame };
  graph_hdr( &w, 8UL, uuid1, 200UL );
  for( ulong i=0UL; i<200UL; i++ ) graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( fw[i].txnp->payload ) );
  w_u64( &w, 0UL );
  w_u64( &w, 0UL );
  ulong   graph_sz = (ulong)(w.p-frame);
  uchar * rx       = env->sess->rx;
  fd_gravity_frame_hdr_write( rx, graph_sz, 0UL );
  fd_memcpy( rx+FD_GRAVITY_FRAME_HDR_SZ, frame, graph_sz );
  ulong off = FD_GRAVITY_FRAME_HDR_SZ+graph_sz;
  fd_gravity_frame_hdr_write( rx+off, 12UL, 0UL );
  FD_STORE( uint,  rx+off+FD_GRAVITY_FRAME_HDR_SZ,     FD_GRAVITY_R2C_PING );
  FD_STORE( ulong, rx+off+FD_GRAVITY_FRAME_HDR_SZ+4UL, 9UL );
  env->sess->rx_lo = 0UL;
  env->sess->rx_hi = off+FD_GRAVITY_FRAME_HDR_SZ+12UL;

  /* 64 nodes per poll, so earlier nodes can be scheduled meanwhile */
  for( ulong i=1UL; i<=3UL; i++ ) {
    FD_TEST( fd_gravity_poll( env->g, env->pack, NULL, now ) );
    FD_TEST( metrics( env )->nodes_inserted==64UL*i );
    FD_TEST( fd_pack_avail_txn_cnt( env->pack )==64UL*i );
    FD_TEST( take_msgs( env->sess )==0UL );
  }

  /* The slot ends: the inserted nodes are purged, the rest of the graph
     is rejected by the next poll, and only then the Ping is handled */
  end_slot( env, 8UL );
  FD_TEST( take_msgs( env->sess )==192UL );
  FD_TEST( fd_gravity_poll( env->g, env->pack, NULL, now ) );
  FD_TEST( take_msgs( env->sess )==8UL );
  for( ulong i=0UL; i<8UL; i++ ) check_tx_reject( msgs+i, 8UL, uuid1, prefix_of( fw[ 192UL+i ].txnp->payload ), FD_GRAVITY_NI_SLOT_ENDED );
  FD_TEST( metrics( env )->nodes_inserted==192UL );
  FD_TEST( fd_gravity_poll( env->g, env->pack, NULL, now ) );
  FD_TEST( take_msgs( env->sess )==1UL && msgs[0].tag==FD_GRAVITY_C2R_PONG );
  env_delete( env );
}

/* Polling, identity switch, back pressure, order limits ***************/

static void
test_misc( void ) {
  FD_LOG_NOTICE(( "TEST MISC" ));
  env_t env[1]; env_new( env, RET_SZ, 64UL );
  env_ready( env, 1 );
  uchar h[ 32 ]; memset( h, 0x42, 32UL );
  progress_t p;
  long now = slot_start( 4UL );

  /* The handshake advertises the blacklist, right before the Jito tip
     weight */
  uchar const * hs    = env->sess->handshake;
  ulong         hs_sz = env->sess->handshake_sz;
  uchar bl[ 32 ]; memset( bl, 'B', 32UL );
  FD_TEST( FD_LOAD( ulong, hs+hs_sz-2UL-32UL-8UL )==1UL && !memcmp( hs+hs_sz-2UL-32UL, bl, 32UL ) );

  fd_gravity_reset( env->g, 4UL, h, 8UL, now );
  FD_TEST( take_msgs( env->sess )==1UL );

  /* A new session announces the next slot again, then relay frames
     queued in the receive buffer are handled */
  env->sess->session_new = 1;
  env->sess->last_rx     = now;
  uchar * rx = env->sess->rx;
  fd_gravity_frame_hdr_write( rx, 12UL, 0UL );
  FD_STORE( uint,  rx+FD_GRAVITY_FRAME_HDR_SZ,     FD_GRAVITY_R2C_PING );
  FD_STORE( ulong, rx+FD_GRAVITY_FRAME_HDR_SZ+4UL, 5UL );
  env->sess->rx_lo = 0UL;
  env->sess->rx_hi = FD_GRAVITY_FRAME_HDR_SZ+12UL;
  FD_TEST( fd_gravity_poll( env->g, env->pack, NULL, now ) );
  FD_TEST( !env->sess->session_new );
  FD_TEST( take_msgs( env->sess )==2UL );
  dec_progress( msgs+0, &p );
  FD_TEST( p.slot==5UL && p.observed_at==(ulong)now && p.has_next && p.next_start==8UL );
  FD_TEST( msgs[1].tag==FD_GRAVITY_C2R_PONG && FD_LOAD( ulong, msgs[1].p+4UL )==5UL );

  /* While leader, the leader slot */
  FD_TEST( lead( env, 8UL )==FD_GRAVITY_MODE_GRAVITY );
  take_msgs( env->sess );
  env->sess->session_new = 1;
  fd_gravity_poll( env->g, env->pack, NULL, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  dec_progress( msgs+0, &p );
  FD_TEST( p.slot==8UL && p.observed_at==(ulong)slot_start( 8UL ) && p.next_start==8UL && p.next_end==11UL );

  /* More builder orders than order_max: the excess is not indexed.  A
     repeated bundle id keeps the first bundle. */
  static btxn_t t[ 70 ], bb[ 3 ];
  for( ulong i=0UL; i<70UL; i++ ) btxn( t+i, 2000UL+i, (uchar)('A'+(i%40UL)), 0 );
  for( ulong i=0UL; i<3UL;  i++ ) btxn( bb+i, 3000UL+i, (uchar)('a'+i), 0 );
  uchar id[ 32 ]; bundle_id( id, 0xE0 );
  wr_t w = { frame };
  graph_hdr ( &w, 8UL, uuid1, 3UL );
  graph_node( &w, FD_GRAVITY_NODE_BUNDLE, id );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t[0].b ) );
  graph_node( &w, FD_GRAVITY_NODE_TX,     prefix_of( t[69].b ) );
  w_u64( &w, 60UL ); for( ulong i=0UL; i<60UL; i++ ) graph_txn( &w, t+i );
  w_u64( &w, 3UL  ); graph_bundle( &w, id, bb, 2UL ); graph_bundle( &w, id, bb+2, 1UL ); graph_bundle( &w, id, bb+2, 1UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_reject( msgs+0, 8UL, uuid1, prefix_of( t[69].b ), FD_GRAVITY_NI_UNKNOWN_ORDERS );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==3UL ); /* bundle {bb0,bb1}, t0 */
  w.p = frame;
  graph_hdr ( &w, 8UL, uuid2, 2UL );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[63].b ) );
  graph_node( &w, FD_GRAVITY_NODE_TX, prefix_of( t[64].b ) );
  w_u64( &w, 70UL ); for( ulong i=0UL; i<70UL; i++ ) graph_txn( &w, t+i );
  w_u64( &w, 0UL );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( take_msgs( env->sess )==1UL );
  check_tx_reject( msgs+0, 8UL, uuid2, prefix_of( t[64].b ), FD_GRAVITY_NI_UNKNOWN_ORDERS );
  FD_TEST( fd_pack_avail_txn_cnt( env->pack )==4UL );

  /* Forwards are shed before the transmit buffer is half full, so
     results and Progress still fit */
  ulong fwd0 = metrics( env )->txn_forwarded;
  for( ulong i=0UL; i<1000UL; i++ ) {
    make_txne( txne+0, 5000UL+i, 'q', 900UL, 0 );
    fd_gravity_on_txn( env->g, txne+0, 0UL, now );
  }
  FD_TEST( metrics( env )->txn_fwd_dropped>0UL );
  FD_TEST( metrics( env )->txn_forwarded-fwd0+metrics( env )->txn_fwd_dropped==1000UL );
  FD_TEST( fd_gravity_sess_tx_free( env->sess )>=TX_MAX/2UL-2048UL );
  end_slot( env, 8UL );
  FD_TEST( env->sess->state==FD_GRAVITY_SESS_STATE_READY );
  ulong n = take_msgs( env->sess );
  FD_TEST( msgs[ n-1UL ].tag==FD_GRAVITY_C2R_EXEC_RESULT ); /* the purge results went out */

  /* A malformed Ping resets the session */
  w.p = frame; w_u32( &w, FD_GRAVITY_R2C_PING );
  send_frame( env->g, env->pack, &w, now );
  FD_TEST( env->sess->state==FD_GRAVITY_SESS_STATE_IDLE );

  /* Identity switch resets the session; a GRAVITY window falls back */
  env_ready( env, 1 );
  FD_TEST( lead( env, 9UL )==FD_GRAVITY_MODE_GRAVITY );
  uchar identity[ 32 ]; memset( identity, 'J', 32UL );
  fd_gravity_set_identity( env->g, identity, now );
  FD_TEST( env->sess->state==FD_GRAVITY_SESS_STATE_IDLE && !memcmp( env->sess->identity, identity, 32UL ) );
  fd_gravity_check_fallback( env->g, env->pack, now );
  FD_TEST( fd_gravity_mode( env->g )==FD_GRAVITY_MODE_NATIVE );
  end_slot( env, 9UL );
  env_delete( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  test_window_mode();
  test_forwarding();
  test_graph_intake();
  test_rejections();
  test_slot_end();
  test_failsafe();
  test_warmup();
  test_jito();
  test_jito_lifecycle();
  test_lookalike_bundle();
  test_progress();
  test_graph_budget();
  test_misc();

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
