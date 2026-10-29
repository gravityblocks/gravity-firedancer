#include "fd_gravity.h"
#include "../../../util/fd_util.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../fd_txn_m.h"

/* The relay announces connectors to builders every 10 s, and builders
   drop orders of connectors they don't know yet (see warmup_ns). */

/* Lane nodes **********************************************************/

#define NODE_STATE_PENDING    (1)  /* inserted in pack, not scheduled */
#define NODE_STATE_DISPATCHED (2)  /* scheduled, waiting for execle */

struct fd_gravity_key { uchar b[ FD_GRAVITY_SIG_PREFIX_SZ ]; };
typedef struct fd_gravity_key fd_gravity_key_t;

/* A dispatched node with txn_cnt transactions owns pack_idx values
   [pack_idx,pack_idx+txn_cnt): pack advances its pack_idx by the
   transaction count of a bundle, and the execle tiles publish each
   bundle transaction as its own microblock with pack_idx+i.  The
   node's result is sent once every transaction's outcome arrived. */

struct node {
  uint             pool_next;
  uint             map_next;
  fd_gravity_key_t key;            /* SigPrefix of the first transaction */
  uchar            first_sig[ 64 ];
  uchar            kind;
  uchar            txn_cnt;
  uchar            state;
  uchar            exec_mask;      /* bit i set once transaction i executed */
  uint             pack_idx;       /* pack_idx of transaction 0, if DISPATCHED */
  uint             pend_idx;       /* index in slot_nodes, if PENDING */
  ulong            graph_slot;
  ulong            dispatch_slot;
  ulong            exec_slot;
  uchar            uuid[ FD_GRAVITY_UUID_SZ ];
  uchar            prefixes[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ][ FD_GRAVITY_SIG_PREFIX_SZ ];
  uchar            bundle_id[ FD_GRAVITY_BUNDLE_ID_SZ ];
  ulong            received_at;
  ulong            forwarded_at;   /* dispatch time */
  ulong            jito_off;       /* retained Jito bundle the node was resolved from (logical offset+1), 0 if none */
  uint             exec_flags[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  uint             exec_cus  [ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
};
typedef struct node node_t;

FD_STATIC_ASSERT( FD_GRAVITY_MAX_TXN_PER_BUNDLE<=FD_PACK_MAX_TXN_PER_BUNDLE, bundle_sz );
FD_STATIC_ASSERT( FD_GRAVITY_MAX_TXN_PER_BUNDLE<=8UL,                        exec_mask_bits );

#define POOL_NAME  node_pool
#define POOL_T     node_t
#define POOL_NEXT  pool_next
#define POOL_IDX_T uint
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME              node_map
#define MAP_ELE_T             node_t
#define MAP_KEY_T             fd_gravity_key_t
#define MAP_KEY               key
#define MAP_NEXT              map_next
#define MAP_IDX_T             uint
#define MAP_KEY_EQ(k0,k1)     (!memcmp( (k0)->b, (k1)->b, FD_GRAVITY_SIG_PREFIX_SZ ))
#define MAP_KEY_HASH(k,seed)  fd_hash( (seed), (k)->b, FD_GRAVITY_SIG_PREFIX_SZ )
#include "../../../util/tmpl/fd_map_chain.c"

/* Retention ring ******************************************************/

/* Transactions received by pack are appended to a byte ring as
   records.  A lossy open addressing table maps SigPrefix -> logical
   ring offset.  A record at logical offset off is intact iff
   ret_w-off<=ret_sz (nothing has been written past off+ret_sz). */

struct ret_rec {
  uchar  prefix[ FD_GRAVITY_SIG_PREFIX_SZ ];
  ulong  sz;               /* record size, multiple of 8 */
  ushort payload_sz;
  ushort txn_t_sz;
  uchar  alt_cnt;
  uchar  source_tpu;
  uint   source_ipv4;
  long   first_seen_nanos;
  ulong  blockhash_height; /* reference block height from resolv, for native reinsertion */
  /* uchar payload[ payload_sz ], padding to alignof(fd_txn_t),
     txn_t[ txn_t_sz ], alt[ alt_cnt*32 ] */
};
typedef struct ret_rec ret_rec_t;

static inline ulong
ret_txn_off( ulong payload_sz ) {
  return fd_ulong_align_up( payload_sz, alignof(fd_txn_t) );
}

struct ret_ent {
  uchar prefix[ FD_GRAVITY_SIG_PREFIX_SZ ];
  ulong off;    /* logical offset + 1, 0 if empty */
};
typedef struct ret_ent ret_ent_t;

#define RET_PROBE (8UL)

/* Jito bundles are retained in the same ring, as a jito_rec followed by
   txn_cnt transaction records (ret_rec format).  A lossy table maps the
   bundle id to the record, and a FIFO list of the last JITO_MAX records
   is walked when windows change mode. */

#define JITO_MAX        (4096UL)                /* power of 2 */
#define JITO_UNSENT     (ULONG_MAX)             /* sent_window: not forwarded */
#define JITO_SENT_IDLE  (ULONG_MAX-1UL)         /* sent_window: forwarded outside a window */
#define JITO_REFWD_NS   (10000000000L)          /* re-forward bundles at most this old, 10 s */
#define JITO_NATIVE_NS  (60000000000L)          /* put bundles back in pack at most this old, ~150 slots */

struct jito_rec {
  uchar uuid[ 32 ];
  ulong off;              /* logical offset of this record */
  ulong sz;               /* record size including the transaction records, multiple of 8 */
  ulong blockhash_height;
  long  received_at;      /* first_seen_nanos of the first transaction */
  ulong sent_window;      /* window_id of the last forward, or JITO_UNSENT, JITO_SENT_IDLE */
  uchar txn_cnt;
  uchar in_pack;          /* inserted into pack natively */
  uchar done;             /* scheduled (or never schedulable) */
  uchar meta[ FD_GRAVITY_BUNDLE_META_MAX ];
};
typedef struct jito_rec jito_rec_t;

struct jito_ent {
  uchar uuid[ 32 ];
  ulong off;    /* logical offset + 1, 0 if empty */
};
typedef struct jito_ent jito_ent_t;

/* Per-graph builder order index ***************************************/

struct ord_ent {
  uint          gen;
  uint          kind;     /* FD_GRAVITY_NODE_{TX,BUNDLE} */
  uchar         key[ 32 ];
  uchar const * ptr;      /* WireSharableTx payload or WireSharableBundle */
  ulong         sz;       /* payload size (TX only) */
};
typedef struct ord_ent ord_ent_t;

struct fd_gravity {
  fd_gravity_cfg_t     cfg;
  fd_gravity_sess_t *  sess;

  node_t *             pool;
  node_map_t *         map;
  uint *               slot_nodes;     /* PENDING nodes (all from the current leader slot), unordered */
  ulong                slot_node_cnt;
  uint                 inflight[ FD_GRAVITY_INFLIGHT_CNT ]; /* DISPATCHED node idx+1 by pack_idx */

  uchar *              ret;
  ulong                ret_sz;
  ulong                ret_w;
  ret_ent_t *          ret_tbl;
  ulong                ret_tbl_mask;

  jito_ent_t *         jito_tbl;       /* 2*JITO_MAX entries */
  ulong *              jito_list;      /* JITO_MAX logical offsets+1 */
  ulong                jito_list_w;
  int                  jito_native;    /* a bundle went to pack natively since the last GRAVITY slot start */
  int                  jito_unsent;    /* a forward failed since the last GRAVITY slot start */
  int                  jito_diverted;  /* a bundle bypassed pack since the last NATIVE transition */

  ord_ent_t *          ord_tbl;
  ulong                ord_tbl_mask;
  uint                 ord_gen;

  /* Graph being inserted.  Its payload stays in the session receive
     buffer, which is not polled until the graph is done. */
  struct {
    int                active;
    int                accept;
    fd_gravity_graph_t graph;
    uchar const *      cur;
    ulong              idx;
    long               received_at;
  } gr;

  /* Leader / mode state */
  ulong                window_id;      /* slot/4 of the window the mode was decided for */
  int                  window_mode;
  int                  window_missed;  /* the window's last GRAVITY slot with forwarded orders scheduled nothing */
  int                  window_done;    /* window_end ran for window_id */
  int                  slot_mode;
  int                  latched;        /* failsafe tripped, see window_end */
  ulong                leader_slot;    /* ULONG_MAX if not leader */
  ulong                last_leader_slot; /* ULONG_MAX if never leader */
  ulong                block_height;
  long                 slot_start_ns;
  long                 slot_end_ns;
  ulong                slot_released;
  ulong                slot_dispatched;
  int                  slot_fwd;       /* an order was offered to the relay since the slot started */
  long                 active_since;   /* first Progress sent in session active_sess (and since the failsafe), 0 if none */
  ulong                active_sess;
  long                 next_poll_ns;
  long                 next_sweep_ns;

  /* Progress state */
  ulong                last_progress_slot;
  ulong                pending_progress; /* slot to announce once the next leader is known, 0 if none */
  long                 pending_deadline; /* announce it anyway at this time */
  ulong                last_completed_slot;
  ulong                next_leader_slot;
  int                  has_blockhash;
  uchar                last_blockhash[ 32 ];

  fd_gravity_metrics_t metrics;
};

FD_FN_CONST static inline ulong
ret_tbl_cnt( ulong retention_sz ) {
  return fd_ulong_pow2_up( fd_ulong_max( 2UL*retention_sz/256UL, 1024UL ) );
}

FD_FN_CONST static inline ulong
ord_tbl_cnt( ulong order_max ) {
  return fd_ulong_pow2_up( fd_ulong_max( 2UL*order_max, 64UL ) );
}

ulong
fd_gravity_align( void ) {
  return 128UL;
}

static int
cfg_valid( fd_gravity_cfg_t const * cfg ) {
  if( FD_UNLIKELY( !cfg->node_max || cfg->node_max>=UINT_MAX ) ) return 0;
  if( FD_UNLIKELY( cfg->retention_sz<(1UL<<20) || (cfg->retention_sz&7UL) ) ) return 0;
  if( FD_UNLIKELY( !cfg->num_threads ) ) return 0;
  if( FD_UNLIKELY( cfg->blacklist_cnt>FD_GRAVITY_BLACKLIST_MAX ) ) return 0;
  if( FD_UNLIKELY( cfg->bundle_meta_sz>FD_GRAVITY_BUNDLE_META_MAX ) ) return 0;
  if( FD_UNLIKELY( cfg->warmup_ns<0L ) ) return 0;
  /* The BundleV2 encoder takes at most 64 bytes of UTF-8 */
  for( ulong i=0UL; i<sizeof(cfg->bundle_uri); i++ ) {
    if( !cfg->bundle_uri[ i ] ) break;
    if( FD_UNLIKELY( i>=64UL || (uchar)cfg->bundle_uri[ i ]>=0x80U ) ) return 0;
  }
  return 1;
}

ulong
fd_gravity_footprint( fd_gravity_cfg_t const * cfg ) {
  if( FD_UNLIKELY( !cfg_valid( cfg ) ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gravity_t),    sizeof(fd_gravity_t) );
  l = FD_LAYOUT_APPEND( l, fd_gravity_sess_align(),  fd_gravity_sess_footprint( cfg->rx_max, cfg->tx_max ) );
  l = FD_LAYOUT_APPEND( l, node_pool_align(),        node_pool_footprint( cfg->node_max ) );
  l = FD_LAYOUT_APPEND( l, node_map_align(),         node_map_footprint( node_map_chain_cnt_est( cfg->node_max ) ) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            cfg->node_max*sizeof(uint) );
  l = FD_LAYOUT_APPEND( l, 64UL,                     cfg->retention_sz );
  l = FD_LAYOUT_APPEND( l, alignof(ret_ent_t),       ret_tbl_cnt( cfg->retention_sz )*sizeof(ret_ent_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ord_ent_t),       ord_tbl_cnt( cfg->order_max )*sizeof(ord_ent_t) );
  l = FD_LAYOUT_APPEND( l, alignof(jito_ent_t),      2UL*JITO_MAX*sizeof(jito_ent_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),           JITO_MAX*sizeof(ulong) );
  return FD_LAYOUT_FINI( l, fd_gravity_align() );
}

fd_gravity_t *
fd_gravity_new( void *                   mem,
                fd_gravity_cfg_t const * cfg ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  /* The footprint assumes an aligned base */
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_gravity_align() ) ) ) return NULL;
  if( FD_UNLIKELY( !cfg_valid( cfg ) ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_gravity_t * g        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gravity_t),   sizeof(fd_gravity_t) );
  void *         sess_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_gravity_sess_align(), fd_gravity_sess_footprint( cfg->rx_max, cfg->tx_max ) );
  void *         pool_mem = FD_SCRATCH_ALLOC_APPEND( l, node_pool_align(),       node_pool_footprint( cfg->node_max ) );
  ulong          chain_cnt = node_map_chain_cnt_est( cfg->node_max );
  void *         map_mem  = FD_SCRATCH_ALLOC_APPEND( l, node_map_align(),        node_map_footprint( chain_cnt ) );
  uint *         slot_nodes = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),         cfg->node_max*sizeof(uint) );
  uchar *        ret      = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                    cfg->retention_sz );
  ret_ent_t *    ret_tbl  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ret_ent_t),      ret_tbl_cnt( cfg->retention_sz )*sizeof(ret_ent_t) );
  ord_ent_t *    ord_tbl  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ord_ent_t),      ord_tbl_cnt( cfg->order_max )*sizeof(ord_ent_t) );
  jito_ent_t *   jito_tbl = FD_SCRATCH_ALLOC_APPEND( l, alignof(jito_ent_t),     2UL*JITO_MAX*sizeof(jito_ent_t) );
  ulong *        jito_list = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),         JITO_MAX*sizeof(ulong) );
  FD_SCRATCH_ALLOC_FINI( l, fd_gravity_align() );

  memset( g, 0, sizeof(fd_gravity_t) );
  g->cfg = *cfg;
  g->cfg.version   [ sizeof(g->cfg.version   )-1UL ] = '\0';
  g->cfg.bundle_uri[ sizeof(g->cfg.bundle_uri)-1UL ] = '\0';

  fd_gravity_handshake_t hs = {
    .version             = g->cfg.version,
    .num_threads         = cfg->num_threads,
    .filter_ofac         = cfg->filter_ofac,
    .blacklist_cnt       = cfg->blacklist_cnt,
    .blacklist           = cfg->blacklist_cnt ? cfg->blacklist[0] : NULL,
    .jito_tip_weight_bps = cfg->jito_tip_weight_bps,
  };
  g->sess = fd_gravity_sess_new( sess_mem, cfg->rx_max, cfg->tx_max, cfg->identity,
                                 cfg->relay_cnt, cfg->relay_ip4, cfg->relay_port, &hs );
  if( FD_UNLIKELY( !g->sess ) ) return NULL;

  g->pool = node_pool_join( node_pool_new( pool_mem, cfg->node_max ) );
  g->map  = node_map_join( node_map_new( map_mem, chain_cnt, 0x6772617669747975UL ) );
  if( FD_UNLIKELY( !g->pool || !g->map ) ) return NULL;
  g->slot_nodes = slot_nodes;

  g->ret          = ret;
  g->ret_sz       = cfg->retention_sz;
  g->ret_w        = 0UL;
  g->ret_tbl      = ret_tbl;
  g->ret_tbl_mask = ret_tbl_cnt( cfg->retention_sz )-1UL;
  memset( ret_tbl, 0, ret_tbl_cnt( cfg->retention_sz )*sizeof(ret_ent_t) );

  g->ord_tbl      = ord_tbl;
  g->ord_tbl_mask = ord_tbl_cnt( cfg->order_max )-1UL;
  memset( ord_tbl, 0, ord_tbl_cnt( cfg->order_max )*sizeof(ord_ent_t) );
  g->ord_gen      = 0U;

  g->jito_tbl     = jito_tbl;
  g->jito_list    = jito_list;
  memset( jito_tbl,  0, 2UL*JITO_MAX*sizeof(jito_ent_t) );
  memset( jito_list, 0, JITO_MAX*sizeof(ulong) );

  g->window_id           = ULONG_MAX;
  g->window_mode         = FD_GRAVITY_MODE_NATIVE;
  g->slot_mode           = FD_GRAVITY_MODE_NATIVE;
  g->leader_slot         = ULONG_MAX;
  g->last_leader_slot    = ULONG_MAX;
  g->last_progress_slot  = 0UL;
  g->last_completed_slot = ULONG_MAX;
  g->next_leader_slot    = ULONG_MAX;
  return g;
}

fd_gravity_sess_t *
fd_gravity_sess( fd_gravity_t * g ) {
  return g->sess;
}

fd_gravity_metrics_t const *
fd_gravity_metrics( fd_gravity_t const * g ) {
  return &g->metrics;
}

int
fd_gravity_failsafe( fd_gravity_t const * g ) {
  return g->latched;
}

int
fd_gravity_mode( fd_gravity_t const * g ) {
  return g->slot_mode;
}

void
fd_gravity_set_identity( fd_gravity_t * g,
                         uchar const    identity[ static 32 ],
                         long           now ) {
  fd_memcpy( g->cfg.identity, identity, 32UL );
  fd_gravity_sess_set_identity( g->sess, identity, now );
}

/* window_open returns 1 between the first leader slot of a window
   (or leadership of adjacent windows) and its end (window_end). */

static inline int
window_open( fd_gravity_t const * g ) {
  return g->window_id!=ULONG_MAX && !g->window_done;
}

/* Retention ***********************************************************/

static inline int
ret_valid( fd_gravity_t const * g,
           ulong                off ) {
  return g->ret_w-off<=g->ret_sz;
}

static ret_rec_t const *
ret_query( fd_gravity_t * g,
           uchar const    prefix[ static FD_GRAVITY_SIG_PREFIX_SZ ] ) {
  ulong h = fd_hash( 0x726574656e74UL, prefix, FD_GRAVITY_SIG_PREFIX_SZ );
  for( ulong i=0UL; i<RET_PROBE; i++ ) {
    ret_ent_t const * e = g->ret_tbl + ((h+i) & g->ret_tbl_mask);
    if( !e->off ) return NULL;
    if( memcmp( e->prefix, prefix, FD_GRAVITY_SIG_PREFIX_SZ ) ) continue;
    ulong off = e->off-1UL;
    if( FD_UNLIKELY( !ret_valid( g, off ) ) ) return NULL;
    ret_rec_t const * rec = (ret_rec_t const *)( g->ret + (off % g->ret_sz) );
    if( FD_UNLIKELY( memcmp( rec->prefix, prefix, FD_GRAVITY_SIG_PREFIX_SZ ) ) ) return NULL;
    return rec;
  }
  return NULL;
}

static inline void *
ret_laddr( fd_gravity_t const * g,
           ulong                off ) {
  return g->ret + (off % g->ret_sz);
}

/* ret_alloc reserves sz contiguous bytes (a multiple of 8, at most
   ret_sz) at the head of the ring and returns their logical offset. */

static ulong
ret_alloc( fd_gravity_t * g,
           ulong          sz ) {
  ulong phys = g->ret_w % g->ret_sz;
  if( FD_UNLIKELY( phys+sz>g->ret_sz ) ) g->ret_w += g->ret_sz-phys; /* wrap */
  ulong off = g->ret_w;
  g->ret_w += sz;
  return off;
}

static ulong
ret_rec_sz( fd_txn_e_t const * txne ) {
  fd_txn_t const * txn = TXN( txne->txnp );
  return fd_ulong_align_up( sizeof(ret_rec_t) + ret_txn_off( txne->txnp->payload_sz ) +
                            fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ) + 32UL*txn->addr_table_adtl_cnt, 8UL );
}

/* ret_rec_write writes txne as a ret_rec_sz( txne ) byte record */

static void
ret_rec_write( ret_rec_t *        rec,
               fd_txn_e_t const * txne,
               ulong              blockhash_height ) {
  fd_txn_p_t const * txnp     = txne->txnp;
  fd_txn_t const *   txn      = TXN( txnp );
  ulong              txn_t_sz = fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt );
  ulong              alt_cnt  = txn->addr_table_adtl_cnt;
  fd_memcpy( rec->prefix, txnp->payload + txn->signature_off, FD_GRAVITY_SIG_PREFIX_SZ );
  rec->sz               = ret_rec_sz( txne );
  rec->payload_sz       = txnp->payload_sz;
  rec->txn_t_sz         = (ushort)txn_t_sz;
  rec->alt_cnt          = (uchar)alt_cnt;
  rec->source_tpu       = txnp->source_tpu;
  rec->source_ipv4      = txnp->source_ipv4;
  rec->first_seen_nanos = txnp->first_seen_nanos;
  rec->blockhash_height = blockhash_height;
  uchar * p = (uchar *)(rec+1);
  fd_memcpy( p, txnp->payload,   txnp->payload_sz ); p += ret_txn_off( txnp->payload_sz );
  fd_memcpy( p, txn,             txn_t_sz         ); p += txn_t_sz;
  fd_memcpy( p, txne->alt_accts, 32UL*alt_cnt     );
}

static void
ret_insert( fd_gravity_t *     g,
            fd_txn_e_t const * txne,
            ulong              blockhash_height ) {
  ulong rec_sz = ret_rec_sz( txne );
  if( FD_UNLIKELY( rec_sz>g->ret_sz ) ) return;
  ulong       off = ret_alloc( g, rec_sz );
  ret_rec_t * rec = ret_laddr( g, off );
  ret_rec_write( rec, txne, blockhash_height );
  uchar const * sig = rec->prefix;

  /* Insert in the first empty, stale or matching slot of the probe
     window, otherwise replace the oldest entry. */
  ulong h      = fd_hash( 0x726574656e74UL, sig, FD_GRAVITY_SIG_PREFIX_SZ );
  ret_ent_t * victim = NULL;
  for( ulong i=0UL; i<RET_PROBE; i++ ) {
    ret_ent_t * e = g->ret_tbl + ((h+i) & g->ret_tbl_mask);
    if( !e->off || !ret_valid( g, e->off-1UL ) || !memcmp( e->prefix, sig, FD_GRAVITY_SIG_PREFIX_SZ ) ) { victim = e; break; }
    if( !victim || e->off<victim->off ) victim = e;
  }
  fd_memcpy( victim->prefix, sig, FD_GRAVITY_SIG_PREFIX_SZ );
  victim->off = off+1UL;
}

/* Sending *************************************************************/

static void
send_progress( fd_gravity_t * g,
               ulong          slot,
               long           observed_at,
               int            leading,
               long           now ) {
  /* While the failsafe is latched the relay must not sequence us, as
     with a connector held by its failsafe. */
  if( FD_UNLIKELY( !fd_gravity_sess_is_ready( g->sess ) || g->latched ) ) return;
  fd_gravity_progress_t p = {
    .slot                  = slot,
    .observed_at           = (ulong)observed_at,
    .current_slot_progress = 0,
    .has_duration_override = 0,
    .has_latest_blockhash  = g->has_blockhash,
  };
  if( leading ) {
    p.has_next_leadership   = 1;
    p.next_leadership_start = slot - (slot&3UL);
    p.next_leadership_end   = p.next_leadership_start+3UL;
  } else if( g->next_leader_slot!=ULONG_MAX && g->next_leader_slot>=slot ) {
    p.has_next_leadership   = 1;
    p.next_leadership_start = g->next_leader_slot - (g->next_leader_slot&3UL);
    p.next_leadership_end   = p.next_leadership_start+3UL;
  }
  if( g->has_blockhash ) fd_memcpy( p.latest_blockhash, g->last_blockhash, 32UL );

  uchar * buf = fd_gravity_sess_tx_prepare( g->sess, 128UL );
  if( FD_UNLIKELY( !buf ) ) { fd_gravity_sess_reset( g->sess, FD_GRAVITY_SESS_RESET_TX_FULL, now ); return; }
  ulong sz = fd_gravity_encode_progress( buf, 128UL, &p );
  FD_TEST( sz );
  fd_gravity_sess_tx_publish( g->sess, sz, now );
  g->last_progress_slot = fd_ulong_max( g->last_progress_slot, slot );
  g->metrics.progress_sent++;
  if( !g->active_since || g->active_sess!=g->sess->session_cnt ) {
    g->active_since = fd_long_max( now, 1L );
    g->active_sess  = g->sess->session_cnt;
  }
}

/* send_result sends one ExecutionResult.  kind/id describe the node,
   res[0,cnt) are the per transaction results. */

static void
send_result( fd_gravity_t *              g,
             ulong                       graph_slot,
             uchar const *               uuid,
             uint                        kind,
             uchar const *               id,
             ulong                       cnt,
             fd_gravity_result_t const * res,
             uchar                       worker,
             ulong                       received_at,
             ulong                       forwarded_at,
             ulong                       res_received_at,
             long                        now ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( res[i].kind==FD_GRAVITY_RESULT_INCLUDED ) g->metrics.results_included++;
    else                                          g->metrics.results_not_included++;
  }
  if( worker==FD_GRAVITY_WORKER_SYNTHETIC ) g->metrics.results_synthetic++;
  if( FD_UNLIKELY( !fd_gravity_sess_is_ready( g->sess ) ) ) return;

  uchar flat[ FD_GRAVITY_MAX_TXN_PER_BUNDLE*FD_GRAVITY_SIG_PREFIX_SZ ];
  fd_gravity_exec_result_t r = {
    .slot              = graph_slot,
    .result_cnt        = cnt,
    .results           = res,
    .batch_received_at = received_at,
    .forwarded_at      = forwarded_at,
    .res_received_at   = res_received_at,
    .worker            = worker,
  };
  fd_memcpy( r.uuid, uuid, FD_GRAVITY_UUID_SZ );
  if( kind==FD_GRAVITY_NODE_BUNDLE ) {
    r.bundle_id = id;
  } else {
    /* A transaction node is a single transaction */
    fd_memcpy( flat, id, FD_GRAVITY_SIG_PREFIX_SZ );
    r.sig_prefix_cnt = 1UL;
    r.sig_prefixes   = flat;
  }

  uchar * buf = fd_gravity_sess_tx_prepare( g->sess, 1024UL );
  if( FD_UNLIKELY( !buf ) ) { fd_gravity_sess_reset( g->sess, FD_GRAVITY_SESS_RESET_TX_FULL, now ); return; }
  ulong sz = fd_gravity_encode_exec_result( buf, 1024UL, &r );
  if( FD_UNLIKELY( !sz ) ) {
    FD_LOG_WARNING(( "gravity: failed to encode execution result" ));
    return;
  }
  fd_gravity_sess_tx_publish( g->sess, sz, now );
}

/* reject sends NotIncluded results for a node of cnt transactions that
   was not executed, in the shape gravity-types reject_orders uses (and
   execle uses for a failed bundle): reason for transaction fail_idx,
   ALL_OR_NOTHING for the others.  As in reject_orders, the forward and
   result times are zero. */

static void
reject( fd_gravity_t * g,
        ulong          graph_slot,
        uchar const *  uuid,
        uint           kind,
        uchar const *  id,
        ulong          cnt,
        ulong          fail_idx,
        uint           reason,
        ulong          received_at,
        long           now ) {
  fd_gravity_result_t res[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  cnt      = fd_ulong_min( fd_ulong_max( cnt, 1UL ), FD_GRAVITY_MAX_TXN_PER_BUNDLE );
  fail_idx = fd_ulong_min( fail_idx, cnt-1UL );
  for( ulong i=0UL; i<cnt; i++ ) {
    res[i] = (fd_gravity_result_t){ .kind   = FD_GRAVITY_RESULT_NOT_INCLUDED,
                                    .reason = i==fail_idx ? reason : FD_GRAVITY_NI_ALL_OR_NOTHING };
  }
  send_result( g, graph_slot, uuid, kind, id, cnt, res, FD_GRAVITY_WORKER_SYNTHETIC, received_at, 0UL, 0UL, now );
}

static void
node_reject( fd_gravity_t * g,
             node_t *       n,
             uint           reason,
             long           now ) {
  reject( g, n->graph_slot, n->uuid, n->kind,
          n->kind==FD_GRAVITY_NODE_BUNDLE ? n->bundle_id : n->prefixes[0],
          n->txn_cnt, 0UL, reason, n->received_at, now );
}

/* slot_nodes holds exactly the PENDING nodes.  Removal swaps in the
   last entry, so the array never holds stale or duplicate entries and
   never grows past node_max. */

static inline void
pend_add( fd_gravity_t * g,
          node_t *       n ) {
  n->pend_idx = (uint)g->slot_node_cnt;
  g->slot_nodes[ g->slot_node_cnt++ ] = (uint)node_pool_idx( g->pool, n );
}

static inline void
pend_remove( fd_gravity_t * g,
             node_t *       n ) {
  uint moved = g->slot_nodes[ --g->slot_node_cnt ];
  g->slot_nodes[ n->pend_idx ] = moved;
  node_pool_ele( g->pool, moved )->pend_idx = n->pend_idx;
}

static inline uint *
inflight_ent( fd_gravity_t * g,
              uint           pack_idx ) {
  return g->inflight + ((ulong)pack_idx & (FD_GRAVITY_INFLIGHT_CNT-1UL));
}

static void
node_free( fd_gravity_t * g,
           node_t *       n ) {
  if( n->state==NODE_STATE_PENDING ) pend_remove( g, n );
  if( n->state==NODE_STATE_DISPATCHED ) {
    uint self = (uint)node_pool_idx( g->pool, n )+1U;
    for( ulong i=0UL; i<n->txn_cnt; i++ ) {
      uint * ent = inflight_ent( g, n->pack_idx+(uint)i );
      if( *ent==self ) *ent = 0U;
    }
  }
  node_map_ele_remove( g->map, &n->key, NULL, g->pool );
  n->state = 0;
  node_pool_ele_release( g->pool, n );
}

/* Lane ****************************************************************/

static uint
insert_reject_reason( int retval ) {
  switch( retval ) {
  case FD_PACK_INSERT_REJECT_PRIORITY:        return FD_GRAVITY_NI_WOULD_EXCEED_BLOCK_COST;
  case FD_PACK_INSERT_REJECT_TOO_LARGE:       return FD_GRAVITY_NI_WOULD_EXCEED_BLOCK_COST;
  case FD_PACK_INSERT_REJECT_NONCE_PRIORITY:
  case FD_PACK_INSERT_REJECT_EXPIRED:
  case FD_PACK_INSERT_REJECT_INVALID_NONCE:
  case FD_PACK_INSERT_REJECT_NONCE_CONFLICT:  return FD_GRAVITY_NI_BLOCKHASH_NOT_FOUND;
  case FD_PACK_INSERT_REJECT_DUPLICATE:       return FD_GRAVITY_NI_ALREADY_PROCESSED;
  case FD_PACK_INSERT_REJECT_UNAFFORDABLE:    return FD_GRAVITY_NI_INSUFFICIENT_FUNDS_FOR_FEE;
  case FD_PACK_INSERT_REJECT_ADDR_LUT:        return FD_GRAVITY_NI_ALT_NOT_FOUND;
  case FD_PACK_INSERT_REJECT_ACCOUNT_CNT:     return FD_GRAVITY_NI_TOO_MANY_ACCOUNT_LOCKS;
  case FD_PACK_INSERT_REJECT_DUPLICATE_ACCT:  return FD_GRAVITY_NI_ACCOUNT_LOADED_TWICE;
  case FD_PACK_INSERT_REJECT_ACCT_BLOCKLIST:  /* advertised in the handshake, builders shouldn't send these */
  default:                                    return FD_GRAVITY_NI_SANITIZE_FAILURE;
  }
}

static void
ord_index( fd_gravity_t *             g,
           fd_gravity_graph_t const * graph ) {
  g->ord_gen++;
  if( FD_UNLIKELY( !g->ord_gen ) ) { /* wrapped, clear stale entries */
    memset( g->ord_tbl, 0, (g->ord_tbl_mask+1UL)*sizeof(ord_ent_t) );
    g->ord_gen = 1U;
  }
  ulong budget = g->cfg.order_max;
  if( FD_UNLIKELY( graph->order_txn_cnt+graph->order_bundle_cnt>budget ) ) {
    FD_LOG_WARNING(( "gravity: graph has %lu builder orders, only indexing %lu",
                     graph->order_txn_cnt+graph->order_bundle_cnt, budget ));
  }

  uchar const * cur = graph->order_txns;
  for( ulong i=0UL; i<graph->order_txn_cnt && budget; i++ ) {
    uchar const * txn; ulong txn_sz;
    cur = fd_gravity_order_txn_next( cur, &txn, &txn_sz );
    uchar key[ 32 ] = {0};
    if( FD_UNLIKELY( fd_gravity_sig_prefix( txn, txn_sz, key ) ) ) continue;
    ulong h = fd_hash( g->ord_gen, key, 32UL ) & g->ord_tbl_mask;
    for(;;) {
      ord_ent_t * e = g->ord_tbl+h;
      if( e->gen!=g->ord_gen ) {
        e->gen  = g->ord_gen;
        e->kind = FD_GRAVITY_NODE_TX;
        fd_memcpy( e->key, key, 32UL );
        e->ptr  = txn;
        e->sz   = txn_sz;
        budget--;
        break;
      }
      if( e->kind==FD_GRAVITY_NODE_TX && !memcmp( e->key, key, 32UL ) ) break; /* duplicate, keep first */
      h = (h+1UL) & g->ord_tbl_mask;
    }
  }

  cur = graph->order_bundles;
  for( ulong i=0UL; i<graph->order_bundle_cnt && budget; i++ ) {
    uchar const * start = cur;
    fd_gravity_bundle_t b;
    cur = fd_gravity_order_bundle_next( cur, &b );
    ulong h = fd_hash( g->ord_gen^1U, b.ext_uuid, 32UL ) & g->ord_tbl_mask;
    for(;;) {
      ord_ent_t * e = g->ord_tbl+h;
      if( e->gen!=g->ord_gen ) {
        e->gen  = g->ord_gen;
        e->kind = FD_GRAVITY_NODE_BUNDLE;
        fd_memcpy( e->key, b.ext_uuid, 32UL );
        e->ptr  = start;
        e->sz   = 0UL;
        budget--;
        break;
      }
      if( e->kind==FD_GRAVITY_NODE_BUNDLE && !memcmp( e->key, b.ext_uuid, 32UL ) ) break;
      h = (h+1UL) & g->ord_tbl_mask;
    }
  }
}

static ord_ent_t const *
ord_query( fd_gravity_t const * g,
           uint                 kind,
           uchar const *        id ) {
  uchar key[ 32 ] = {0};
  ulong h;
  if( kind==FD_GRAVITY_NODE_TX ) {
    fd_memcpy( key, id, FD_GRAVITY_SIG_PREFIX_SZ );
    h = fd_hash( g->ord_gen, key, 32UL );
  } else {
    fd_memcpy( key, id, 32UL );
    h = fd_hash( g->ord_gen^1U, key, 32UL );
  }
  h &= g->ord_tbl_mask;
  for( ulong i=0UL; i<=g->ord_tbl_mask; i++ ) {
    ord_ent_t const * e = g->ord_tbl+h;
    if( e->gen!=g->ord_gen ) return NULL;
    if( e->kind==kind && !memcmp( e->key, key, 32UL ) ) return e;
    h = (h+1UL) & g->ord_tbl_mask;
  }
  return NULL;
}

/* A member is either a retained record or raw builder bytes. */

typedef struct {
  ret_rec_t const * rec;
  uchar const *     txn;
  ulong             txn_sz;
} member_t;

/* fill_txn populates a pack transaction slot from a member.  Returns 0
   on success or a NotIncluded reason. */

static uint
fill_txn( fd_gravity_t *   g,
          fd_txn_e_t *     txne,
          member_t const * m,
          long             now ) {
  fd_txn_p_t * txnp = txne->txnp;
  if( m->rec ) {
    ret_rec_t const * rec = m->rec;
    uchar const * p = (uchar const *)(rec+1);
    fd_memcpy( txnp->payload,  p, rec->payload_sz ); p += ret_txn_off( rec->payload_sz );
    fd_memcpy( TXN( txnp ),    p, rec->txn_t_sz   ); p += rec->txn_t_sz;
    fd_memcpy( txne->alt_accts, p, 32UL*rec->alt_cnt );
    txnp->payload_sz       = rec->payload_sz;
    txnp->source_tpu       = rec->source_tpu;
    txnp->source_ipv4      = rec->source_ipv4;
    txnp->first_seen_nanos = rec->first_seen_nanos;
  } else {
    if( FD_UNLIKELY( m->txn_sz>FD_TPU_MTU ) ) return FD_GRAVITY_NI_SANITIZE_FAILURE;
    fd_memcpy( txnp->payload, m->txn, m->txn_sz );
    if( FD_UNLIKELY( !fd_txn_parse( txnp->payload, m->txn_sz, TXN( txnp ), NULL ) ) ) return FD_GRAVITY_NI_SANITIZE_FAILURE;
    if( FD_UNLIKELY( TXN( txnp )->addr_table_lookup_cnt ) ) {
      g->metrics.nodes_alt++;
      return FD_GRAVITY_NI_ALT_NOT_FOUND;
    }
    txnp->payload_sz       = (ushort)m->txn_sz;
    txnp->source_tpu       = FD_TXN_M_TPU_SOURCE_BUNDLE;
    txnp->source_ipv4      = 0U;
    txnp->first_seen_nanos = now;
  }
  txnp->scheduler_arrival_time_nanos = now;
  txnp->flags                        = 0U; /* pack slots are recycled, don't inherit stale flags */
  return 0U;
}

/* Jito bundles ********************************************************/

static jito_rec_t *
jito_query( fd_gravity_t const * g,
            uchar const          uuid[ static 32 ] ) {
  ulong h = fd_hash( 0x6a69746fUL, uuid, 32UL );
  for( ulong i=0UL; i<RET_PROBE; i++ ) {
    jito_ent_t const * e = g->jito_tbl + ((h+i) & (2UL*JITO_MAX-1UL));
    if( !e->off ) return NULL;
    if( memcmp( e->uuid, uuid, 32UL ) ) continue;
    ulong off = e->off-1UL;
    if( FD_UNLIKELY( !ret_valid( g, off ) ) ) return NULL;
    jito_rec_t * rec = ret_laddr( g, off );
    if( FD_UNLIKELY( memcmp( rec->uuid, uuid, 32UL ) ) ) return NULL;
    return rec;
  }
  return NULL;
}

/* jito_query_txns looks up the retained Jito bundle with the given
   serialized transactions, by the id Jito derives from them. */

static jito_rec_t *
jito_query_txns( fd_gravity_t const *  g,
                 ulong                 cnt,
                 uchar const * const * txn,
                 ulong const *         txn_sz ) {
  uchar const * sigs[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  if( FD_UNLIKELY( !cnt || cnt>FD_GRAVITY_MAX_TXN_PER_BUNDLE ) ) return NULL;
  for( ulong i=0UL; i<cnt; i++ ) {
    sigs[i] = fd_gravity_first_sig( txn[i], txn_sz[i] );
    if( FD_UNLIKELY( !sigs[i] ) ) return NULL;
  }
  uchar uuid[ 32 ];
  fd_gravity_jito_bundle_id( uuid, cnt, sigs );
  return jito_query( g, uuid );
}

static jito_rec_t *
jito_store( fd_gravity_t *       g,
            uchar const          uuid[ static 32 ],
            fd_txn_e_t * const * bundle,
            ulong                txn_cnt,
            ulong                blockhash_height,
            void const *         meta ) {
  ulong sz = sizeof(jito_rec_t);
  for( ulong i=0UL; i<txn_cnt; i++ ) sz += ret_rec_sz( bundle[i] );
  if( FD_UNLIKELY( sz>g->ret_sz ) ) return NULL;

  ulong        off = ret_alloc( g, sz );
  jito_rec_t * rec = ret_laddr( g, off );
  fd_memcpy( rec->uuid, uuid, 32UL );
  rec->off              = off;
  rec->sz               = sz;
  rec->blockhash_height = blockhash_height;
  rec->received_at      = bundle[0]->txnp->first_seen_nanos;
  rec->sent_window      = JITO_UNSENT;
  rec->txn_cnt          = (uchar)txn_cnt;
  rec->in_pack          = 0;
  rec->done             = 0;
  memset( rec->meta, 0, sizeof(rec->meta) );
  if( meta ) fd_memcpy( rec->meta, meta, g->cfg.bundle_meta_sz );
  uchar * p = (uchar *)(rec+1);
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    ret_rec_write( (ret_rec_t *)p, bundle[i], blockhash_height );
    p += ((ret_rec_t *)p)->sz;
  }

  ulong h = fd_hash( 0x6a69746fUL, uuid, 32UL );
  jito_ent_t * victim = NULL;
  for( ulong i=0UL; i<RET_PROBE; i++ ) {
    jito_ent_t * e = g->jito_tbl + ((h+i) & (2UL*JITO_MAX-1UL));
    if( !e->off || !ret_valid( g, e->off-1UL ) || !memcmp( e->uuid, uuid, 32UL ) ) { victim = e; break; }
    if( !victim || e->off<victim->off ) victim = e;
  }
  fd_memcpy( victim->uuid, uuid, 32UL );
  victim->off = off+1UL;
  g->jito_list[ (g->jito_list_w++) & (JITO_MAX-1UL) ] = off+1UL;
  return rec;
}

/* jito_members points m[0,txn_cnt) at a retained bundle's transactions
   and returns txn_cnt. */

static ulong
jito_members( jito_rec_t const * rec,
              member_t *         m ) {
  uchar const * p = (uchar const *)(rec+1);
  for( ulong i=0UL; i<rec->txn_cnt; i++ ) {
    m[i] = (member_t){ .rec = (ret_rec_t const *)p };
    p += m[i].rec->sz;
  }
  return rec->txn_cnt;
}

/* jito_divert returns 1 if Jito bundles currently go to the relay
   instead of pack: during a window if it is GRAVITY, outside windows if
   the session is up (the next window is likely GRAVITY). */

static int
jito_divert( fd_gravity_t const * g ) {
  if( !fd_gravity_sess_is_ready( g->sess ) || g->latched ) return 0;
  if( window_open( g ) ) return g->window_mode==FD_GRAVITY_MODE_GRAVITY;
  return 1;
}

/* jito_forward sends a retained bundle to the relay as BundleV2.
   Returns 1 on success. */

static int
jito_forward( fd_gravity_t * g,
              jito_rec_t *   rec,
              long           now ) {
  if( FD_UNLIKELY( !fd_gravity_sess_is_ready( g->sess ) || g->latched ) ) return 0;
  g->slot_fwd = 1;
  /* A bundle that bypassed pack has no copy there, so it gets more of the
     buffer than forwarded transactions before being dropped. */
  if( FD_UNLIKELY( fd_gravity_sess_tx_free( g->sess )<g->sess->tx_max/8UL ) ) {
    g->metrics.jito_fwd_dropped++;
    return 0;
  }
  uchar const * txn   [ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  ulong         txn_sz[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  member_t      m     [ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  ulong         cnt    = jito_members( rec, m );
  ulong         max_sz = 128UL + sizeof(g->cfg.bundle_uri);
  for( ulong i=0UL; i<cnt; i++ ) {
    txn   [i] = (uchar const *)(m[i].rec+1);
    txn_sz[i] = m[i].rec->payload_sz;
    max_sz   += 8UL+txn_sz[i];
  }
  uchar * buf = fd_gravity_sess_tx_prepare( g->sess, max_sz );
  if( FD_UNLIKELY( !buf ) ) { g->metrics.jito_fwd_dropped++; return 0; }
  ulong sz = fd_gravity_encode_bundle_v2( buf, max_sz, rec->uuid, cnt, txn, txn_sz, g->cfg.bundle_uri,
                                          (ulong)rec->received_at, (ulong)now );
  if( FD_UNLIKELY( !sz ) ) { g->metrics.jito_fwd_dropped++; return 0; }
  fd_gravity_sess_tx_publish( g->sess, sz, now );
  g->metrics.jito_fwd++;
  rec->sent_window = window_open( g ) ? g->window_id : JITO_SENT_IDLE;
  return 1;
}

/* jito_to_relay runs at the start of a GRAVITY slot, after pack's
   native Jito bundles were deleted.  It forwards retained bundles that
   were in pack, whose forward failed, or that were forwarded before
   this window: the relay passes an order on to builders only once, and
   only while a leader is near. */

static void
jito_to_relay( fd_gravity_t * g,
               long           now ) {
  for( ulong i=0UL; i<JITO_MAX; i++ ) {
    ulong o = g->jito_list[ i ];
    if( !o ) continue;
    if( FD_UNLIKELY( !ret_valid( g, o-1UL ) ) ) { g->jito_list[ i ] = 0UL; continue; }
    jito_rec_t * rec = ret_laddr( g, o-1UL );
    if( rec->done ) continue;
    if( rec->in_pack ) g->jito_diverted = 1; /* deleted from pack: jito_to_pack puts it back */
    rec->in_pack = 0;
    if( rec->sent_window!=g->window_id && now-rec->received_at<JITO_REFWD_NS ) jito_forward( g, rec, now );
  }
  g->jito_native = 0;
  g->jito_unsent = 0;
}

/* jito_to_pack runs when a window goes NATIVE: retained bundles that
   bypassed pack are inserted into it. */

static void
jito_to_pack( fd_gravity_t * g,
              fd_pack_t *    pack,
              long           now ) {
  for( ulong i=0UL; i<JITO_MAX; i++ ) {
    ulong o = g->jito_list[ i ];
    if( !o ) continue;
    if( FD_UNLIKELY( !ret_valid( g, o-1UL ) ) ) { g->jito_list[ i ] = 0UL; continue; }
    jito_rec_t * rec = ret_laddr( g, o-1UL );
    if( rec->done || rec->in_pack ) continue;
    if( now-rec->received_at>=JITO_NATIVE_NS ) { rec->done = 1; continue; }

    member_t     m[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
    ulong        cnt = jito_members( rec, m );
    fd_txn_e_t * _bundle[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
    fd_txn_e_t * const * bundle = fd_pack_insert_bundle_init( pack, _bundle, cnt );
    int ok = 1;
    for( ulong j=0UL; j<cnt && ok; j++ ) ok = !fill_txn( g, bundle[j], m+j, now );
    if( FD_UNLIKELY( !ok ) ) {
      fd_pack_insert_bundle_cancel( pack, bundle, cnt );
      rec->done = 1;
      continue;
    }
    ulong deleted;
    int retval = fd_pack_insert_bundle_fini( pack, bundle, cnt, rec->blockhash_height, 0,
                                             g->cfg.bundle_meta_sz ? rec->meta : NULL, &deleted );
    if( FD_LIKELY( retval>=0 ) ) { rec->in_pack = 1; g->metrics.jito_reinserted++; }
    else                         rec->done = 1;
  }
  g->jito_diverted = 0;
}

/* jito_scheduled marks the retained copy of a bundle pack scheduled
   natively as done. */

static void
jito_scheduled( fd_gravity_t *     g,
                fd_txn_e_t const * out,
                ulong              txn_cnt ) {
  if( FD_UNLIKELY( !txn_cnt || txn_cnt>FD_GRAVITY_MAX_TXN_PER_BUNDLE ) ) return;
  uchar const * sigs[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  for( ulong i=0UL; i<txn_cnt; i++ ) sigs[i] = out[i].txnp->payload + TXN( out[i].txnp )->signature_off;
  uchar uuid[ 32 ];
  fd_gravity_jito_bundle_id( uuid, txn_cnt, sigs );
  jito_rec_t * rec = jito_query( g, uuid );
  if( rec ) rec->done = 1;
}

/* lane_insert resolves a node and inserts it into pack as a bundle.
   Returns 0 on success, or a NotIncluded reason and sets *txn_cnt to
   the number of results to report and *fail_idx to the transaction the
   reason applies to. */

static uint
lane_insert( fd_gravity_t *             g,
             fd_pack_t *                pack,
             void const *               bundle_meta,
             fd_gravity_graph_t const * graph,
             fd_gravity_node_t const *  gn,
             long                       received_at,
             long                       now,
             ulong *                    txn_cnt,
             ulong *                    fail_idx ) {
  member_t     m[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  ulong        cnt = 0UL;
  jito_rec_t * jr  = NULL;
  *txn_cnt  = 1UL;
  *fail_idx = 0UL;

  if( gn->kind==FD_GRAVITY_NODE_TX ) {
    m[0].rec = ret_query( g, gn->id );
    if( m[0].rec ) {
      g->metrics.retention_hit++;
    } else {
      ord_ent_t const * e = ord_query( g, FD_GRAVITY_NODE_TX, gn->id );
      if( FD_UNLIKELY( !e ) ) { g->metrics.retention_miss++; g->metrics.nodes_unknown++; return FD_GRAVITY_NI_UNKNOWN_ORDERS; }
      m[0].txn = e->ptr; m[0].txn_sz = e->sz;
    }
    cnt = 1UL;
  } else {
    /* A Jito bundle we forwarded comes without bytes.  One the builder
       first saw from another connector comes with bytes under that
       connector's id: if we hold it too, use our copy, whose address
       lookup tables are resolved. */
    fd_gravity_bundle_t b = {0};
    jr = jito_query( g, gn->id );
    if( !jr ) {
      ord_ent_t const * e = ord_query( g, FD_GRAVITY_NODE_BUNDLE, gn->id );
      if( FD_UNLIKELY( !e ) ) { g->metrics.nodes_unknown++; return FD_GRAVITY_NI_UNKNOWN_ORDERS; }
      fd_gravity_order_bundle_next( e->ptr, &b );
      if( FD_UNLIKELY( !b.txn_cnt ) ) { g->metrics.nodes_unknown++; return FD_GRAVITY_NI_UNKNOWN_ORDERS; }
      jr = jito_query_txns( g, b.txn_cnt, b.txn, b.txn_sz );
    }
    if( jr ) {
      cnt = jito_members( jr, m );
      g->metrics.jito_hit++;
    } else {
      cnt = b.txn_cnt;
      for( ulong i=0UL; i<cnt; i++ ) { m[i].rec = NULL; m[i].txn = b.txn[i]; m[i].txn_sz = b.txn_sz[i]; }
    }
    *txn_cnt = cnt;
  }

  if( FD_UNLIKELY( !node_pool_free( g->pool ) ) ) return FD_GRAVITY_NI_SLOT_ENDED;

  fd_txn_e_t * _bundle[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  fd_txn_e_t * const * bundle = fd_pack_insert_bundle_init( pack, _bundle, cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    uint reason = fill_txn( g, bundle[i], m+i, now );
    if( FD_UNLIKELY( reason ) ) {
      fd_pack_insert_bundle_cancel( pack, bundle, cnt );
      *fail_idx = i;
      return reason;
    }
  }

  /* fd_pack_delete_transaction (which purge and on_schedule use) relies
     on a bundle never holding two transactions with the same signature:
     it deletes the whole bundle while iterating over the signature's
     chain, so a repeat would be a use after free.  Builder bytes are
     not verified, so check. */
  for( ulong i=1UL; i<cnt; i++ ) {
    fd_txn_p_t const * ti = bundle[i]->txnp;
    for( ulong j=0UL; j<i; j++ ) {
      fd_txn_p_t const * tj = bundle[j]->txnp;
      if( FD_UNLIKELY( !memcmp( ti->payload+TXN( ti )->signature_off, tj->payload+TXN( tj )->signature_off, 64UL ) ) ) {
        fd_pack_insert_bundle_cancel( pack, bundle, cnt );
        *fail_idx = i;
        return FD_GRAVITY_NI_ALREADY_PROCESSED;
      }
    }
  }

  /* Duplicate guard: pack deletes by signature, so two pending lane
     nodes may not share a first signature. */
  fd_txn_p_t const * first = bundle[0]->txnp;
  uchar const *      sig0  = first->payload + TXN( first )->signature_off;
  fd_gravity_key_t   key;
  fd_memcpy( key.b, sig0, FD_GRAVITY_SIG_PREFIX_SZ );
  if( FD_UNLIKELY( node_map_ele_query( g->map, &key, NULL, g->pool ) ) ) {
    fd_pack_insert_bundle_cancel( pack, bundle, cnt );
    return FD_GRAVITY_NI_ALREADY_PROCESSED;
  }

  node_t * n = node_pool_ele_acquire( g->pool );
  n->key          = key;
  fd_memcpy( n->first_sig, sig0, 64UL );
  n->kind         = (uchar)gn->kind;
  n->txn_cnt      = (uchar)cnt;
  n->state        = 0;
  n->exec_mask    = 0;
  n->pack_idx     = 0U;
  n->graph_slot    = graph->slot;
  n->dispatch_slot = ULONG_MAX;
  n->exec_slot     = ULONG_MAX;
  n->received_at   = (ulong)received_at;
  n->forwarded_at  = 0UL;
  n->jito_off      = jr ? jr->off+1UL : 0UL;
  fd_memcpy( n->uuid, graph->uuid, FD_GRAVITY_UUID_SZ );
  if( gn->kind==FD_GRAVITY_NODE_BUNDLE ) fd_memcpy( n->bundle_id, gn->id, FD_GRAVITY_BUNDLE_ID_SZ );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_txn_p_t const * t = bundle[i]->txnp;
    fd_memcpy( n->prefixes[i], t->payload + TXN( t )->signature_off, FD_GRAVITY_SIG_PREFIX_SZ );
  }

  ulong deleted;
  int retval = fd_pack_insert_bundle_fini( pack, bundle, cnt, g->block_height, 0, bundle_meta, &deleted );
  if( FD_UNLIKELY( retval<0 ) ) {
    node_pool_ele_release( g->pool, n );
    return insert_reject_reason( retval );
  }

  node_map_ele_insert( g->map, n, g->pool );
  n->state = NODE_STATE_PENDING;
  pend_add( g, n );
  return 0U;
}

/* bundle_txn_cnt returns the transaction count of a builder bundle in
   the current graph's order index, 1 if unknown. */

static ulong
bundle_txn_cnt( fd_gravity_t const * g,
                uchar const *        id ) {
  ord_ent_t const * e = ord_query( g, FD_GRAVITY_NODE_BUNDLE, id );
  if( !e ) {
    jito_rec_t const * jr = jito_query( g, id );
    return jr ? jr->txn_cnt : 1UL;
  }
  fd_gravity_bundle_t b;
  fd_gravity_order_bundle_next( e->ptr, &b );
  return fd_ulong_max( b.txn_cnt, 1UL );
}

/* graph_begin starts inserting a mini-block graph.  graph_step then
   handles up to *budget of its nodes per call, so a large graph does not
   stall the pack loop: nodes inserted by earlier calls can already
   execute. */

static void
graph_begin( fd_gravity_t * g,
             uchar const *  payload,
             ulong          sz,
             long           now ) {
  if( FD_UNLIKELY( fd_gravity_decode_graph( payload, sz, &g->gr.graph ) ) ) {
    FD_LOG_WARNING(( "gravity: malformed mini-block graph" ));
    fd_gravity_sess_reset( g->sess, FD_GRAVITY_SESS_RESET_DECODE, now );
    return;
  }
  g->metrics.graphs++;

  g->gr.accept = g->leader_slot!=ULONG_MAX &&
                 g->slot_mode==FD_GRAVITY_MODE_GRAVITY &&
                 g->gr.graph.slot==g->leader_slot;
  if( FD_UNLIKELY( !g->gr.accept ) ) g->metrics.graphs_rejected++;

  /* Also indexed for a rejected graph, to report every transaction of
     a rejected bundle. */
  ord_index( g, &g->gr.graph );
  g->gr.active      = 1;
  g->gr.cur         = g->gr.graph.nodes;
  g->gr.idx         = 0UL;
  g->gr.received_at = now;
}

static void
graph_step( fd_gravity_t * g,
            fd_pack_t *    pack,
            void const *   bundle_meta,
            ulong *        budget,
            long           now ) {
  fd_gravity_graph_t const * graph = &g->gr.graph;
  /* The graph's slot may end (or fall back) between two steps.  The
     rest of the graph is then rejected. */
  if( g->gr.accept && ( g->leader_slot!=graph->slot || g->slot_mode!=FD_GRAVITY_MODE_GRAVITY ) ) g->gr.accept = 0;

  while( g->gr.idx<graph->node_cnt && *budget ) {
    /* A session reset (e.g. transmit buffer full) ends the graph: the
       receive buffer will be reused, and no result can be sent. */
    if( FD_UNLIKELY( !fd_gravity_sess_is_ready( g->sess ) ) ) break;
    fd_gravity_node_t gn;
    g->gr.cur = fd_gravity_node_next( g->gr.cur, &gn );
    g->gr.idx++;
    (*budget)--;
    if( FD_UNLIKELY( !g->gr.accept ) ) {
      ulong cnt = gn.kind==FD_GRAVITY_NODE_BUNDLE ? bundle_txn_cnt( g, gn.id ) : 1UL;
      reject( g, graph->slot, graph->uuid, gn.kind, gn.id, cnt, 0UL, FD_GRAVITY_NI_SLOT_ENDED, (ulong)g->gr.received_at, now );
      continue;
    }
    ulong txn_cnt;
    ulong fail_idx;
    uint reason = lane_insert( g, pack, bundle_meta, graph, &gn, g->gr.received_at, now, &txn_cnt, &fail_idx );
    if( FD_LIKELY( !reason ) ) {
      g->metrics.nodes_inserted++;
      g->slot_released++;
    } else {
      g->metrics.nodes_rejected++;
      reject( g, graph->slot, graph->uuid, gn.kind, gn.id, txn_cnt, fail_idx, reason, (ulong)g->gr.received_at, now );
    }
  }
  if( g->gr.idx>=graph->node_cnt || !fd_gravity_sess_is_ready( g->sess ) ) g->gr.active = 0;
}

/* Relay messages ******************************************************/

static void flush_progress( fd_gravity_t * g, long now, int force );
static void sweep_inflight( fd_gravity_t * g, ulong slot, long now );
static int  maybe_ours    ( fd_gravity_t const * g, ulong slot );

/* announce sends the Progress for the current slot right away: the relay
   keeps a connector inactive until its first Progress. */

static void
announce( fd_gravity_t * g,
          long           now ) {
  if( g->leader_slot!=ULONG_MAX ) {
    send_progress( g, g->leader_slot, g->slot_start_ns, 1, now );
  } else if( g->last_completed_slot!=ULONG_MAX && !maybe_ours( g, g->last_completed_slot+1UL ) ) {
    send_progress( g, g->last_completed_slot+1UL, now, 0, now );
  }
}


static void
handle_frame( fd_gravity_t * g,
              fd_pack_t *    pack,
              void const *   bundle_meta,
              uchar const *  payload,
              ulong          sz,
              ulong *        budget,
              long           now ) {
  uint tag;
  if( FD_UNLIKELY( fd_gravity_decode_tag( payload, sz, &tag ) ) ) {
    fd_gravity_sess_reset( g->sess, FD_GRAVITY_SESS_RESET_DECODE, now );
    return;
  }
  switch( tag ) {
  case FD_GRAVITY_R2C_MINI_BLOCK_GRAPH:
    graph_begin( g, payload, sz, now );
    if( FD_LIKELY( g->gr.active ) ) graph_step( g, pack, bundle_meta, budget, now );
    break;
  case FD_GRAVITY_R2C_PING: {
    ulong seq;
    if( FD_UNLIKELY( fd_gravity_decode_ping( payload, sz, &seq ) ) ) {
      fd_gravity_sess_reset( g->sess, FD_GRAVITY_SESS_RESET_DECODE, now );
      return;
    }
    uchar * buf = fd_gravity_sess_tx_prepare( g->sess, 16UL );
    if( FD_LIKELY( buf ) ) fd_gravity_sess_tx_publish( g->sess, fd_gravity_encode_pong( buf, 16UL, seq ), now );
    break;
  }
  case FD_GRAVITY_R2C_DELETE_FAILSAFE:
    /* Sent by the relay admin endpoint.  Windows are GRAVITY again once
       the session is warm. */
    if( g->latched ) {
      FD_LOG_WARNING(( "gravity: relay cleared the failsafe, leader windows are relay built again after warmup" ));
      g->latched      = 0;
      g->active_since = 0L;
      announce( g, now );
    } else {
      FD_LOG_NOTICE(( "gravity: relay sent DeleteFailsafe, but the failsafe is not tripped" ));
    }
    break;
  case FD_GRAVITY_R2C_PREVIOUS_TIP_RECEIVER:
  case FD_GRAVITY_R2C_SHRED_RECEIVERS:
  case FD_GRAVITY_R2C_SHRED_RETRANSMIT_RECEIVERS:
    /* Not needed: the tip crank (pack's, with the bundle tile) reads the
       tip payment config from the leader bank.  Not implemented: shred
       destinations are static configuration. */
    break;
  default:
    /* The protocol only ever adds tags, so skip unknown ones. */
    break;
  }
}

void
fd_gravity_handle_frame( fd_gravity_t * g,
                         fd_pack_t *    pack,
                         void const *   bundle_meta,
                         uchar const *  payload,
                         ulong          sz,
                         long           now ) {
  ulong budget = ULONG_MAX;
  handle_frame( g, pack, bundle_meta, payload, sz, &budget, now );
}

#define POLL_NS         (20000L)     /* socket poll interval while idle, 20 us */
#define SWEEP_NS        (100000000L) /* 100 ms */
#define NODES_PER_POLL  (64UL)       /* graph nodes handled per fd_gravity_poll */
#define FRAMES_PER_POLL (64UL)

int
fd_gravity_poll( fd_gravity_t * g,
                 fd_pack_t *    pack,
                 void const *   bundle_meta,
                 long           now ) {
  ulong budget = NODES_PER_POLL;

  /* Finish the graph being inserted before touching the socket: its
     payload lives in the receive buffer. */
  if( FD_UNLIKELY( g->gr.active ) ) {
    graph_step( g, pack, bundle_meta, &budget, now );
    return 1;
  }

  /* A syscall per run loop iteration would slow down pack, so poll the
     socket at most every POLL_NS, unless the last poll received data or
     changed the session state (more may be pending).  Transmits are
     batched to the poll interval. */
  int work = 0;
  if( now>=g->next_poll_ns ) {
    fd_gravity_sess_t * sess   = g->sess;
    ulong               rx0    = sess->rx_bytes;
    int                 state0 = sess->state;
    work = fd_gravity_sess_poll( sess, now );
    g->next_poll_ns = ( sess->rx_bytes!=rx0 || sess->state!=state0 ) ? now : now+POLL_NS;
  }

  /* Results for nodes whose execle frags were missed (unreliable tap) */
  if( FD_UNLIKELY( now>=g->next_sweep_ns ) ) {
    g->next_sweep_ns = now+SWEEP_NS;
    if( g->last_completed_slot!=ULONG_MAX ) sweep_inflight( g, g->last_completed_slot, now );
  }

  if( FD_UNLIKELY( g->sess->session_new ) ) {
    g->sess->session_new = 0;
    announce( g, now );
    work = 1;
  }

  if( FD_UNLIKELY( g->pending_progress && now>=g->pending_deadline ) ) flush_progress( g, now, 1 );

  for( ulong i=0UL; i<FRAMES_PER_POLL && budget && !g->gr.active; i++ ) {
    ulong sz;
    uchar const * payload = fd_gravity_sess_next_frame( g->sess, &sz );
    if( !payload ) break;
    handle_frame( g, pack, bundle_meta, payload, sz, &budget, now );
    work = 1;
  }
  return work;
}

/* Replay events *******************************************************/

/* reinsert_native puts back the native copy of a retained (forwarded)
   transaction.  Purging a lane node deletes by signature, which also
   deletes the native copy the transaction had in pack, so without this a
   fallback to native would lose the transactions the relay had picked. */

static void
reinsert_native( fd_gravity_t * g,
                 fd_pack_t *    pack,
                 node_t const * n,
                 long           now ) {
  ret_rec_t const * rec = ret_query( g, n->prefixes[0] );
  if( !rec ) return; /* builder bytes, pack never had a native copy */
  uchar const *    payload = (uchar const *)(rec+1);
  fd_txn_t const * txn     = (fd_txn_t const *)( payload+ret_txn_off( rec->payload_sz ) );
  if( FD_UNLIKELY( memcmp( payload+txn->signature_off, n->first_sig, 64UL ) ) ) return;

  fd_txn_e_t * spot = fd_pack_insert_txn_init( pack );
  member_t m = { .rec = rec };
  if( FD_UNLIKELY( fill_txn( g, spot, &m, now ) ) ) { fd_pack_insert_txn_cancel( pack, spot ); return; }
  ulong deleted;
  fd_pack_insert_txn_fini( pack, spot, rec->blockhash_height, &deleted );
}

static void
purge_pending( fd_gravity_t * g,
               fd_pack_t *    pack,
               uint           reason,
               long           now ) {
  /* Results go out in slot_nodes order (insertion order unless nodes
     were dispatched in between). */
  ulong cnt = g->slot_node_cnt;
  if( cnt ) FD_LOG_DEBUG(( "gravity: purging %lu undispatched lane nodes (reason %u)", cnt, reason ));
  for( ulong i=0UL; i<cnt; i++ ) {
    node_t * n = node_pool_ele( g->pool, g->slot_nodes[i] );
    fd_pack_delete_transaction( pack, (fd_ed25519_sig_t const *)n->first_sig );
    reinsert_native( g, pack, n, now );
    node_reject( g, n, reason, now );
    n->state = 0; /* detach, slot_nodes is reset below */
    node_free( g, n );
  }
  g->slot_node_cnt = 0UL;
}

/* sweep_inflight synthesizes results for dispatched nodes from slots
   before slot-1 (their execle frags were missed).  Nodes from slot-1
   may still be executing when the next leader slot starts. */

static void
sweep_inflight( fd_gravity_t * g,
                ulong          slot,
                long           now ) {
  for( ulong i=0UL; i<FD_GRAVITY_INFLIGHT_CNT; i++ ) {
    if( !g->inflight[i] ) continue;
    node_t * n = node_pool_ele( g->pool, g->inflight[i]-1U );
    if( n->dispatch_slot+1UL<slot ) {
      node_reject( g, n, FD_GRAVITY_NI_SLOT_ENDED, now );
      node_free( g, n );
    }
  }
}

/* window_end handles the end of the current leadership (a leader
   window, or adjacent ones), once.  As with gravity-connector's
   failsafe, a leadership whose last GRAVITY slot with forwarded orders
   scheduled nothing from the relay trips the failsafe, even if the
   window then fell back on a lost session: later windows are NATIVE
   and no Progress is sent until the relay sends DeleteFailsafe (or a
   restart).  The connector writes a failsafe file and exits instead.
   The session is reset, which ends the relay's sequencing as when the
   connector exits. */

static void
window_end( fd_gravity_t * g,
            long           now ) {
  if( !window_open( g ) ) return;
  g->window_done = 1;
  if( !g->window_missed ) return;
  FD_LOG_WARNING(( "gravity: leadership ending with window %lu-%lu had unscheduled slots, failsafe tripped: leader windows "
                   "are packed natively and no Progress is sent until the relay sends DeleteFailsafe or a restart",
                   g->window_id*4UL, g->window_id*4UL+3UL ));
  g->latched      = 1;
  g->active_since = 0L;
  g->metrics.failsafe_trips++;
  fd_gravity_sess_reset( g->sess, FD_GRAVITY_SESS_RESET_CALLER, now );
}

/* warm returns 1 if the relay has known this session as active (it
   sent Progress) for warmup_ns.  A fresh session's first window would
   otherwise likely stay empty and trip the failsafe. */

static int
warm( fd_gravity_t const * g,
      long                 now ) {
  if( !g->cfg.warmup_ns ) return 1;
  return g->active_since && g->active_sess==g->sess->session_cnt && now-g->active_since>=g->cfg.warmup_ns;
}

int
fd_gravity_became_leader( fd_gravity_t * g,
                          fd_pack_t *    pack,
                          ulong          slot,
                          long           slot_start_ns,
                          long           slot_end_ns,
                          ulong          block_height,
                          int            crank,
                          long           now ) {
  /* The previous leader slot should have been ended with
     fd_gravity_slot_end.  If it wasn't, pack switched slots. */
  fd_gravity_slot_end( g, pack, 1, now );
  sweep_inflight( g, slot, now );

  ulong window     = slot/4UL;
  int   new_window = window!=g->window_id;
  if( new_window ) {
    /* Adjacent windows are one leadership, as gravity-connector stays
       Sequencing across them: a missed slot carries over and can still
       be cleared. */
    if( !( window_open( g ) && window==g->window_id+1UL ) ) {
      window_end( g, now );
      g->window_missed = 0;
    }
    g->window_id   = window;
    g->window_done = 0;
    g->window_mode = fd_gravity_sess_is_ready( g->sess ) && !g->latched && warm( g, now ) ? FD_GRAVITY_MODE_GRAVITY : FD_GRAVITY_MODE_NATIVE;
    if( g->window_mode==FD_GRAVITY_MODE_GRAVITY ) g->metrics.windows_gravity++;
    else                                          g->metrics.windows_native++;
    FD_LOG_INFO(( "gravity: leader window %lu-%lu is %s%s", window*4UL, window*4UL+3UL,
                  g->window_mode==FD_GRAVITY_MODE_GRAVITY ? "GRAVITY" : "NATIVE",
                  g->latched ? " (failsafe)" : fd_gravity_sess_is_ready( g->sess ) && !warm( g, now ) ? " (warming up)" : "" ));
  } else if( FD_UNLIKELY( g->window_mode==FD_GRAVITY_MODE_GRAVITY && !fd_gravity_sess_is_ready( g->sess ) ) ) {
    /* The session dropped between two slots of a GRAVITY window: the
       rest of the window is NATIVE, decided now rather than at the
       first fd_gravity_check_fallback. */
    FD_LOG_WARNING(( "gravity: session lost before leader slot %lu, falling back to native for the rest of the window", slot ));
    g->metrics.fallback_session++;
    g->window_mode = FD_GRAVITY_MODE_NATIVE;
  }

  if( g->pending_progress<=slot ) g->pending_progress = 0UL; /* superseded by the leader progress below */
  g->leader_slot      = slot;
  g->last_leader_slot = slot;
  g->block_height  = block_height;
  g->slot_start_ns = slot_start_ns;
  g->slot_end_ns   = slot_end_ns;
  g->slot_released   = 0UL;
  g->slot_dispatched = 0UL;
  g->slot_fwd        = 0;
  g->slot_mode     = g->window_mode;

  /* Lane nodes are bundles, which pack only schedules once the
     initializer bundle state is ready.  If pack cranks the tip accounts
     (bundle tile enabled), the crank's initializer bundle runs first.
     Otherwise nothing initializes. */
  if( g->slot_mode==FD_GRAVITY_MODE_GRAVITY && !crank ) fd_pack_set_initializer_bundles_ready( pack );

  /* Leader progress releases the relay's first mini-block for the
     slot, so send it right away.  It is also sent in NATIVE windows so
     the relay's slot clock stays correct. */
  if( slot>g->last_progress_slot || g->last_progress_slot==0UL ) send_progress( g, slot, slot_start_ns, 1, now );

  /* Jito bundles follow the mode.  Pack's bundle FIFO would schedule
     native ones among the lane nodes of a GRAVITY slot, and lane nodes
     never outlive their slot, so any bundle left besides the tip crank
     is native. */
  if( g->slot_mode==FD_GRAVITY_MODE_GRAVITY ) {
    ulong pulled = fd_pack_delete_bundles( pack );
    g->metrics.jito_pulled += pulled;
    if( new_window || pulled || g->jito_native || g->jito_unsent ) jito_to_relay( g, now );
  } else if( g->jito_diverted ) {
    jito_to_pack( g, pack, now );
  }
  return g->slot_mode;
}

/* maybe_ours returns 1 if slot may be one of our leader slots, so must
   not be announced as a non-leader slot.  Progress for our own leader
   slots is only sent at became_leader, when the leader bank is ready:
   the relay starts a slot (and releases its first mini-block) at the
   first Progress for it, and ignores later ones.

   - The next leader slot replay reported is ours.
   - The slot after one of ours in the same window is ours.
   - Right after our window, replay doesn't tell: the NEXT_LEADER sent
     when our last slot completes still reports that slot (the leader
     bank), and the RESET only comes when becoming leader again.  Until
     a fresher next leader slot arrives (the RESET, or the NEXT_LEADER
     of the next completed slot), it may be ours. */

static int
maybe_ours( fd_gravity_t const * g,
            ulong                slot ) {
  if( slot==g->next_leader_slot ) return 1;
  if( g->last_leader_slot==ULONG_MAX || slot!=g->last_leader_slot+1UL ) return 0;
  if( slot%4UL ) return 1;
  return g->next_leader_slot!=ULONG_MAX && g->next_leader_slot<slot;
}

/* flush_progress announces the slot after the last completed one,
   unless it may be ours. */

#define PROGRESS_WAIT_NS (20000000L) /* 20 ms */

static void
flush_progress( fd_gravity_t * g,
                long           now,
                int            force ) {
  ulong next = g->pending_progress;
  if( !next ) return;
  if( next<=g->last_progress_slot                         ) { g->pending_progress = 0UL; return; }
  if( g->leader_slot!=ULONG_MAX && next/4UL==g->window_id ) { g->pending_progress = 0UL; return; }
  if( maybe_ours( g, next ) ) {
    /* Superseded by became_leader if it is ours, or by the next
       completion if not.  Never announce it on the deadline. */
    if( next==g->next_leader_slot || next%4UL ) g->pending_progress = 0UL;
    else                                        g->pending_deadline = LONG_MAX;
    return;
  }
  /* A next leader slot behind the slot to announce is stale (see
     maybe_ours).  For a slot that can't be ours it doesn't matter, but
     the next leadership sent with the Progress would be wrong, so wait
     briefly for a fresher one. */
  if( !force && g->next_leader_slot!=ULONG_MAX && g->next_leader_slot<next ) return;
  g->pending_progress = 0UL;
  send_progress( g, next, now, 0, now );
}

static void
completed( fd_gravity_t * g,
           ulong          slot,
           uchar const    block_hash[ static 32 ],
           long           now ) {
  /* Completions can arrive out of order across forks.  Keep the newest
     blockhash. */
  if( g->last_completed_slot==ULONG_MAX || slot>=g->last_completed_slot ) {
    g->last_completed_slot = slot;
    fd_memcpy( g->last_blockhash, block_hash, 32UL );
    g->has_blockhash = 1;
  }
  if( slot+1UL>g->pending_progress ) {
    g->pending_progress = slot+1UL;
    g->pending_deadline = now + PROGRESS_WAIT_NS;
  }
  /* A later window's slot completed: our leadership is over (the
     connector's first non-Sequencing progress), even if we did not
     become leader for its last slots.  Unless one of them is still
     ahead, and the slot is from another fork. */
  int ours_ahead = g->next_leader_slot!=ULONG_MAX && g->next_leader_slot/4UL==g->window_id &&
                   ( g->last_leader_slot==ULONG_MAX || g->next_leader_slot>g->last_leader_slot );
  if( g->leader_slot==ULONG_MAX && window_open( g ) && slot/4UL>g->window_id && !ours_ahead ) window_end( g, now );
}

void
fd_gravity_slot_completed( fd_gravity_t * g,
                           ulong          slot,
                           uchar const    block_hash[ static 32 ],
                           long           now ) {
  /* Replay publishes the next leader slot right after this, which is
     needed to tell whether the next slot is ours.  Wait for it. */
  completed( g, slot, block_hash, now );
}

void
fd_gravity_next_leader( fd_gravity_t * g,
                        ulong          next_leader_slot,
                        long           now ) {
  g->next_leader_slot = next_leader_slot;
  flush_progress( g, now, 0 );
}

void
fd_gravity_reset( fd_gravity_t * g,
                  ulong          completed_slot,
                  uchar const    completed_blockhash[ static 32 ],
                  ulong          next_leader_slot,
                  long           now ) {
  g->next_leader_slot = next_leader_slot;
  completed( g, completed_slot, completed_blockhash, now );
  flush_progress( g, now, 0 );
}

void
fd_gravity_slot_end( fd_gravity_t * g,
                     fd_pack_t *    pack,
                     int            abandoned,
                     long           now ) {
  if( g->leader_slot==ULONG_MAX ) return;
  purge_pending( g, pack, FD_GRAVITY_NI_SLOT_ENDED, now );

  /* gravity-connector's missed slot: orders were forwarded but nothing
     from the relay was scheduled (a slot without orders has nothing to
     schedule).  A later slot of the leadership that schedules clears
     it.  A slot cut short by consensus is not the relay's fault, as the
     connector skips slots going backwards. */
  if( g->slot_mode==FD_GRAVITY_MODE_GRAVITY && !abandoned ) {
    if( g->slot_dispatched ) {
      g->window_missed = 0;
    } else if( g->slot_fwd ) {
      FD_LOG_WARNING(( "gravity: nothing from the relay scheduled in slot %lu (%lu nodes released), failsafe at the end of the "
                       "leadership unless a later slot schedules", g->leader_slot, g->slot_released ));
      g->metrics.slots_missed++;
      g->window_missed = 1;
    }
  }

  g->leader_slot = ULONG_MAX;
  g->slot_mode   = FD_GRAVITY_MODE_NATIVE;
}

void
fd_gravity_check_fallback( fd_gravity_t * g,
                           fd_pack_t *    pack,
                           long           now ) {
  /* A GRAVITY window stays GRAVITY even if nothing from the relay can be
     scheduled (see window_end), unless the session is lost: then nothing
     can arrive anymore. */
  if( FD_LIKELY( g->slot_mode!=FD_GRAVITY_MODE_GRAVITY || fd_gravity_sess_is_ready( g->sess ) ) ) return;
  FD_LOG_WARNING(( "gravity: session lost while leader for slot %lu, falling back to native for the rest of the window", g->leader_slot ));
  g->metrics.fallback_session++;
  purge_pending( g, pack, FD_GRAVITY_NI_SLOT_ENDED, now );
  g->window_mode = FD_GRAVITY_MODE_NATIVE;
  g->slot_mode   = FD_GRAVITY_MODE_NATIVE;
  /* After the purge, which deletes lane nodes by signature */
  if( g->jito_diverted ) jito_to_pack( g, pack, now );
}

/* Forwarding **********************************************************/

void
fd_gravity_on_txn( fd_gravity_t *     g,
                   fd_txn_e_t const * txne,
                   ulong              blockhash_height,
                   long               now ) {
  ret_insert( g, txne, blockhash_height );

  fd_txn_p_t const * txnp = txne->txnp;
  if( FD_UNLIKELY( !fd_gravity_sess_is_ready( g->sess ) || g->latched ) ) return;
  /* Offered orders count for the failsafe even if shed, as the connector
     counts orders drained from its outbox. */
  g->slot_fwd = 1;
  /* Shed forwards before the buffer gets tight so results and progress
     always fit. */
  if( FD_UNLIKELY( fd_gravity_sess_tx_free( g->sess )<g->sess->tx_max/2UL ) ) {
    g->metrics.txn_fwd_dropped++;
    return;
  }
  ulong max_sz = 64UL+txnp->payload_sz;
  uchar * buf = fd_gravity_sess_tx_prepare( g->sess, max_sz );
  if( FD_UNLIKELY( !buf ) ) { g->metrics.txn_fwd_dropped++; return; }

  /* IPv4 mapped source address, all zeros if unknown */
  uchar src[ 16 ] = {0};
  if( FD_LIKELY( txnp->source_ipv4 ) ) {
    src[10] = 0xff;
    src[11] = 0xff;
    FD_STORE( uint, src+12, txnp->source_ipv4 ); /* already network order */
  }
  ulong sz = fd_gravity_encode_transaction( buf, max_sz, txnp->payload, txnp->payload_sz,
                                            /* sent_at */ (ulong)now, /* received_at */ (ulong)txnp->first_seen_nanos,
                                            src, NULL );
  if( FD_UNLIKELY( !sz ) ) { g->metrics.txn_fwd_dropped++; return; }
  fd_gravity_sess_tx_publish( g->sess, sz, now );
  g->metrics.txn_forwarded++;
}

int
fd_gravity_on_bundle( fd_gravity_t *       g,
                      fd_txn_e_t * const * bundle,
                      ulong                txn_cnt,
                      ulong                blockhash_height,
                      void const *         meta,
                      long                 now ) {
  g->metrics.jito_rx++;
  if( FD_UNLIKELY( !txn_cnt || txn_cnt>FD_GRAVITY_MAX_TXN_PER_BUNDLE ) ) return 0;
  uchar const * sigs[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  for( ulong i=0UL; i<txn_cnt; i++ ) sigs[i] = bundle[i]->txnp->payload + TXN( bundle[i]->txnp )->signature_off;
  uchar uuid[ 32 ];
  fd_gravity_jito_bundle_id( uuid, txn_cnt, sigs );
  if( FD_UNLIKELY( jito_query( g, uuid ) ) ) { g->metrics.jito_dup++; return 1; }

  jito_rec_t * rec = jito_store( g, uuid, bundle, txn_cnt, blockhash_height, meta );
  if( FD_UNLIKELY( !rec ) ) return 0; /* larger than the retention ring */
  if( !jito_divert( g ) ) {
    rec->in_pack = 1;
    g->jito_native = 1;
    g->metrics.jito_native++;
    return 0;
  }
  /* Not in pack: it executes only as part of relay mini-blocks, or goes
     to pack if a window turns NATIVE (jito_to_pack).  A failed forward is
     retried at the next GRAVITY slot start. */
  g->jito_diverted = 1;
  if( FD_UNLIKELY( !jito_forward( g, rec, now ) ) ) g->jito_unsent = 1;
  return 1;
}

/* Scheduling and results **********************************************/

void
fd_gravity_on_schedule( fd_gravity_t * g,
                        fd_pack_t *    pack,
                        fd_txn_e_t *   out,
                        ulong          txn_cnt,
                        uint           pack_idx,
                        long           now ) {
  fd_txn_p_t * first = out[0].txnp;
  uchar const * sig0 = first->payload + TXN( first )->signature_off;
  fd_gravity_key_t key;
  fd_memcpy( key.b, sig0, FD_GRAVITY_SIG_PREFIX_SZ );
  node_t * n = node_map_ele_query( g->map, &key, NULL, g->pool );
  /* A Jito bundle can start with the same transaction as a lane node.
     Only an exact match is the lane node. */
  int lane = n && !memcmp( n->first_sig, sig0, 64UL ) && n->state==NODE_STATE_PENDING && txn_cnt==(ulong)n->txn_cnt;
  for( ulong i=1UL; lane && i<txn_cnt; i++ ) {
    fd_txn_p_t const * t = out[i].txnp;
    lane = !memcmp( t->payload + TXN( t )->signature_off, n->prefixes[i], FD_GRAVITY_SIG_PREFIX_SZ );
  }
  if( FD_UNLIKELY( !lane ) ) {
    jito_scheduled( g, out, txn_cnt ); /* a native Jito bundle (or the tip crank) */
    return;
  }
  if( n->jito_off && ret_valid( g, n->jito_off-1UL ) ) ((jito_rec_t *)ret_laddr( g, n->jito_off-1UL ))->done = 1;

  /* The node owns pack_idx [pack_idx,pack_idx+txn_cnt).  An entry still
     owned by an older node means that node's results were never seen
     (pack_idx moved on by FD_GRAVITY_INFLIGHT_CNT since). */
  for( ulong i=0UL; i<n->txn_cnt; i++ ) {
    uint * ent = inflight_ent( g, pack_idx+(uint)i );
    if( FD_UNLIKELY( *ent ) ) {
      node_t * old = node_pool_ele( g->pool, *ent-1U );
      node_reject( g, old, FD_GRAVITY_NI_SLOT_ENDED, now );
      node_free( g, old ); /* clears every entry old owned */
    }
  }
  pend_remove( g, n );
  g->slot_dispatched++;
  n->state         = NODE_STATE_DISPATCHED;
  n->pack_idx      = pack_idx;
  n->dispatch_slot = g->leader_slot;
  n->forwarded_at  = (ulong)now;
  n->exec_mask     = 0;
  uint self = (uint)node_pool_idx( g->pool, n )+1U;
  for( ulong i=0UL; i<n->txn_cnt; i++ ) *inflight_ent( g, pack_idx+(uint)i ) = self;

  /* A transaction node executes like a normal transaction: it lands
     (and pays fees) even if it fails. */
  if( n->kind==FD_GRAVITY_NODE_TX ) first->flags &= ~FD_TXN_P_FLAGS_BUNDLE;

  /* Drop native copies of the same transactions.  The scheduled ones
     are no longer in the pool. */
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t const * t = out[i].txnp;
    fd_pack_delete_transaction( pack, (fd_ed25519_sig_t const *)(t->payload + TXN( t )->signature_off) );
  }
}

int
fd_gravity_is_inflight( fd_gravity_t const * g,
                        uint                 pack_idx ) {
  uint idx = g->inflight[ (ulong)pack_idx & (FD_GRAVITY_INFLIGHT_CNT-1UL) ];
  if( !idx ) return 0;
  node_t const * n = g->pool + (idx-1U);
  return (uint)(pack_idx-n->pack_idx)<(uint)n->txn_cnt;
}

void
fd_gravity_on_executed( fd_gravity_t * g,
                        ulong          slot,
                        uint           pack_idx,
                        ulong          txn_cnt,
                        uint const *   flags,
                        uint const *   cus,
                        uchar          worker,
                        long           now ) {
  uint idx = *inflight_ent( g, pack_idx );
  if( FD_UNLIKELY( !idx ) ) return; /* not a lane node */
  node_t * n = node_pool_ele( g->pool, idx-1U );
  if( FD_UNLIKELY( n->state!=NODE_STATE_DISPATCHED ) ) return;
  ulong off = (ulong)(uint)(pack_idx-n->pack_idx);
  if( FD_UNLIKELY( off>=(ulong)n->txn_cnt ) ) return;

  /* Execle publishes a bundle one transaction per frag (pack_idx+i), a
     microblock in one frag.  Collect until every transaction is in. */
  for( ulong i=0UL; i<txn_cnt && off+i<(ulong)n->txn_cnt; i++ ) {
    n->exec_flags[ off+i ] = flags[i];
    n->exec_cus  [ off+i ] = cus  [i];
    n->exec_mask           = (uchar)( n->exec_mask | (1U<<(off+i)) );
  }
  n->exec_slot = slot;
  ulong cnt = (ulong)n->txn_cnt;
  if( (ulong)n->exec_mask!=fd_ulong_mask_lsb( (int)cnt ) ) return;

  fd_gravity_result_t res[ FD_GRAVITY_MAX_TXN_PER_BUNDLE ];
  int all_aon = 1;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( n->exec_flags[i] & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) {
      res[i] = (fd_gravity_result_t){ .kind = FD_GRAVITY_RESULT_INCLUDED, .slot = n->exec_slot, .cus = n->exec_cus[i] };
      all_aon = 0;
    } else {
      int err = -(int)(n->exec_flags[i]>>24);
      uint reason = fd_gravity_reason_from_txn_err( err );
      res[i] = (fd_gravity_result_t){ .kind = FD_GRAVITY_RESULT_NOT_INCLUDED, .reason = reason };
      if( reason!=FD_GRAVITY_NI_ALL_OR_NOTHING ) all_aon = 0;
    }
  }
  /* Builders take the first non all-or-nothing result as the bundle
     outcome and ignore all all-or-nothing results. */
  if( FD_UNLIKELY( all_aon ) ) res[0].reason = FD_GRAVITY_NI_SANITIZE_FAILURE;
  send_result( g, n->graph_slot, n->uuid, n->kind, n->kind==FD_GRAVITY_NODE_BUNDLE ? n->bundle_id : n->prefixes[0],
               cnt, res, worker, n->received_at, n->forwarded_at, (ulong)now, now );
  node_free( g, n );
}
