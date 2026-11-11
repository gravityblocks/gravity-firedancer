#define _GNU_SOURCE
#include "fd_gravity.h"
#include "fd_gravity_wire.h"
#include "fd_gravity_version.h"
#include "../../disco/tiles.h"
#include "../../disco/fd_txn_m.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/waker/fd_waker.h"
#include "../../disco/wait_info/fd_wait_info.h"
#include "../../disco/bundle/fd_bundle_tile.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/resolv/fd_adns.h"
#include "../replay/fd_replay_tile.h"
#include "../poh/fd_poh_tile.h"
#include "../../flamenco/runtime/fd_runtime_err.h"
#include "../../util/pod/fd_pod_format.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/futex.h>
#include "generated/fd_gravity_tile_seccomp.h"

/* The gravity tile connects the validator to a block building relay.
   It reports slot progress, receives the relay's graphs of orders for
   our leader slots, sends their transactions through resolv to pack,
   walks each graph in dependency order telling pack which node to run
   next, and reports each node that is not included.  fd_gravity.h
   describes the messages it exchanges with resolv, pack and gossip. */

/* The version the relay sees follows gravity-connector releases, not
   Firedancer's, which gossip reports. */
#define FD_GRAVITY_CONNECTOR_VERSION "0.5.0-alpha.1"

#define IN_KIND_REPLAY (0)
#define IN_KIND_EXECLE (1)
#define IN_KIND_PACK   (2)
#define IN_KIND_RESOLV (3)
#define IN_KIND_BUNDLE (4)

#define STATE_DISCONNECTED (0)
#define STATE_CONNECTING   (1)
#define STATE_AWAIT_HELLO  (2)
#define STATE_AWAIT_ACCEPT (3)
#define STATE_READY        (4)

#define NODE_WAIT (0) /* predecessors or admission pending */
#define NODE_HEAP (1) /* ready to run */
#define NODE_RUN  (2) /* run command sent */
#define NODE_DONE (3)

#define ADMIT_PENDING (0)
#define ADMIT_OK      (1)
#define ADMIT_FAILED  (2)

#define RX_BUF_SZ     (16UL<<20)
#define TX_BUF_SZ     (8UL<<20)
#define MSG_MAX       (512UL)
#define GRAPH_MAX     (64UL)
#define NODE_MAX      (4096UL)
#define EDGE_MAX      (32768UL)
#define NODE_POOL     (10UL*(NODE_MAX+1UL)) /* 10 graphs of the largest size */
#define EDGE_POOL     (10UL*(EDGE_MAX+1UL))
#define RUN_AHEAD     (2UL)  /* run commands in flight beyond one per execle tile */
#define RUN_BATCH_MAX (64UL)
#define DRAIN_MAX     (FD_PACK_MAX_EXECLE_TILES+RUN_AHEAD)

#define CONNECT_TIMEOUT_NS ((long)3e9)
#define LOGIN_TIMEOUT_NS  ((long)10e9)
#define RECONNECT_NS      ((long)1e9)
#define LEADER_SILENCE_NS ((long)100e6)
#define IDLE_SILENCE_NS   ((long)3e9)
#define RX_POLL_NS        ((long)1e6)
#define USER_TIMEOUT_MS   (1000)
#define NEAR_LEADER_SLOTS (4UL)
#define STATS_INTERVAL_NS ((long)10e9)

/* Sent to the relay every STATS_INTERVAL_NS and reset.  The *_max_ns
   ones are the longest call in the interval, kept in ticks. */
#define STAT_NETWORK_MAX_NS  (0)
#define STAT_PUBLISH_MAX_NS  (1)
#define STAT_DISPATCH_MAX_NS (2)
#define STAT_TIMING_CNT      (3)
#define STAT_GRAPHS          (3)
#define STAT_NODES_ADMITTED  (4)
#define STAT_NODES_REJECTED  (5)
#define STAT_NODES_RESOLV    (6)
#define STAT_NODES_SCHED     (7)
#define STAT_RESULTS         (8)
#define STAT_NODES_DRAINED   (9)
#define STAT_CNT             (10)

static char const * const stat_names[ STAT_CNT ] = {
  "network_max_ns", "publish_max_ns", "dispatch_max_ns",
  "graphs", "nodes_admitted", "nodes_rejected", "nodes_resolv_failed", "nodes_sched_failed", "results",
  "nodes_drained"
};

/* A node's transactions, a run command, a TPU and a shred update */
#define STEM_BURST (FD_GRAVITY_WIRE_BUNDLE_TXN_MAX+3UL)
#define STEM_LAZY  ((long)1e6)

struct sig_ent {
  ulong  key;  /* first 8 bytes of the transaction's signature */
  uint   node;  /* in graph, or in drain if graph is NULL */
  uint   txn;
  void * graph;
};
typedef struct sig_ent sig_ent_t;

/* Holds every transaction of the queued graphs, at most
   NODE_POOL*FD_GRAVITY_WIRE_BUNDLE_TXN_MAX, so it is never full */

#define MAP_NAME        sig_map
#define MAP_T           sig_ent_t
#define MAP_LG_SLOT_CNT 18
#define MAP_MEMOIZE     0
#include "../../util/tmpl/fd_map.c"
FD_STATIC_ASSERT( NODE_POOL*FD_GRAVITY_WIRE_BUNDLE_TXN_MAX<(1UL<<18), sig_map );

/* Builder orders of the graph being taken in, by the first 8 bytes of
   their key */

struct order_ent {
  ulong key;
  ulong off;
};
typedef struct order_ent order_ent_t;

#define MAP_NAME        order_map
#define MAP_T           order_ent_t
#define MAP_LG_SLOT_CNT 14
#define MAP_MEMOIZE     0
#include "../../util/tmpl/fd_map.c"

typedef struct {
  uchar         key[ 32 ];  /* signature prefix or bundle id */
  int           is_bundle;
  uint          txn_cnt;
  uint          depth;
  uint          preds;      /* unfinished predecessors */
  uchar         state;
  uchar         admit;
  uchar         done_cnt;   /* transactions executed */
  uchar         worker;
  ulong         run_at;
  ulong         sig_key[ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ]; /* 0 if not in sig_map */
  uint          ni     [ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
  ulong         cus    [ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
  uchar const * txn    [ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ]; /* in the retained rx frame until published */
  ushort        txn_sz [ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
} node_t;

typedef struct {
  ulong    slot;
  uchar    uuid[ 16 ];
  ulong    base_id;
  ulong    node_cnt;
  ulong    done_cnt;
  ulong    rx_at;
  ulong    node_off;  /* of node and row in their pools */
  ulong    node_sz;   /* node_cnt+1 */
  ulong    edge_off;
  ulong    edge_sz;   /* edges+1 */
  uint *   row;
  uint *   col;
  node_t * node;
} graph_t;

/* A node still running when its slot ended */

typedef struct {
  ulong  id;    /* 0 if free */
  ulong  slot;
  uchar  uuid[ 16 ];
  ulong  rx_at;
  node_t node;
} drain_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} in_ctx_t;

typedef struct {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} out_ctx_t;

/* A relay session, kept logged in whether or not it is active */

typedef struct {
  char    host[ 256 ];
  ushort  port;
  ulong   addr_rr;       /* rotates through the DNS records */
  int     resolving;
  uint    ip4;           /* the address in use */
  int     sock;
  int     state;
  int     confirmed;     /* a session message arrived since login */
  int     drop;          /* close at the next safe point */
  int     epoll_out;
  long    deadline;      /* ticks, while connecting and logging in */
  long    reconnect_at;  /* ticks */
  long    last_rx;       /* ticks */
  uint    tpu_ip4;       /* the relay's TPU address, 0 if none */
  ushort  tpu_port;
  fd_gravity_shred_dests_t shred_dests[1];
  ulong   shred_seq;     /* changes of shred_dests */

  uchar * rx_buf;
  ulong   rx_off;
  ulong   rx_len;        /* bytes buffered from rx_off */
  int     rx_held;       /* the frame at rx_off is a graph still being published */
  uchar * tx_buf;
  ulong   tx_off;
  ulong   tx_len;
  int     tx_new;        /* messages queued since the last send */
} relay_t;

typedef struct {
  /* Relay sessions.  As the connector does, the tile stays logged in
     to every relay, and only the active one gets Progress and results,
     so only it builds for us. */
  relay_t relay[ 4 ];
  ulong   relay_cnt;
  ulong   active;        /* ULONG_MAX if no relay is logged in */
  ulong   lost;          /* the relay last active, ULONG_MAX if none */
  int     halted;        /* identity switch in progress */
  int     asleep;        /* off the relays, see update_sleep */
  int     caught_up;
  fd_wait_info_box_t const * wait_info;
  fd_netdb_fds_t netdb_fds[1];
  fd_adns_t *    adns;
  long    next_rx_poll;  /* ticks */
  double  tick_per_ns;

  ulong   waker_client_idx;
  ulong * waker_fseq;

  uchar                identity[ 32 ];
  char                 version[ 160 ];
  fd_keyguard_client_t keyguard_client[1];
  fd_keyswitch_t *     keyswitch;

  ulong   execle_cnt;
  ushort  jito_tip_weight_bps;
  int     filter_ofac;
  ulong   blacklisted_cnt;
  uchar   blacklisted[ 16 ][ 32 ];
  uchar   block_builder[ 32 ];      /* from the block engine, zero until known */
  uchar   block_builder_commission;

  /* Leader slots */
  ulong   progress_slot;
  ulong   next_leader_slot;
  uchar   blockhash[ 32 ];
  int     blockhash_known;
  ulong   leader_slot;       /* the slot we lead now, ULONG_MAX if none */
  long    leader_start_ns;
  long    leader_end_ns;
  int     slot_relay;        /* pack builds leader_slot from the relay */
  int     slot_executed;     /* a relay node executed in leader_slot */
  int     leadership_missed;
  int     tripped;           /* failsafe */
  int     failsafe_fd;       /* holds '1' while tripped, across restarts */
  ulong   native_until;      /* no relay building through this slot */
  ulong * mode;
  ulong   mode_val;
  ulong   mode_slot;         /* a mode report for a slot we have not led yet */
  int     mode_active;
  ulong * relay_fseq;        /* 1 while we hold a relay session */
  ulong   relay_val;

  ulong   stat[ STAT_CNT ];
  long    next_stats;

  uint    tpu_applied_ip4;
  ushort  tpu_applied_port;

  ulong   shred_applied; /* active relay<<32 | its shred_seq, ULONG_MAX if none */

  /* Graphs.  The oldest one runs, the others wait. */
  graph_t *     graph;       /* GRAPH_MAX of them */
  node_t *      node_pool;   /* NODE_POOL */
  uint *        row_pool;    /* NODE_POOL */
  uint *        col_pool;    /* EDGE_POOL */
  ulong         graph_head;
  ulong         graph_cnt;
  ulong         next_id;
  graph_t *     pub_graph;   /* graph whose transactions are being published */
  ulong         pub_node;
  ulong         running;     /* nodes with a run command and no result yet */
  ulong         heap_cnt;
  ulong *       heap;        /* depth<<32 | node, max-heap */
  ulong *       topo_queue;
  uint *        topo_preds;
  sig_ent_t *   sig_map;
  order_ent_t * tx_map;
  order_ent_t * bundle_map;
  drain_t       drain[ DRAIN_MAX ];
  ulong         drain_cnt;

  ulong     run_batch[ RUN_BATCH_MAX ];

  int       in_kind  [ 64 ];
  ulong     in_execle[ 64 ];
  in_ctx_t  in       [ 64 ];
  out_ctx_t resolv_out[1];
  out_ctx_t pack_out  [1];
  out_ctx_t gossip_out[1];
  out_ctx_t shred_out [1];

  union {
    fd_replay_slot_completed_t completed;
    fd_poh_reset_t           reset;
    fd_became_leader_t       became_leader;
    fd_gravity_pack_report_t report;
    fd_gravity_resolv_fail_t resolv_fail;
    fd_bundle_builder_info_t builder;
    uchar                    execle[ FD_EXECLE_POH_MTU ];
  } staged;

  fd_txn_t * txn_t[ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
  uchar      txn_t_mem[ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ][ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
} fd_gravity_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

/* Each relay has its own socket buffers */

FD_FN_PURE static inline ulong
relay_buf_cnt( fd_topo_tile_t const * tile ) {
  return fd_ulong_max( tile->gravity.relay_cnt, 1UL );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gravity_tile_t), sizeof(fd_gravity_tile_t)  );
  for( ulong i=0UL; i<relay_buf_cnt( tile ); i++ ) {
    l = FD_LAYOUT_APPEND( l, 64UL, RX_BUF_SZ );
    l = FD_LAYOUT_APPEND( l, 64UL, TX_BUF_SZ );
  }
  l = FD_LAYOUT_APPEND( l, fd_adns_align(),           fd_adns_footprint( 4UL )  );
  l = FD_LAYOUT_APPEND( l, alignof(graph_t),          GRAPH_MAX*sizeof(graph_t) );
  l = FD_LAYOUT_APPEND( l, alignof(node_t),           NODE_POOL*sizeof(node_t)  );
  l = FD_LAYOUT_APPEND( l, alignof(uint),             NODE_POOL*sizeof(uint)    );
  l = FD_LAYOUT_APPEND( l, alignof(uint),             EDGE_POOL*sizeof(uint)    );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),            NODE_MAX*sizeof(ulong)    );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),            NODE_MAX*sizeof(ulong)    );
  l = FD_LAYOUT_APPEND( l, alignof(uint),             NODE_MAX*sizeof(uint)     );
  l = FD_LAYOUT_APPEND( l, sig_map_align(),           sig_map_footprint()       );
  l = FD_LAYOUT_APPEND( l, order_map_align(),         order_map_footprint()     );
  l = FD_LAYOUT_APPEND( l, order_map_align(),         order_map_footprint()     );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline long
deadline_ns( fd_gravity_tile_t const * ctx,
             long                      ns ) {
  return fd_tickcount() + (long)( (double)ns*ctx->tick_per_ns );
}

static inline ulong
window_end( ulong slot ) {
  return slot - slot%4UL + 3UL;
}

/* Outgoing relay messages ********************************************/

static uchar *
msg_begin( relay_t * r ) {
  if( FD_UNLIKELY( r->tx_off+r->tx_len+FD_GRAVITY_WIRE_FRAME_HDR_SZ+MSG_MAX>TX_BUF_SZ ) ) {
    memmove( r->tx_buf, r->tx_buf+r->tx_off, r->tx_len );
    r->tx_off = 0UL;
    if( FD_UNLIKELY( r->tx_len+FD_GRAVITY_WIRE_FRAME_HDR_SZ+MSG_MAX>TX_BUF_SZ ) ) return NULL;
  }
  return r->tx_buf+r->tx_off+r->tx_len+FD_GRAVITY_WIRE_FRAME_HDR_SZ;
}

static void
msg_end( relay_t * r,
         ulong     sz ) {
  uchar * hdr = r->tx_buf+r->tx_off+r->tx_len;
  FD_STORE( uint,  hdr,     (uint)sz                  );
  FD_STORE( ulong, hdr+4UL, (ulong)fd_log_wallclock() );
  r->tx_len += FD_GRAVITY_WIRE_FRAME_HDR_SZ+sz;
  r->tx_new  = 1;
}

/* SEND_TO appends the message an fd_gravity_wire encoder writes for
   relay r, and SEND for the active relay, which must exist.  A relay
   that does not drain what we send is dropped. */

#define SEND_TO( r, encoder, ... ) do {                                \
    uchar * _buf = msg_begin( (r) );                                   \
    ulong   _sz  = _buf ? encoder( _buf, MSG_MAX, __VA_ARGS__ ) : 0UL; \
    if( FD_LIKELY( _sz ) ) msg_end( (r), _sz );                        \
    else                   (r)->drop = 1;                              \
  } while(0)

#define SEND( ctx, encoder, ... ) SEND_TO( (ctx)->relay+(ctx)->active, encoder, __VA_ARGS__ )

static inline int
has_session( fd_gravity_tile_t const * ctx ) {
  return ctx->active!=ULONG_MAX;
}

static inline int eligible( fd_gravity_tile_t const * ctx );

/* slot_progress is the elapsed percentage of the slot we lead, from
   the clock as Agave reports it under Alpenglow, and 0 otherwise. */

static uint
slot_progress( fd_gravity_tile_t const * ctx ) {
  long len = ctx->leader_end_ns-ctx->leader_start_ns;
  if( FD_UNLIKELY( ctx->progress_slot!=ctx->leader_slot || len<=0L ) ) return 0U;
  return (uint)fd_long_min( fd_long_max( (fd_log_wallclock()-ctx->leader_start_ns)*100L/len, 0L ), 100L );
}

static void
send_progress( fd_gravity_tile_t * ctx ) {
  if( FD_UNLIKELY( !has_session( ctx ) || ctx->tripped || ctx->progress_slot==ULONG_MAX ) ) return;
  /* The relay only builds for a leadership we announce */
  ulong next = eligible( ctx ) ? ctx->next_leader_slot : ULONG_MAX;
  fd_gravity_wire_progress_t progress = {
    .slot              = ctx->progress_slot,
    .observed_at       = (ulong)fd_log_wallclock(),
    .slot_progress     = slot_progress( ctx ),
    .next_leader_start = fd_ulong_if( next!=ULONG_MAX && next>=ctx->progress_slot, next, ULONG_MAX ),
    .next_leader_end   = window_end( next ),
    .blockhash         = ctx->blockhash_known ? ctx->blockhash : NULL,
  };
  SEND( ctx, fd_gravity_wire_progress, &progress );
}

static void
send_result( fd_gravity_tile_t * ctx,
             ulong               slot,
             uchar const *       uuid,
             ulong               rx_at,
             node_t const *      node ) {
  if( FD_UNLIKELY( !has_session( ctx ) ) ) return;
  /* TODO: the relay probably only needs failures.  Results for included
     nodes are only telemetry, so skip them to save network work. */
  ctx->stat[ STAT_RESULTS ]++;
  fd_gravity_wire_result_t result = {
    .slot        = slot,
    .graph_uuid  = uuid,
    .is_bundle   = node->is_bundle,
    .key         = node->key,
    .txn_cnt     = fd_uint_max( node->txn_cnt, 1U ),
    .graph_rx_at = rx_at,
    .run_at      = node->run_at,
    .done_at     = (ulong)fd_log_wallclock(),
    .worker      = node->worker,
  };
  fd_memcpy( result.ni,  node->ni,  sizeof(result.ni)  );
  fd_memcpy( result.cus, node->cus, sizeof(result.cus) );
  SEND( ctx, fd_gravity_wire_result, &result );
}

/* fail reports a node as not included, with reason for its first
   transaction. */

static void
fail( fd_gravity_tile_t * ctx,
      ulong               slot,
      uchar const *       uuid,
      ulong               rx_at,
      node_t *            node,
      uint                reason ) {
  node->ni[ 0 ] = reason;
  for( ulong i=1UL; i<FD_GRAVITY_WIRE_BUNDLE_TXN_MAX; i++ ) node->ni[ i ] = FD_GRAVITY_WIRE_NI_ALL_OR_NOTHING;
  node->worker = 255;
  send_result( ctx, slot, uuid, rx_at, node );
}

/* Graph execution ****************************************************/

static inline graph_t *
graph_at( fd_gravity_tile_t * ctx,
          ulong               i ) {
  return ctx->graph + (ctx->graph_head+i)%GRAPH_MAX;
}

static inline int
graph_running( fd_gravity_tile_t * ctx,
               graph_t const *     graph ) {
  return ctx->graph_cnt && graph==graph_at( ctx, 0UL );
}

static void
heap_push( fd_gravity_tile_t * ctx,
           node_t *            node,
           ulong               idx ) {
  node->state = NODE_HEAP;
  ulong item  = ((ulong)node->depth<<32) | idx;
  ulong i     = ctx->heap_cnt++;
  while( i ) {
    ulong parent = (i-1UL)/2UL;
    if( ctx->heap[ parent ]>=item ) break;
    ctx->heap[ i ] = ctx->heap[ parent ];
    i = parent;
  }
  ctx->heap[ i ] = item;
}

static ulong
heap_pop( fd_gravity_tile_t * ctx ) {
  ulong top  = ctx->heap[ 0 ];
  ulong last = ctx->heap[ --ctx->heap_cnt ];
  ulong i    = 0UL;
  for(;;) {
    ulong c = 2UL*i+1UL;
    if( c>=ctx->heap_cnt ) break;
    if( c+1UL<ctx->heap_cnt && ctx->heap[ c+1UL ]>ctx->heap[ c ] ) c++;
    if( last>=ctx->heap[ c ] ) break;
    ctx->heap[ i ] = ctx->heap[ c ];
    i = c;
  }
  if( ctx->heap_cnt ) ctx->heap[ i ] = last;
  return top & 0xFFFFFFFFUL;
}

static void
unmap_node( fd_gravity_tile_t * ctx,
            node_t *            node ) {
  for( ulong i=0UL; i<node->txn_cnt; i++ ) {
    if( !node->sig_key[ i ] ) continue;
    sig_ent_t * ent = sig_map_query( ctx->sig_map, node->sig_key[ i ], NULL );
    if( FD_LIKELY( ent ) ) sig_map_remove( ctx->sig_map, ent );
    node->sig_key[ i ] = 0UL;
  }
}

static void complete( fd_gravity_tile_t * ctx, graph_t * graph, ulong idx );

/* ready handles a node of the running graph whose predecessors are all
   done.  A node that never reached pack completes when it would have
   run, so its successors keep their order. */

static void
ready( fd_gravity_tile_t * ctx,
       graph_t *           graph,
       ulong               idx ) {
  node_t * node = graph->node+idx;
  if( FD_LIKELY  ( node->admit==ADMIT_OK     ) ) heap_push( ctx, node, idx );
  if( FD_UNLIKELY( node->admit==ADMIT_FAILED ) ) complete( ctx, graph, idx );
}

static void
activate( fd_gravity_tile_t * ctx ) {
  graph_t * graph = graph_at( ctx, 0UL );
  for( ulong i=0UL; i<graph->node_cnt; i++ ) {
    if( !graph->node[ i ].preds && graph->node[ i ].state==NODE_WAIT ) ready( ctx, graph, i );
  }
}

static void
complete( fd_gravity_tile_t * ctx,
          graph_t *           graph,
          ulong               idx ) {
  node_t * node = graph->node+idx;
  node->state = NODE_DONE;
  unmap_node( ctx, node );
  for( uint e=graph->row[ idx ]; e<graph->row[ idx+1UL ]; e++ ) {
    ulong succ = graph->col[ e ];
    if( !--graph->node[ succ ].preds ) ready( ctx, graph, succ );
  }

  if( FD_UNLIKELY( ++graph->done_cnt==graph->node_cnt ) ) {
    ctx->graph_head = (ctx->graph_head+1UL)%GRAPH_MAX;
    ctx->graph_cnt--;
    if( ctx->graph_cnt ) activate( ctx );
  }
}

static void
release_rx_frame( relay_t * r ) {
  ulong frame_sz = FD_GRAVITY_WIRE_FRAME_HDR_SZ+FD_LOAD( uint, r->rx_buf+r->rx_off );
  r->rx_held = 0;
  r->rx_off += frame_sz;
  r->rx_len -= frame_sz;
}

/* flush reports every unfinished node as not included and drops all
   graphs. */

static void
flush( fd_gravity_tile_t * ctx,
       uint                reason ) {
  for( ulong g=0UL; g<ctx->graph_cnt; g++ ) {
    graph_t * graph = graph_at( ctx, g );
    for( ulong i=0UL; i<graph->node_cnt; i++ ) {
      node_t * node = graph->node+i;
      if( node->state==NODE_DONE || node->admit==ADMIT_FAILED ) continue;
      unmap_node( ctx, node );
      fail( ctx, graph->slot, graph->uuid, graph->rx_at, node, reason );
    }
  }
  ctx->graph_cnt = 0UL;
  ctx->pub_graph = NULL;
  ctx->running   = 0UL;
  ctx->heap_cnt  = 0UL;
  if( FD_UNLIKELY( has_session( ctx ) && ctx->relay[ ctx->active ].rx_held ) ) release_rx_frame( ctx->relay+ctx->active );
}

static void
drain_done( fd_gravity_tile_t * ctx,
            drain_t *           d ) {
  unmap_node( ctx, &d->node );
  send_result( ctx, d->slot, d->uuid, d->rx_at, &d->node );
  d->id = 0UL;
  ctx->drain_cnt--;
}

/* drain_clear reports the drained nodes still waiting as not included. */

static void
drain_clear( fd_gravity_tile_t * ctx,
             uint                reason ) {
  for( ulong k=0UL; ctx->drain_cnt && k<DRAIN_MAX; k++ ) {
    drain_t * d = ctx->drain+k;
    if( !d->id ) continue;
    fail( ctx, d->slot, d->uuid, d->rx_at, &d->node, reason );
    unmap_node( ctx, &d->node );
    d->id = 0UL;
    ctx->drain_cnt--;
  }
}

/* drain_running moves the nodes pack may be executing out of the
   graphs when their slot ends.  Each gets its real result, from an
   execle tile or a pack report. */

static void
drain_running( fd_gravity_tile_t * ctx ) {
  for( ulong g=0UL; g<ctx->graph_cnt; g++ ) {
    graph_t * graph = graph_at( ctx, g );
    for( ulong i=0UL; i<graph->node_cnt && ctx->drain_cnt<DRAIN_MAX; i++ ) {
      node_t * node = graph->node+i;
      if( node->state!=NODE_RUN ) continue;
      drain_t * d = ctx->drain+ctx->drain_cnt;
      d->id    = graph->base_id+i;
      d->slot  = graph->slot;
      d->rx_at = graph->rx_at;
      d->node  = *node;
      fd_memcpy( d->uuid, graph->uuid, 16UL );
      for( ulong t=0UL; t<node->txn_cnt; t++ ) {
        sig_ent_t * ent = node->sig_key[ t ] ? sig_map_query( ctx->sig_map, node->sig_key[ t ], NULL ) : NULL;
        if( FD_LIKELY( ent ) ) { ent->graph = NULL; ent->node = (uint)ctx->drain_cnt; }
        node->sig_key[ t ] = 0UL;
      }
      node->state = NODE_DONE;
      ctx->drain_cnt++;
      ctx->stat[ STAT_NODES_DRAINED ]++;
    }
  }
}

static drain_t *
find_drained( fd_gravity_tile_t * ctx,
              ulong               id ) {
  for( ulong k=0UL; ctx->drain_cnt && k<DRAIN_MAX; k++ ) {
    if( ctx->drain[ k ].id==id ) return ctx->drain+k;
  }
  return NULL;
}

static node_t *
find_node( fd_gravity_tile_t * ctx,
           ulong               id,
           graph_t **          out_graph,
           ulong *             out_idx ) {
  for( ulong g=0UL; g<ctx->graph_cnt; g++ ) {
    graph_t * graph = graph_at( ctx, g );
    if( id>=graph->base_id && id<graph->base_id+graph->node_cnt ) {
      *out_graph = graph;
      *out_idx   = id-graph->base_id;
      return graph->node+(id-graph->base_id);
    }
  }
  return NULL;
}

/* admit_failed handles a node that pack will not run. */

static void
admit_failed( fd_gravity_tile_t * ctx,
              graph_t *           graph,
              ulong               idx,
              uint                reason ) {
  node_t * node = graph->node+idx;
  if( FD_UNLIKELY( node->admit!=ADMIT_PENDING ) ) return;
  node->admit = ADMIT_FAILED;
  unmap_node( ctx, node );
  fail( ctx, graph->slot, graph->uuid, graph->rx_at, node, reason );
  if( graph_running( ctx, graph ) && !node->preds ) complete( ctx, graph, idx );
}

static void
node_done( fd_gravity_tile_t * ctx,
           graph_t *           graph,
           ulong               idx ) {
  send_result( ctx, graph->slot, graph->uuid, graph->rx_at, graph->node+idx );
  ctx->running--;
  complete( ctx, graph, idx );
}

/* Graph intake *******************************************************/

static void
reject_graph( fd_gravity_tile_t *             ctx,
              fd_gravity_wire_graph_t const * wire,
              uint                            reason ) {
  ulong rx_at = (ulong)fd_log_wallclock();
  ulong off   = 0UL;
  for( ulong i=0UL; i<wire->node_cnt; i++ ) {
    node_t node[1];
    uchar const * key;
    memset( node, 0, sizeof(node_t) );
    if( FD_UNLIKELY( fd_gravity_wire_graph_node( wire, &off, &node->is_bundle, &key, &node->depth ) ) ) return;
    fd_memcpy( node->key, key, node->is_bundle ? 32UL : 16UL );
    fail( ctx, wire->slot, wire->uuid, rx_at, node, reason );
  }
}

/* index_orders maps the builder orders of wire by key.  The relay sends
   the bytes of every order in a graph, since this validator forwards
   none.  Returns 0 if the orders are malformed. */

static int
index_orders( fd_gravity_tile_t *             ctx,
              fd_gravity_wire_graph_t const * wire ) {
  ulong off = 0UL;
  for( ulong i=0UL; i<wire->tx_cnt; i++ ) {
    ulong         start = off;
    uchar const * txn;
    ulong         txn_sz;
    if( FD_UNLIKELY( fd_gravity_wire_graph_tx( wire, &off, &txn, &txn_sz ) ) ) return 0;
    uchar const * prefix = fd_gravity_wire_sig_prefix( txn, txn_sz );
    if( FD_UNLIKELY( !prefix ) ) continue;
    order_ent_t * ent = order_map_insert( ctx->tx_map, fd_ulong_max( FD_LOAD( ulong, prefix ), 1UL ) );
    if( FD_LIKELY( ent ) ) ent->off = start;
  }
  off = 0UL;
  for( ulong i=0UL; i<wire->bundle_cnt; i++ ) {
    ulong         start = off;
    uchar const * id;
    ulong         cnt;
    uchar const * txn   [ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
    ulong         txn_sz[ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
    if( FD_UNLIKELY( fd_gravity_wire_graph_bundle( wire, &off, &id, &cnt, txn, txn_sz ) ) ) return 0;
    order_ent_t * ent = order_map_insert( ctx->bundle_map, fd_ulong_max( FD_LOAD( ulong, id ), 1UL ) );
    if( FD_LIKELY( ent ) ) ent->off = start;
  }
  return 1;
}

/* order_find points node at the builder order matching its key. */

static int
order_find( fd_gravity_tile_t *             ctx,
            fd_gravity_wire_graph_t const * wire,
            node_t *                        node ) {
  ulong key = fd_ulong_max( FD_LOAD( ulong, node->key ), 1UL );
  if( !node->is_bundle ) {
    order_ent_t const * ent = order_map_query_const( ctx->tx_map, key, NULL );
    if( FD_UNLIKELY( !ent ) ) return 0;
    ulong         off = ent->off;
    uchar const * txn;
    ulong         txn_sz;
    if( FD_UNLIKELY( fd_gravity_wire_graph_tx( wire, &off, &txn, &txn_sz ) ) ) return 0;
    uchar const * prefix = fd_gravity_wire_sig_prefix( txn, txn_sz );
    if( FD_UNLIKELY( !prefix || memcmp( prefix, node->key, 16UL ) || txn_sz>FD_TXN_MTU ) ) return 0;
    node->txn_cnt     = 1U;
    node->txn   [ 0 ] = txn;
    node->txn_sz[ 0 ] = (ushort)txn_sz;
    return 1;
  }

  order_ent_t const * ent = order_map_query_const( ctx->bundle_map, key, NULL );
  if( FD_UNLIKELY( !ent ) ) return 0;
  ulong         off = ent->off;
  uchar const * id;
  ulong         cnt;
  uchar const * txn   [ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
  ulong         txn_sz[ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
  if( FD_UNLIKELY( fd_gravity_wire_graph_bundle( wire, &off, &id, &cnt, txn, txn_sz ) ) ) return 0;
  if( FD_UNLIKELY( memcmp( id, node->key, 32UL ) || !cnt ) ) return 0;
  for( ulong j=0UL; j<cnt; j++ ) {
    if( FD_UNLIKELY( txn_sz[ j ]>FD_TXN_MTU ) ) return 0;
    node->txn   [ j ] = txn   [ j ];
    node->txn_sz[ j ] = (ushort)txn_sz[ j ];
  }
  node->txn_cnt = (uint)cnt;
  return 1;
}

/* ring_alloc returns where sz entries fit in a pool of pool_sz, after
   the queued graphs' entries [lo,hi), or ULONG_MAX.  Each graph holds
   at least one entry, so lo==hi means full. */

static ulong
ring_alloc( int   empty,
            ulong lo,
            ulong hi,
            ulong pool_sz,
            ulong sz ) {
  if( empty    ) return 0UL;
  if( hi>lo    ) return fd_ulong_if( pool_sz-hi>=sz, hi, fd_ulong_if( lo>=sz, 0UL, ULONG_MAX ) );
  return fd_ulong_if( lo-hi>=sz, hi, ULONG_MAX );
}

/* graph_alloc places graph's nodes and edges in the pools.  Graphs
   finish in order, so the pools are rings. */

static int
graph_alloc( fd_gravity_tile_t * ctx,
             graph_t *           graph,
             ulong               node_cnt,
             ulong               edge_cnt ) {
  int       empty = !ctx->graph_cnt;
  graph_t * head  = graph_at( ctx, 0UL );
  graph_t * tail  = graph_at( ctx, ctx->graph_cnt+GRAPH_MAX-1UL );
  graph->node_sz  = node_cnt+1UL;
  graph->edge_sz  = edge_cnt+1UL;
  graph->node_off = ring_alloc( empty, head->node_off, tail->node_off+tail->node_sz, NODE_POOL, graph->node_sz );
  graph->edge_off = ring_alloc( empty, head->edge_off, tail->edge_off+tail->edge_sz, EDGE_POOL, graph->edge_sz );
  if( FD_UNLIKELY( graph->node_off==ULONG_MAX || graph->edge_off==ULONG_MAX ) ) return 0;
  graph->node = ctx->node_pool+graph->node_off;
  graph->row  = ctx->row_pool +graph->node_off;
  graph->col  = ctx->col_pool +graph->edge_off;
  return 1;
}

/* on_graph returns 1 if the frame holding wire must be retained while
   its transactions are published. */

static int
on_graph( fd_gravity_tile_t *             ctx,
          fd_gravity_wire_graph_t const * wire ) {
  ctx->stat[ STAT_GRAPHS ]++;
  if( FD_UNLIKELY( !ctx->slot_relay || wire->slot!=ctx->leader_slot || ctx->graph_cnt==GRAPH_MAX ) ) {
    reject_graph( ctx, wire, FD_GRAVITY_WIRE_NI_SLOT_ENDED );
    return 0;
  }

  ulong     n     = wire->node_cnt;
  graph_t * graph = graph_at( ctx, ctx->graph_cnt );
  int       ok    = n && n<=NODE_MAX && wire->edge_cnt<=EDGE_MAX && wire->tx_cnt+wire->bundle_cnt<=NODE_MAX;
  if( FD_UNLIKELY( ok && !graph_alloc( ctx, graph, n, wire->edge_cnt ) ) ) {
    reject_graph( ctx, wire, FD_GRAVITY_WIRE_NI_SLOT_ENDED );
    return 0;
  }
  for( ulong i=0UL; ok && i<=n; i++ ) {
    graph->row[ i ] = FD_LOAD( uint, wire->row_offsets+4UL*i );
    ok = i ? graph->row[ i ]>=graph->row[ i-1UL ] : !graph->row[ 0 ];
  }
  ok = ok && graph->row[ n ]==wire->edge_cnt;
  for( ulong e=0UL; ok && e<wire->edge_cnt; e++ ) {
    graph->col[ e ] = FD_LOAD( uint, wire->col_indices+4UL*e );
    ok = graph->col[ e ]<n;
  }

  ulong off = 0UL;
  for( ulong i=0UL; ok && i<n; i++ ) {
    node_t * node = graph->node+i;
    uchar const * key;
    memset( node, 0, sizeof(node_t) );
    ok = !fd_gravity_wire_graph_node( wire, &off, &node->is_bundle, &key, &node->depth );
    if( ok ) fd_memcpy( node->key, key, node->is_bundle ? 32UL : 16UL );
  }
  for( ulong e=0UL; ok && e<wire->edge_cnt; e++ ) graph->node[ graph->col[ e ] ].preds++;

  /* A cycle would never run. */
  ulong q_end = 0UL;
  for( ulong i=0UL; ok && i<n; i++ ) {
    ctx->topo_preds[ i ] = graph->node[ i ].preds;
    if( !ctx->topo_preds[ i ] ) ctx->topo_queue[ q_end++ ] = i;
  }
  for( ulong q=0UL; ok && q<q_end; q++ ) {
    ulong v = ctx->topo_queue[ q ];
    for( uint e=graph->row[ v ]; e<graph->row[ v+1UL ]; e++ ) {
      if( !--ctx->topo_preds[ graph->col[ e ] ] ) ctx->topo_queue[ q_end++ ] = graph->col[ e ];
    }
  }
  ok = ok && q_end==n && index_orders( ctx, wire );
  if( FD_UNLIKELY( !ok ) ) {
    order_map_clear( ctx->tx_map );
    order_map_clear( ctx->bundle_map );
    reject_graph( ctx, wire, FD_GRAVITY_WIRE_NI_UNKNOWN_ORDERS );
    return 0;
  }

  graph->slot     = wire->slot;
  graph->rx_at    = (ulong)fd_log_wallclock();
  graph->node_cnt = n;
  graph->done_cnt = 0UL;
  graph->base_id  = ctx->next_id;
  fd_memcpy( graph->uuid, wire->uuid, 16UL );
  ctx->next_id += n;
  ctx->graph_cnt++;

  for( ulong i=0UL; i<n; i++ ) {
    if( FD_UNLIKELY( !order_find( ctx, wire, graph->node+i ) ) ) {
      graph->node[ i ].txn_cnt = 0U;
      admit_failed( ctx, graph, i, FD_GRAVITY_WIRE_NI_UNKNOWN_ORDERS );
    }
  }
  order_map_clear( ctx->tx_map );
  order_map_clear( ctx->bundle_map );

  ctx->pub_graph = graph;
  ctx->pub_node  = 0UL;
  if( ctx->graph_cnt==1UL ) activate( ctx );
  return 1;
}

/* publish_node sends the transactions of the next node of pub_graph to
   resolv as one bundle. */

static void
publish_node( fd_gravity_tile_t * ctx,
              fd_stem_context_t * stem ) {
  graph_t * graph = ctx->pub_graph;
  ulong     idx   = ctx->pub_node++;
  node_t *  node  = graph->node+idx;
  if( FD_UNLIKELY( ctx->pub_node==graph->node_cnt ) ) ctx->pub_graph = NULL;
  if( FD_UNLIKELY( node->admit!=ADMIT_PENDING ) ) return;

  /* Parse first, so a bad transaction fails the node before any of it
     reaches resolv. */
  ulong txn_t_sz[ FD_GRAVITY_WIRE_BUNDLE_TXN_MAX ];
  for( ulong i=0UL; i<node->txn_cnt; i++ ) {
    txn_t_sz[ i ] = fd_txn_parse( node->txn[ i ], node->txn_sz[ i ], ctx->txn_t[ i ], NULL );
    if( FD_UNLIKELY( !txn_t_sz[ i ] ) ) {
      admit_failed( ctx, graph, idx, FD_GRAVITY_WIRE_NI_SANITIZE_FAILURE );
      return;
    }
    uchar const * sig = node->txn[ i ]+ctx->txn_t[ i ]->signature_off;
    for( ulong j=0UL; j<i; j++ ) {
      if( FD_UNLIKELY( !memcmp( sig, node->txn[ j ]+ctx->txn_t[ j ]->signature_off, 64UL ) ) ) {
        admit_failed( ctx, graph, idx, FD_GRAVITY_WIRE_NI_SANITIZE_FAILURE );
        return;
      }
    }
  }

  for( ulong i=0UL; i<node->txn_cnt; i++ ) {
    ulong key = fd_ulong_max( FD_LOAD( ulong, node->txn[ i ]+ctx->txn_t[ i ]->signature_off ), 1UL );
    sig_ent_t * ent = sig_map_insert( ctx->sig_map, key );
    if( FD_UNLIKELY( !ent ) ) { /* a transaction already in flight */
      admit_failed( ctx, graph, idx, FD_GRAVITY_WIRE_NI_SANITIZE_FAILURE );
      return;
    }
    ent->graph = graph;
    ent->node  = (uint)idx;
    ent->txn   = (uint)i;
    node->sig_key[ i ] = key;
  }

  ulong id = graph->base_id+idx;
  for( ulong i=0UL; i<node->txn_cnt; i++ ) {
    fd_txn_m_t * txnm = fd_chunk_to_laddr( ctx->resolv_out->mem, ctx->resolv_out->chunk );
    *txnm = (fd_txn_m_t){
      .payload_sz       = node->txn_sz[ i ],
      .txn_t_sz         = (ushort)txn_t_sz[ i ],
      .source_tpu       = FD_TXN_M_TPU_SOURCE_BUNDLE,
      .first_seen_nanos = (long)graph->rx_at,
      .block_engine     = {
        .bundle_id      = id,
        .bundle_txn_cnt = node->txn_cnt,
        .commission     = ctx->block_builder_commission,
      },
    };
    fd_memcpy( txnm->block_engine.commission_pubkey, ctx->block_builder, 32UL );
    fd_memcpy( fd_txn_m_payload( txnm ), node->txn[ i ], node->txn_sz[ i ] );
    fd_memcpy( fd_txn_m_txn_t( txnm ), ctx->txn_t[ i ], txn_t_sz[ i ] );

    ulong sz = fd_txn_m_realized_footprint( txnm, 1, 0 );
    fd_stem_publish( stem, ctx->resolv_out->idx, 1UL, ctx->resolv_out->chunk, sz, 0UL, 0UL, 0UL );
    ctx->resolv_out->chunk = fd_dcache_compact_next( ctx->resolv_out->chunk, sz, ctx->resolv_out->chunk0, ctx->resolv_out->wmark );
  }
}

/* dispatch sends run commands for the deepest ready nodes, keeping a
   few more in flight than there are execle tiles. */

static void
dispatch( fd_gravity_tile_t * ctx,
          fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( !ctx->graph_cnt ) ) return;
  graph_t * graph = graph_at( ctx, 0UL );
  ulong     cnt   = 0UL;
  while( ctx->heap_cnt && ctx->running<ctx->execle_cnt+RUN_AHEAD && cnt<RUN_BATCH_MAX ) {
    ulong    idx  = heap_pop( ctx );
    node_t * node = graph->node+idx;
    node->state  = NODE_RUN;
    node->run_at = (ulong)fd_log_wallclock();
    ctx->run_batch[ cnt++ ] = ((graph->base_id+idx)<<1) | fd_ulong_if( node->is_bundle, 0UL, FD_GRAVITY_RUN_LOOSE );
    ctx->running++;
  }
  if( FD_UNLIKELY( !cnt ) ) return;

  ulong sz = cnt*sizeof(ulong);
  fd_memcpy( fd_chunk_to_laddr( ctx->pack_out->mem, ctx->pack_out->chunk ), ctx->run_batch, sz );
  fd_stem_publish( stem, ctx->pack_out->idx, 0UL, ctx->pack_out->chunk, sz, 0UL, 0UL, 0UL );
  ctx->pack_out->chunk = fd_dcache_compact_next( ctx->pack_out->chunk, sz, ctx->pack_out->chunk0, ctx->pack_out->wmark );
}

/* Leader slots *******************************************************/

static inline int
eligible( fd_gravity_tile_t const * ctx ) {
  return has_session( ctx ) && !ctx->tripped && !ctx->relay[ ctx->active ].drop &&
         ( ctx->progress_slot==ULONG_MAX || ctx->progress_slot>ctx->native_until );
}

/* update_mode tells pack whether it may build windows from the relay.
   Pack decides each window at its first slot, see fd_gravity.h. */

static void
update_mode( fd_gravity_tile_t * ctx ) {
  ulong val = (ulong)eligible( ctx );
  if( FD_LIKELY( val==ctx->mode_val ) ) return;
  ctx->mode_val = val;
  fd_fseq_update( ctx->mode, val );
  send_progress( ctx );
}

static void
set_progress_slot( fd_gravity_tile_t * ctx,
                   ulong               slot ) {
  if( FD_UNLIKELY( slot==ctx->progress_slot ) ) return;
  ctx->progress_slot = slot;
  send_progress( ctx );
}

/* fallback packs the rest of our window natively. */

static void
fallback( fd_gravity_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->slot_relay ) ) flush( ctx, FD_GRAVITY_WIRE_NI_SLOT_ENDED );
  ctx->slot_relay = 0;
  ctx->mode_val   = 0UL;
  fd_fseq_update( ctx->mode, 0UL );
  if( FD_UNLIKELY( ctx->leader_slot!=ULONG_MAX ) ) set_progress_slot( ctx, ctx->leader_slot );
}

static void
set_failsafe( fd_gravity_tile_t * ctx,
              int                 tripped ) {
  ctx->tripped = tripped;
  char c = tripped ? '1' : '0';
  if( FD_UNLIKELY( 1L!=pwrite( ctx->failsafe_fd, &c, 1UL, 0L ) || -1==fsync( ctx->failsafe_fd ) ) )
    FD_LOG_WARNING(( "writing the failsafe file failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
end_slot( fd_gravity_tile_t * ctx,
          int                 leadership_continues ) {
  drain_clear( ctx, FD_GRAVITY_WIRE_NI_SLOT_ENDED ); /* results of an earlier slot are in by now */
  if( FD_LIKELY( ctx->slot_relay ) ) {
    drain_running( ctx );
    flush( ctx, FD_GRAVITY_WIRE_NI_SLOT_ENDED );
    ctx->leadership_missed = !ctx->slot_executed && !ctx->drain_cnt;
  }
  if( !leadership_continues ) {
    if( FD_UNLIKELY( ctx->leadership_missed ) ) {
      FD_LOG_WARNING(( "relay built nothing at the end of our leadership, packing natively until the relay clears the failsafe" ));
      set_failsafe( ctx, 1 );
      for( ulong i=0UL; i<ctx->relay_cnt; i++ ) ctx->relay[ i ].drop = 1; /* rejoin without progress, so no relay builds for us */
      fallback( ctx );
    }
    ctx->leadership_missed = 0;
  }
  ctx->leader_slot   = ULONG_MAX;
  ctx->slot_relay    = 0;
  ctx->slot_executed = 0;
}

/* apply_mode starts leader_slot as pack decided it. */

static void
apply_mode( fd_gravity_tile_t * ctx,
            int                 active ) {
  ctx->slot_relay = active && has_session( ctx ) && !ctx->tripped;
  ctx->mode_slot  = ULONG_MAX;
  set_progress_slot( ctx, ctx->leader_slot );
  /* As the connector does for a validator that cranks itself.  Pack
     runs the crank ahead of relay nodes. */
  if( ctx->slot_relay ) SEND( ctx, fd_gravity_wire_ready_for_tips, ctx->leader_slot );
}

static void
on_reset( fd_gravity_tile_t *    ctx,
          fd_poh_reset_t const * reset ) {
  ctx->next_leader_slot = reset->next_leader_slot;
  ctx->blockhash_known  = 1;
  fd_memcpy( ctx->blockhash, reset->completed_blockhash, 32UL );
  if( FD_UNLIKELY( ctx->leader_slot!=ULONG_MAX && reset->completed_slot>=ctx->leader_slot ) ) {
    end_slot( ctx, reset->next_leader_slot==ctx->leader_slot+1UL );
  }
  /* The relay starts building a slot on its Progress, so a slot pack may
     build from the relay is reported once pack decides. */
  ulong slot = reset->completed_slot+1UL;
  if( FD_LIKELY( slot!=reset->next_leader_slot || !ctx->mode_val ) ) set_progress_slot( ctx, slot );
}

/* on_slot_completed reports Progress for every slot replay completes,
   and ends our leadership once its window completes.  Under Alpenglow,
   replay resets only ahead of our leader windows. */

static void
on_slot_completed( fd_gravity_tile_t *                ctx,
                   fd_replay_slot_completed_t const * completed ) {
  if( FD_UNLIKELY( ctx->leader_slot!=ULONG_MAX && completed->slot>=window_end( ctx->leader_slot ) ) ) {
    end_slot( ctx, ctx->next_leader_slot==ctx->leader_slot+1UL );
  }
  ulong slot = completed->slot+1UL;
  if( FD_UNLIKELY( ctx->leader_slot!=ULONG_MAX || ( ctx->progress_slot!=ULONG_MAX && slot<=ctx->progress_slot ) ) ) return;
  ctx->blockhash_known = 1;
  fd_memcpy( ctx->blockhash, completed->block_hash.uc, 32UL );
  if( FD_LIKELY( slot!=ctx->next_leader_slot || !ctx->mode_val ) ) set_progress_slot( ctx, slot );
}

static void
on_became_leader( fd_gravity_tile_t *        ctx,
                  fd_became_leader_t const * became ) {
  ulong slot = became->slot;
  if( FD_UNLIKELY( ctx->leader_slot!=ULONG_MAX && slot!=ctx->leader_slot ) ) end_slot( ctx, slot==ctx->leader_slot+1UL );
  ctx->leader_slot      = slot;
  ctx->next_leader_slot = slot;
  ctx->leader_start_ns  = became->slot_start_ns;
  ctx->leader_end_ns   = became->slot_end_ns;
  ctx->slot_relay      = 0;
  ctx->slot_executed   = 0;
  if(      ctx->mode_slot==slot ) apply_mode( ctx, ctx->mode_active );
  else if( !ctx->mode_val       ) set_progress_slot( ctx, slot );
}

static void
on_mode( fd_gravity_tile_t * ctx,
         ulong               slot,
         int                 active ) {
  if( FD_LIKELY( slot==ctx->leader_slot ) ) {
    apply_mode( ctx, active );
  } else if( ctx->leader_slot==ULONG_MAX || slot>ctx->leader_slot ) {
    /* Pack became leader before we heard of it */
    ctx->mode_slot   = slot;
    ctx->mode_active = active;
  }
}

/* Relay sessions *****************************************************/

static void
epoll_out( fd_gravity_tile_t * ctx,
           relay_t *           r,
           int                 want ) {
  if( FD_LIKELY( want==r->epoll_out ) ) return;
  struct epoll_event ev = { .events = EPOLLIN | (want ? EPOLLOUT : 0U), .data.fd = r->sock };
  if( FD_UNLIKELY( -1==epoll_ctl( FD_WAKER_INNER_FD( ctx->waker_client_idx ), EPOLL_CTL_MOD, r->sock, &ev ) ) )
    FD_LOG_ERR(( "epoll_ctl(MOD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  r->epoll_out = want;
}

/* end_session ends the active relay's session.  Its graphs are reported
   as not included; the window stays relay-built if another relay takes
   over, see select_active. */

static void
end_session( fd_gravity_tile_t * ctx ) {
  flush( ctx, FD_GRAVITY_WIRE_NI_SLOT_ENDED );
  drain_clear( ctx, FD_GRAVITY_WIRE_NI_SLOT_ENDED );
  ctx->lost   = ctx->active;
  ctx->active = ULONG_MAX;
}

/* close_relay closes relay i.  Only call it at a point where no frame
   or graph is being handled; elsewhere, set drop. */

static void
close_relay( fd_gravity_tile_t * ctx,
             ulong               i ) {
  relay_t * r = ctx->relay+i;
  r->drop = 0;
  if( FD_UNLIKELY( r->state==STATE_DISCONNECTED ) ) return;
  if( i==ctx->active ) end_session( ctx );
  if( FD_LIKELY( r->sock>=0 ) ) close( r->sock ); /* also leaves the epoll set */
  r->sock         = -1;
  r->state        = STATE_DISCONNECTED;
  r->confirmed    = 0;
  r->tpu_ip4      = 0U;
  r->shred_seq++;
  memset( r->shred_dests, 0, sizeof(fd_gravity_shred_dests_t) );
  r->rx_off       = 0UL;
  r->rx_len       = 0UL;
  r->rx_held      = 0;
  r->tx_off       = 0UL;
  r->tx_len       = 0UL;
  r->tx_new       = 0;
  r->reconnect_at = deadline_ns( ctx, RECONNECT_NS );
  FD_LOG_INFO(( "disconnected from relay %s", r->host ));
}

/* select_active keeps a confirmed active relay.  Otherwise it takes the
   first confirmed relay after the one lost last, so failover cycles
   through all of them, and failing that any logged-in relay, as the
   connector does. */

static void
select_active( fd_gravity_tile_t * ctx ) {
  if( FD_LIKELY( has_session( ctx ) && ctx->relay[ ctx->active ].confirmed ) ) return;
  ulong pick  = ctx->active;
  ulong start = ctx->lost==ULONG_MAX ? 0UL : ctx->lost+1UL;
  for( ulong k=0UL; k<ctx->relay_cnt; k++ ) {
    ulong     i = (start+k)%ctx->relay_cnt;
    relay_t * r = ctx->relay+i;
    if( r->state!=STATE_READY || r->drop ) continue;
    if( r->confirmed ) { pick = i; break; }
    if( pick==ULONG_MAX ) pick = i;
  }
  if( FD_LIKELY( pick==ctx->active ) ) return;
  if( has_session( ctx ) ) end_session( ctx );
  ctx->active = pick;
  if( FD_UNLIKELY( pick==ULONG_MAX ) ) {
    fallback( ctx );
    return;
  }
  relay_t * r = ctx->relay+pick;
  r->last_rx = fd_tickcount();
  FD_LOG_NOTICE(( "relay %s (" FD_IP4_ADDR_FMT ":%hu) is active", r->host, FD_IP4_ADDR_FMT_ARGS( r->ip4 ), r->port ));
  send_progress( ctx );
  if( ctx->slot_relay ) SEND( ctx, fd_gravity_wire_ready_for_tips, ctx->leader_slot );
}

static inline void
drop_if_requested( fd_gravity_tile_t * ctx ) {
  for( ulong i=0UL; i<ctx->relay_cnt; i++ ) {
    if( FD_UNLIKELY( ctx->relay[ i ].drop ) ) close_relay( ctx, i );
  }
  select_active( ctx );
}

static void
connect_relay( fd_gravity_tile_t * ctx,
               relay_t *           r,
               uint                ip4 ) {
  r->ip4 = ip4;
  int sock = socket( AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( sock<0 ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int one          = 1;
  int user_timeout = USER_TIMEOUT_MS;
  if( FD_UNLIKELY( setsockopt( sock, SOL_TCP, TCP_NODELAY,      &one,          sizeof(int) ) ||
                   setsockopt( sock, SOL_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(int) ) ) )
    FD_LOG_ERR(( "setsockopt failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct epoll_event ev = { .events = EPOLLIN|EPOLLOUT, .data.fd = sock };
  if( FD_UNLIKELY( -1==epoll_ctl( FD_WAKER_INNER_FD( ctx->waker_client_idx ), EPOLL_CTL_ADD, sock, &ev ) ) )
    FD_LOG_ERR(( "epoll_ctl(ADD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  r->sock      = sock;
  r->epoll_out = 1;
  r->state     = STATE_CONNECTING;
  r->deadline  = deadline_ns( ctx, CONNECT_TIMEOUT_NS );

  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = r->ip4,
    .sin_port        = fd_ushort_bswap( r->port ),
  };
  if( FD_UNLIKELY( -1==connect( sock, fd_type_pun_const( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
    FD_LOG_WARNING(( "connect to relay %s (" FD_IP4_ADDR_FMT ":%hu) failed (%i-%s)", r->host,
                     FD_IP4_ADDR_FMT_ARGS( r->ip4 ), r->port, errno, fd_io_strerror( errno ) ));
    r->drop = 1;
    return;
  }
  SEND_TO( r, fd_gravity_wire_client_hello, ctx->identity );
}

/* dns_advance connects the relays whose lookup finished, taking their
   addresses in turn on successive connects.  Lookups never block. */

static void
dns_advance( fd_gravity_tile_t * ctx ) {
  fd_adns_result_t res[1];
  while( fd_adns_advance( ctx->adns, fd_log_wallclock(), res ) ) {
    relay_t * r = ctx->relay+res->req_id;
    r->resolving = 0;
    if( FD_UNLIKELY( res->err ) ) FD_LOG_WARNING(( "resolving relay `%s` failed (%d-%s)", r->host, res->err, fd_gai_strerror( res->err ) ));
    if( FD_UNLIKELY( res->err || ctx->halted || ctx->asleep ) ) {
      r->reconnect_at = deadline_ns( ctx, RECONNECT_NS );
      continue;
    }
    connect_relay( ctx, r, res->addrs[ r->addr_rr++ % res->addr_cnt ] );
  }
}

static void
on_boot_frame( fd_gravity_tile_t * ctx,
               relay_t *           r,
               uchar const *       payload,
               ulong               sz ) {
  uchar const * challenge = NULL;
  uint tag = fd_gravity_wire_boot_decode( payload, sz, &challenge );
  if( r->state==STATE_AWAIT_HELLO && tag==FD_GRAVITY_WIRE_BOOT_SERVER_HELLO ) {
    uchar msg[ FD_GRAVITY_WIRE_LOGIN_MSG_SZ ];
    uchar sig[ 64 ];
    fd_gravity_wire_login_msg( msg, ctx->identity, challenge );
    fd_keyguard_client_sign( ctx->keyguard_client, sig, msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_ED25519 );
    SEND_TO( r, fd_gravity_wire_auth_proof, sig );
    r->state = STATE_AWAIT_ACCEPT;
  } else if( r->state==STATE_AWAIT_ACCEPT && tag==FD_GRAVITY_WIRE_BOOT_ACCEPTED ) {
    SEND_TO( r, fd_gravity_wire_handshake, ctx->identity, ctx->version, (uint)ctx->execle_cnt,
             ctx->filter_ofac, ctx->blacklisted[ 0 ], ctx->blacklisted_cnt, ctx->jito_tip_weight_bps );
    r->state = STATE_READY;
    FD_LOG_NOTICE(( "logged in to relay %s (" FD_IP4_ADDR_FMT ":%hu)", r->host, FD_IP4_ADDR_FMT_ARGS( r->ip4 ), r->port ));
  } else {
    FD_LOG_WARNING(( "relay %s login failed (state %d, frame %u)", r->host, r->state, tag ));
    r->drop = 1;
  }
}

/* on_be_challenge signs a block engine's login challenge for the relay,
   which subscribes to that block engine as us.  The sign tile signs
   base58(identity) "-" challenge, and only for a 9 byte challenge;
   anything but ASCII alphanumerics is refused here too. */

static void
on_be_challenge( fd_gravity_tile_t * ctx,
                 relay_t *           r,
                 uchar const *       challenge ) {
  for( ulong i=0UL; i<FD_GRAVITY_WIRE_BE_CHALLENGE_SZ; i++ ) {
    uchar c = challenge[ i ];
    if( FD_UNLIKELY( !( (c>='0' && c<='9') || (c>='A' && c<='Z') || (c>='a' && c<='z') ) ) ) {
      FD_LOG_WARNING(( "relay %s sent an invalid block engine challenge", r->host ));
      return;
    }
  }
  uchar sig[ 64 ];
  fd_keyguard_client_sign( ctx->keyguard_client, sig, challenge, FD_GRAVITY_WIRE_BE_CHALLENGE_SZ, FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 );
  SEND_TO( r, fd_gravity_wire_be_challenge_sig, challenge, sig );
}

/* on_frame handles one frame from relay r.  Returns 1 if the frame must
   be retained.  Only the active relay's session messages are acted on;
   a standby relay's confirm its session and set its TPU address and
   shred destinations. */

static int
on_frame( fd_gravity_tile_t * ctx,
          relay_t *           r,
          uchar const *       payload,
          ulong               sz ) {
  if( FD_UNLIKELY( r->state!=STATE_READY ) ) {
    on_boot_frame( ctx, r, payload, sz );
    return 0;
  }

  fd_gravity_wire_msg_t msg[1];
  int err = fd_gravity_wire_msg_decode( payload, sz, msg );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_WARNING(( "malformed message from relay %s (tag %u)", r->host, msg->tag ));
    r->drop = 1;
    return 0;
  }
  r->confirmed = 1;
  if( err ) return 0;

  if( FD_UNLIKELY( msg->tag==FD_GRAVITY_WIRE_R2C_TPU_ADDRESS ) ) {
    r->tpu_ip4  = msg->tpu.ip4;
    r->tpu_port = msg->tpu.port;
    return 0;
  }
  if( FD_UNLIKELY( msg->tag==FD_GRAVITY_WIRE_R2C_SHRED_RECV || msg->tag==FD_GRAVITY_WIRE_R2C_SHRED_RTX_RECV ) ) {
    /* The relay sends them when it activates us */
    int                       rtx  = msg->tag==FD_GRAVITY_WIRE_R2C_SHRED_RTX_RECV;
    ulong *                   cnt  = rtx ? &r->shred_dests->retransmit_cnt : &r->shred_dests->leader_cnt;
    fd_gravity_shred_dest_t * dest = rtx ?  r->shred_dests->retransmit     :  r->shred_dests->leader;
    int changed = *cnt!=msg->shred_dests.cnt;
    for( ulong i=0UL; i<msg->shred_dests.cnt; i++ ) {
      changed |= dest[ i ].ip4!=msg->shred_dests.ip4[ i ] || dest[ i ].port!=msg->shred_dests.port[ i ];
      dest[ i ] = (fd_gravity_shred_dest_t){ .ip4 = msg->shred_dests.ip4[ i ], .port = msg->shred_dests.port[ i ] };
    }
    *cnt = msg->shred_dests.cnt;
    r->shred_seq += (ulong)changed;
    return 0;
  }
  if( FD_UNLIKELY( r!=ctx->relay+ctx->active ) ) return 0;

  switch( msg->tag ) {
  case FD_GRAVITY_WIRE_R2C_GRAPH:
    return on_graph( ctx, msg->graph );
  case FD_GRAVITY_WIRE_R2C_PING:
    SEND_TO( r, fd_gravity_wire_pong, msg->ping );
    return 0;
  case FD_GRAVITY_WIRE_R2C_BE_CHALLENGE:
    on_be_challenge( ctx, r, msg->be_challenge );
    return 0;
  case FD_GRAVITY_WIRE_R2C_DELETE_FAILSAFE:
    if( ctx->tripped ) {
      FD_LOG_NOTICE(( "relay cleared the failsafe" ));
      set_failsafe( ctx, 0 );
    }
    send_progress( ctx );
    return 0;
  default:
    return 0;
  }
}

/* rx_frames handles r's buffered frames, stopping at a retained one. */

static void
rx_frames( fd_gravity_tile_t * ctx,
           relay_t *           r ) {
  while( !r->rx_held && !r->drop && r->rx_len>=FD_GRAVITY_WIRE_FRAME_HDR_SZ ) {
    uchar const * hdr = r->rx_buf+r->rx_off;
    ulong         sz  = FD_LOAD( uint, hdr );
    if( FD_UNLIKELY( sz>RX_BUF_SZ-FD_GRAVITY_WIRE_FRAME_HDR_SZ ) ) {
      FD_LOG_WARNING(( "relay %s frame of %lu bytes is too large", r->host, sz ));
      r->drop = 1;
      return;
    }
    if( r->rx_len<FD_GRAVITY_WIRE_FRAME_HDR_SZ+sz ) return;
    r->last_rx = fd_tickcount();
    if( FD_UNLIKELY( sz && on_frame( ctx, r, hdr+FD_GRAVITY_WIRE_FRAME_HDR_SZ, sz ) ) ) {
      r->rx_held = 1;
      return;
    }
    r->rx_off += FD_GRAVITY_WIRE_FRAME_HDR_SZ+sz;
    r->rx_len -= FD_GRAVITY_WIRE_FRAME_HDR_SZ+sz;
  }
}

static void
rx_socket( fd_gravity_tile_t * ctx,
           relay_t *           r ) {
  rx_frames( ctx, r );
  while( !r->rx_held && !r->drop ) {
    if( r->rx_off ) {
      memmove( r->rx_buf, r->rx_buf+r->rx_off, r->rx_len );
      r->rx_off = 0UL;
    }
    if( FD_UNLIKELY( r->rx_len==RX_BUF_SZ ) ) return;
    long n = recv( r->sock, r->rx_buf+r->rx_len, RX_BUF_SZ-r->rx_len, MSG_DONTWAIT );
    if( FD_UNLIKELY( n==0L || ( n<0L && errno!=EAGAIN && errno!=EINTR ) ) ) {
      FD_LOG_WARNING(( "relay %s connection closed (%i-%s)", r->host, n ? errno : 0, n ? fd_io_strerror( errno ) : "eof" ));
      r->drop = 1;
      return;
    }
    if( n<0L ) return;
    r->rx_len += (ulong)n;
    rx_frames( ctx, r );
  }
}

static void
tx_socket( fd_gravity_tile_t * ctx,
           relay_t *           r ) {
  r->tx_new = 0;
  while( r->tx_len ) {
    long n = send( r->sock, r->tx_buf+r->tx_off, r->tx_len, MSG_NOSIGNAL|MSG_DONTWAIT );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EINTR ) ) break;
      FD_LOG_WARNING(( "relay %s send failed (%i-%s)", r->host, errno, fd_io_strerror( errno ) ));
      r->drop = 1;
      return;
    }
    r->tx_off += (ulong)n;
    r->tx_len -= (ulong)n;
  }
  if( !r->tx_len ) r->tx_off = 0UL;
  epoll_out( ctx, r, !!r->tx_len );
}

/* step services the relay sockets. */

static void
step( fd_gravity_tile_t * ctx ) {
  for( ulong i=0UL; i<ctx->relay_cnt; i++ ) {
    relay_t * r = ctx->relay+i;
    if( r->sock<0 || r->drop ) continue;
    if( FD_UNLIKELY( r->state==STATE_CONNECTING ) ) {
      struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = r->ip4,
        .sin_port        = fd_ushort_bswap( r->port ),
      };
      /* connect again reports whether the first one finished */
      if( -1==connect( r->sock, fd_type_pun_const( &addr ), sizeof(addr) ) && errno!=EISCONN ) {
        if( FD_LIKELY( errno==EALREADY || errno==EINPROGRESS ) ) continue;
        FD_LOG_WARNING(( "connect to relay %s failed (%i-%s)", r->host, errno, fd_io_strerror( errno ) ));
        r->drop = 1;
        continue;
      }
      r->state    = STATE_AWAIT_HELLO;
      r->deadline = deadline_ns( ctx, LOGIN_TIMEOUT_NS );
      r->last_rx  = fd_tickcount();
    }
    rx_socket( ctx, r );
    if( FD_LIKELY( !r->drop ) ) tx_socket( ctx, r );
  }
}

/* Links **************************************************************/

static void
on_execle( fd_gravity_tile_t * ctx,
           ulong               in_idx,
           ulong               sig,
           ulong               sz ) {
  ulong slot    = fd_disco_execle_sig_slot( sig );
  ulong txn_cnt = (sz-sizeof(fd_microblock_trailer_t))/sizeof(fd_txn_p_t);
  fd_txn_p_t const * txns = (fd_txn_p_t const *)ctx->staged.execle;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t const * txn = txns+i;
    ulong key = fd_ulong_max( FD_LOAD( ulong, txn->payload+TXN(txn)->signature_off ), 1UL );
    sig_ent_t * ent = sig_map_query( ctx->sig_map, key, NULL );
    if( FD_UNLIKELY( !ent ) ) continue; /* the tip crank, or a node already reported */
    graph_t * graph = ent->graph;
    ulong     idx   = ent->node;
    drain_t * d     = graph ? NULL : ctx->drain+idx;
    node_t *  node  = graph ? graph->node+idx : &d->node;
    if( FD_UNLIKELY( node->state!=NODE_RUN || slot!=( graph ? graph->slot : d->slot ) ) ) continue;

    int included = !!(txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS);
    node->ni [ ent->txn ] = included ? 0U : fd_gravity_wire_ni_from_txn_err( -(int)(txn->flags>>24) );
    node->cus[ ent->txn ] = txn->execle_cu.actual_consumed_cus;
    node->worker          = (uchar)ctx->in_execle[ in_idx ];
    if( FD_UNLIKELY( ++node->done_cnt<node->txn_cnt ) ) continue;
    if( FD_LIKELY( graph ) ) { ctx->slot_executed = 1; node_done( ctx, graph, idx ); }
    else                       drain_done( ctx, d );
  }
}

static uint
insert_reject_reason( int code ) {
  switch( code ) {
    case 0:                                    return FD_GRAVITY_WIRE_NI_SLOT_ENDED; /* pack is not building a relay slot */
    case FD_PACK_INSERT_REJECT_EXPIRED:        return FD_GRAVITY_WIRE_NI_BLOCKHASH_NOT_FOUND;
    case FD_PACK_INSERT_REJECT_DUPLICATE:      return fd_gravity_wire_ni_from_txn_err( FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED );
    case FD_PACK_INSERT_REJECT_ADDR_LUT:       return fd_gravity_wire_ni_from_txn_err( FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND );
    case FD_PACK_INSERT_REJECT_UNAFFORDABLE:   return fd_gravity_wire_ni_from_txn_err( FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE );
    case FD_PACK_INSERT_REJECT_ACCOUNT_CNT:    return fd_gravity_wire_ni_from_txn_err( FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS );
    case FD_PACK_INSERT_REJECT_DUPLICATE_ACCT: return fd_gravity_wire_ni_from_txn_err( FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE );
    case FD_PACK_INSERT_REJECT_TOO_LARGE:      return FD_GRAVITY_WIRE_NI_WOULD_EXCEED_MAX_BLOCK_COST;
    default:                                   return FD_GRAVITY_WIRE_NI_SANITIZE_FAILURE;
  }
}

/* sched_failed records why pack did not run a node of slot.  Pack
   reports the commands it drops at the end of its slot with a later
   slot. */

static void
sched_failed( node_t *                         node,
              ulong                            slot,
              fd_gravity_pack_report_t const * report ) {
  uint reason = FD_GRAVITY_WIRE_NI_UNKNOWN_ORDERS;
  if( report->code==FD_PACK_SCHEDULE_BUNDLE_DOES_NOT_FIT ) reason = FD_GRAVITY_WIRE_NI_WOULD_EXCEED_MAX_BLOCK_COST;
  if( report->slot!=slot                                 ) reason = FD_GRAVITY_WIRE_NI_SLOT_ENDED;
  node->ni[ 0 ] = reason;
  for( ulong i=1UL; i<FD_GRAVITY_WIRE_BUNDLE_TXN_MAX; i++ ) node->ni[ i ] = FD_GRAVITY_WIRE_NI_ALL_OR_NOTHING;
  node->worker = 255;
}

static void
on_pack_report( fd_gravity_tile_t *              ctx,
                fd_gravity_pack_report_t const * report ) {
  if( FD_UNLIKELY( report->kind==FD_GRAVITY_REPORT_MODE ) ) {
    on_mode( ctx, report->slot, report->code );
    return;
  }

  graph_t * graph;
  ulong     idx;
  node_t *  node = find_node( ctx, report->bundle_id, &graph, &idx );
  if( FD_UNLIKELY( !node ) ) {
    drain_t * d = find_drained( ctx, report->bundle_id );
    if( FD_LIKELY( d && report->kind==FD_GRAVITY_REPORT_SCHED_FAIL ) ) {
      sched_failed( &d->node, d->slot, report );
      drain_done( ctx, d );
    }
    return;
  }

  switch( report->kind ) {
  case FD_GRAVITY_REPORT_ADMITTED:
    /* Admitted in a later slot than its graph, pack deletes it then */
    if( FD_UNLIKELY( report->slot!=graph->slot ) ) {
      admit_failed( ctx, graph, idx, FD_GRAVITY_WIRE_NI_SLOT_ENDED );
      return;
    }
    if( FD_UNLIKELY( node->admit!=ADMIT_PENDING ) ) return;
    ctx->stat[ STAT_NODES_ADMITTED ]++;
    node->admit = ADMIT_OK;
    if( graph_running( ctx, graph ) && !node->preds ) heap_push( ctx, node, idx );
    return;
  case FD_GRAVITY_REPORT_REJECTED:
    ctx->stat[ STAT_NODES_REJECTED ]++;
    admit_failed( ctx, graph, idx, insert_reject_reason( report->code ) );
    return;
  case FD_GRAVITY_REPORT_SCHED_FAIL:
    if( FD_UNLIKELY( node->state!=NODE_RUN ) ) return;
    ctx->stat[ STAT_NODES_SCHED ]++;
    sched_failed( node, graph->slot, report );
    node_done( ctx, graph, idx );
    return;
  default:
    return;
  }
}

static void
on_resolv_fail( fd_gravity_tile_t *              ctx,
                fd_gravity_resolv_fail_t const * fail_msg ) {
  graph_t * graph;
  ulong     idx;
  if( FD_UNLIKELY( !find_node( ctx, fail_msg->bundle_id, &graph, &idx ) ) ) return;
  ctx->stat[ STAT_NODES_RESOLV ]++;
  uint reason = fail_msg->err==FD_GRAVITY_ERR_NO_BANK ? FD_GRAVITY_WIRE_NI_BANK_NOT_AVAILABLE : fd_gravity_wire_ni_from_txn_err( fail_msg->err );
  admit_failed( ctx, graph, idx, reason );
}

/* update_sleep keeps the tile off the relays until replay has caught up
   and our identity has leader slots, as the bundle tile keeps off the
   block engine.  Until then the relay can't build for us, and rejects
   an unstaked identity.  It also tracks the next leader slot, which
   Alpenglow replay publishes in a reset only right before our windows. */

static void
update_sleep( fd_gravity_tile_t * ctx ) {
  fd_wait_info_t wi[1];
  if( FD_UNLIKELY( !fd_wait_info_try_read( wi, ctx->wait_info ) ) ) return;
  ctx->caught_up |= wi->caught_up;
  ulong next = ( wi->next_leader_known && wi->next_leader_slot ) ? wi->next_leader_slot : ULONG_MAX;
  /* Replay writes wait_info in housekeeping, so a read can predate the
     leader slot we were just told we lead */
  if( ctx->leader_slot==ULONG_MAX || next>=ctx->leader_slot ) ctx->next_leader_slot = next;
  int asleep = !ctx->caught_up || !wi->next_leader_known || !wi->next_leader_slot;
  if( FD_LIKELY( asleep==ctx->asleep ) ) return;
  ctx->asleep = asleep;
  if( asleep ) {
    for( ulong i=0UL; i<ctx->relay_cnt; i++ ) ctx->relay[ i ].drop = 1;
    FD_LOG_NOTICE(( "gravity tile sleeping: %s", ctx->caught_up ? "no upcoming leader slots" : "not caught up" ));
  } else {
    FD_LOG_NOTICE(( "gravity tile waking: next leader slot %lu", wi->next_leader_slot ));
  }
}

/* Stem callbacks *****************************************************/

static void
during_housekeeping( fd_gravity_tile_t * ctx ) {
  /* As the bundle tile does, stop signing while the identity switches */
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    for( ulong i=0UL; i<ctx->relay_cnt; i++ ) ctx->relay[ i ].drop = 1;
    ctx->halted = 1;
    fd_memcpy( ctx->identity, ctx->keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    ctx->halted = 0;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
  update_sleep( ctx );
  drop_if_requested( ctx );

  long now = fd_tickcount();
  for( ulong i=0UL; i<ctx->relay_cnt; i++ ) {
    relay_t * r = ctx->relay+i;
    if( FD_UNLIKELY( r->state==STATE_DISCONNECTED ) ) {
      if( !ctx->halted && !ctx->asleep && !r->resolving && now>=r->reconnect_at ) r->resolving = !fd_adns_resolve( ctx->adns, r->host, i );
    } else if( FD_UNLIKELY( r->state!=STATE_READY && now>r->deadline ) ) {
      FD_LOG_WARNING(( "relay %s %s timed out", r->host, r->state==STATE_CONNECTING ? "connect" : "login" ));
      r->drop = 1;
    }
  }
  dns_advance( ctx );
  if( FD_LIKELY( has_session( ctx ) && !ctx->relay[ ctx->active ].rx_held ) ) {
    /* The relay pings every few ms near our leader slots, and slows down
       once our last slot ends, which can be well before replay completes
       it.  The socket is not read while a graph frame is retained. */
    relay_t * r    = ctx->relay+ctx->active;
    ulong     next = ctx->next_leader_slot;
    ulong     prog = ctx->progress_slot;
    int       near = ( ctx->leader_slot!=ULONG_MAX && fd_log_wallclock()<ctx->leader_end_ns ) ||
                     ( next!=ULONG_MAX && prog!=ULONG_MAX && next>prog && next<=prog+NEAR_LEADER_SLOTS );
    long      silence = near && !ctx->tripped ? LEADER_SILENCE_NS : IDLE_SILENCE_NS;
    if( FD_UNLIKELY( now-r->last_rx>(long)( (double)silence*ctx->tick_per_ns ) ) ) {
      FD_LOG_WARNING(( "relay %s went silent", r->host ));
      r->drop = 1;
    }
  }
  if( FD_UNLIKELY( has_session( ctx ) && now>=ctx->next_stats ) ) {
    for( ulong i=0UL; i<STAT_TIMING_CNT; i++ ) ctx->stat[ i ] = (ulong)( (double)ctx->stat[ i ]/ctx->tick_per_ns );
    SEND( ctx, fd_gravity_wire_stats, stat_names, ctx->stat, STAT_CNT );
    memset( ctx->stat, 0, sizeof(ctx->stat) );
    ctx->next_stats = deadline_ns( ctx, STATS_INTERVAL_NS );
  }
  drop_if_requested( ctx );
  update_mode( ctx );
}

/* Housekeeping runs the session timers, so don't park for long. */

static long
next_deadline( fd_gravity_tile_t * ctx ) {
  return deadline_ns( ctx, (long)10e6 );
}

static void
before_credit( fd_gravity_tile_t * ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;
  drop_if_requested( ctx );
  int open  = 0;
  int fresh = 0;
  for( ulong i=0UL; i<ctx->relay_cnt; i++ ) {
    open  |= ctx->relay[ i ].sock>=0;
    fresh |= ctx->relay[ i ].tx_new && ctx->relay[ i ].state!=STATE_CONNECTING;
  }
  if( FD_UNLIKELY( !open ) ) {
    if( FD_UNLIKELY( fd_fseq_query( ctx->waker_fseq )==1UL ) ) {
      fd_fseq_update( ctx->waker_fseq, 0UL );
      dns_advance( ctx );
      fd_waker_client_rearm( ctx->waker_client_idx );
    }
    return;
  }

  /* Writes that would block wait for the waker. */
  int  fired = fd_fseq_query( ctx->waker_fseq )==1UL;
  long now   = fd_tickcount();
  if( FD_LIKELY( !fired && !fresh && now<ctx->next_rx_poll ) ) return;
  if( fired ) fd_fseq_update( ctx->waker_fseq, 0UL );
  step( ctx );
  ctx->stat[ STAT_NETWORK_MAX_NS ] = fd_ulong_max( ctx->stat[ STAT_NETWORK_MAX_NS ], (ulong)( fd_tickcount()-now ) );
  if( fired ) {
    dns_advance( ctx );
    fd_waker_client_rearm( ctx->waker_client_idx );
  }
  ctx->next_rx_poll = deadline_ns( ctx, RX_POLL_NS );
  drop_if_requested( ctx );
  *charge_busy = 1;
}

static void
after_credit( fd_gravity_tile_t * ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;

  /* Publishing a retained graph frees the rx buffer for more frames. */
  if( FD_UNLIKELY( ctx->pub_graph ) ) {
    long start = fd_tickcount();
    publish_node( ctx, stem );
    ctx->stat[ STAT_PUBLISH_MAX_NS ] = fd_ulong_max( ctx->stat[ STAT_PUBLISH_MAX_NS ], (ulong)( fd_tickcount()-start ) );
    if( !ctx->pub_graph && has_session( ctx ) && ctx->relay[ ctx->active ].rx_held ) {
      release_rx_frame( ctx->relay+ctx->active );
      rx_frames( ctx, ctx->relay+ctx->active );
    }
    *charge_busy = 1;
  }

  if( FD_UNLIKELY( ctx->heap_cnt ) ) {
    long start = fd_tickcount();
    dispatch( ctx, stem );
    ctx->stat[ STAT_DISPATCH_MAX_NS ] = fd_ulong_max( ctx->stat[ STAT_DISPATCH_MAX_NS ], (ulong)( fd_tickcount()-start ) );
    *charge_busy = 1;
  }

  ulong relay = (ulong)( has_session( ctx ) && !ctx->tripped );
  if( FD_UNLIKELY( relay!=ctx->relay_val ) ) {
    fd_fseq_update( ctx->relay_fseq, relay );
    ctx->relay_val = relay;
  }

  uint   ip4  = relay ? ctx->relay[ ctx->active ].tpu_ip4 : 0U;
  ushort port = ip4 ? ctx->relay[ ctx->active ].tpu_port : (ushort)0;
  if( FD_UNLIKELY( ip4!=ctx->tpu_applied_ip4 || port!=ctx->tpu_applied_port ) ) {
    fd_gravity_tpu_t * tpu = fd_chunk_to_laddr( ctx->gossip_out->mem, ctx->gossip_out->chunk );
    *tpu = (fd_gravity_tpu_t){ .ip4 = ip4, .port = port };
    fd_stem_publish( stem, ctx->gossip_out->idx, 0UL, ctx->gossip_out->chunk, sizeof(fd_gravity_tpu_t), 0UL, 0UL, 0UL );
    ctx->gossip_out->chunk = fd_dcache_compact_next( ctx->gossip_out->chunk, sizeof(fd_gravity_tpu_t), ctx->gossip_out->chunk0, ctx->gossip_out->wmark );
    ctx->tpu_applied_ip4  = ip4;
    ctx->tpu_applied_port = port;
    if( ip4 ) FD_LOG_NOTICE(( "advertising TPU " FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( ip4 ), port ));
    else      FD_LOG_NOTICE(( "advertising our own TPU" ));
    *charge_busy = 1;
  }

  /* The active relay's shred destinations, none without a session */
  ulong shred = has_session( ctx ) ? ctx->active<<32 | ctx->relay[ ctx->active ].shred_seq : ULONG_MAX;
  if( FD_UNLIKELY( shred!=ctx->shred_applied ) ) {
    fd_gravity_shred_dests_t * dests = fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk );
    if( has_session( ctx ) ) *dests = *ctx->relay[ ctx->active ].shred_dests;
    else                     memset( dests, 0, sizeof(fd_gravity_shred_dests_t) );
    fd_stem_publish( stem, ctx->shred_out->idx, 0UL, ctx->shred_out->chunk, sizeof(fd_gravity_shred_dests_t), 0UL, 0UL, 0UL );
    ctx->shred_out->chunk = fd_dcache_compact_next( ctx->shred_out->chunk, sizeof(fd_gravity_shred_dests_t), ctx->shred_out->chunk0, ctx->shred_out->wmark );
    ctx->shred_applied    = shred;
    *charge_busy = 1;
  }
  drop_if_requested( ctx );
}

static int
before_frag( fd_gravity_tile_t * ctx,
             ulong               in_idx,
             ulong               seq,
             ulong               sig ) {
  (void)seq;
  if( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) return sig!=REPLAY_SIG_SLOT_COMPLETED && sig!=REPLAY_SIG_RESET && sig!=REPLAY_SIG_BECAME_LEADER;
  if( ctx->in_kind[ in_idx ]==IN_KIND_EXECLE ) return !ctx->slot_relay && !ctx->drain_cnt;
  return 0;
}

static void
during_frag( fd_gravity_tile_t * ctx,
             ulong               in_idx,
             ulong               seq,
             ulong               sig,
             ulong               chunk,
             ulong               sz,
             ulong               ctl ) {
  (void)seq; (void)sig; (void)ctl;
  in_ctx_t const * in = ctx->in+in_idx;
  if( FD_UNLIKELY( chunk<in->chunk0 || chunk>in->wmark || sz>in->mtu || sz>sizeof(ctx->staged) ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, in->chunk0, in->wmark ));
  fd_memcpy( &ctx->staged, fd_chunk_to_laddr_const( in->mem, chunk ), sz );
}

static void
after_frag( fd_gravity_tile_t * ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)tsorig; (void)tspub; (void)stem;
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY:
    if(      sig==REPLAY_SIG_SLOT_COMPLETED && sz==sizeof(fd_replay_slot_completed_t) ) on_slot_completed( ctx, &ctx->staged.completed );
    else if( sig==REPLAY_SIG_RESET         && sz==sizeof(fd_poh_reset_t)          ) on_reset        ( ctx, &ctx->staged.reset         );
    else if( sig==REPLAY_SIG_BECAME_LEADER && sz==sizeof(fd_became_leader_t)      ) on_became_leader( ctx, &ctx->staged.became_leader );
    break;
  case IN_KIND_EXECLE:
    if( FD_LIKELY( sz>=sizeof(fd_microblock_trailer_t) ) ) on_execle( ctx, in_idx, sig, sz );
    break;
  case IN_KIND_PACK:
    if( FD_LIKELY( sz==sizeof(fd_gravity_pack_report_t) ) ) on_pack_report( ctx, &ctx->staged.report );
    break;
  case IN_KIND_RESOLV:
    if( FD_LIKELY( sz==sizeof(fd_gravity_resolv_fail_t) ) ) on_resolv_fail( ctx, &ctx->staged.resolv_fail );
    break;
  case IN_KIND_BUNDLE:
    if( FD_LIKELY( sz==sizeof(fd_bundle_builder_info_t) ) ) {
      fd_memcpy( ctx->block_builder, ctx->staged.builder.pubkey, 32UL );
      ctx->block_builder_commission = (uchar)ctx->staged.builder.commission;
    }
    break;
  }
  drop_if_requested( ctx );
}

/* A missed result, report or slot event can leave a node running
   forever or a slot unbuilt, so an overrun ends relay building for the
   rest of the window. */

static void
after_poll_overrun( fd_gravity_tile_t * ctx ) {
  FD_LOG_WARNING(( "gravity overrun, packing the rest of the window natively" ));
  ulong slot = fd_ulong_if( ctx->leader_slot!=ULONG_MAX, ctx->leader_slot, ctx->progress_slot );
  if( FD_LIKELY( slot!=ULONG_MAX ) ) ctx->native_until = window_end( slot );
  fallback( ctx );
}

/* Init ***************************************************************/

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  fd_gravity_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_gravity_tile_t) );
  fd_memcpy( ctx->identity, fd_keyload_load( tile->gravity.identity_key_path, /* pubkey only: */ 1 ), 32UL );

  if( FD_UNLIKELY( !fd_netdb_open_fds( ctx->netdb_fds ) ) ) FD_LOG_ERR(( "fd_netdb_open_fds failed" ));

  ctx->failsafe_fd = open( tile->gravity.failsafe_path, O_RDWR|O_CREAT|O_CLOEXEC, 0600 );
  if( FD_UNLIKELY( -1==ctx->failsafe_fd ) ) FD_LOG_ERR(( "open(`%s`) failed (%i-%s)", tile->gravity.failsafe_path, errno, fd_io_strerror( errno ) ));
  char c = 0;
  if( FD_UNLIKELY( -1==pread( ctx->failsafe_fd, &c, 1UL, 0L ) ) ) FD_LOG_ERR(( "read(`%s`) failed (%i-%s)", tile->gravity.failsafe_path, errno, fd_io_strerror( errno ) ));
  ctx->tripped = c=='1';
  if( FD_UNLIKELY( ctx->tripped ) ) FD_LOG_WARNING(( "failsafe is set, packing natively until the relay clears it" ));
}

static void
out_init( out_ctx_t *            out,
          fd_topo_t const *      topo,
          fd_topo_tile_t const * tile,
          char const *           name ) {
  out->idx = fd_topo_find_tile_out_link( topo, tile, name, 0UL );
  FD_TEST( out->idx!=ULONG_MAX );
  fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ out->idx ] ];
  out->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  out->chunk0 = fd_dcache_compact_chunk0( out->mem, link->dcache );
  out->wmark  = fd_dcache_compact_wmark ( out->mem, link->dcache, link->mtu );
  out->chunk  = out->chunk0;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gravity_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gravity_tile_t), sizeof(fd_gravity_tile_t)  );
  for( ulong i=0UL; i<relay_buf_cnt( tile ); i++ ) {
    ctx->relay[ i ].rx_buf = FD_SCRATCH_ALLOC_APPEND( l, 64UL, RX_BUF_SZ );
    ctx->relay[ i ].tx_buf = FD_SCRATCH_ALLOC_APPEND( l, 64UL, TX_BUF_SZ );
  }
  void * _adns    = FD_SCRATCH_ALLOC_APPEND( l, fd_adns_align(),  fd_adns_footprint( 4UL )  );
  ctx->graph      = FD_SCRATCH_ALLOC_APPEND( l, alignof(graph_t), GRAPH_MAX*sizeof(graph_t) );
  ctx->node_pool  = FD_SCRATCH_ALLOC_APPEND( l, alignof(node_t),  NODE_POOL*sizeof(node_t)  );
  ctx->row_pool   = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),    NODE_POOL*sizeof(uint)    );
  ctx->col_pool   = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),    EDGE_POOL*sizeof(uint)    );
  ctx->heap       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),   NODE_MAX*sizeof(ulong)    );
  ctx->topo_queue = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),   NODE_MAX*sizeof(ulong)    );
  ctx->topo_preds = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),    NODE_MAX*sizeof(uint)     );
  ctx->sig_map    = sig_map_join  ( sig_map_new  ( FD_SCRATCH_ALLOC_APPEND( l, sig_map_align(),   sig_map_footprint()   ) ) );
  ctx->tx_map     = order_map_join( order_map_new( FD_SCRATCH_ALLOC_APPEND( l, order_map_align(), order_map_footprint() ) ) );
  ctx->bundle_map = order_map_join( order_map_new( FD_SCRATCH_ALLOC_APPEND( l, order_map_align(), order_map_footprint() ) ) );
  FD_TEST( ctx->sig_map && ctx->tx_map && ctx->bundle_map );
  for( ulong i=0UL; i<FD_GRAVITY_WIRE_BUNDLE_TXN_MAX; i++ ) ctx->txn_t[ i ] = (fd_txn_t *)ctx->txn_t_mem[ i ];

  ctx->adns = fd_adns_join( fd_adns_new( _adns, 4UL, FD_WAKER_INNER_FD( tile->waker_client_idx ) ) );
  FD_TEST( ctx->adns );

  FD_TEST( tile->gravity.relay_cnt && tile->gravity.relay_cnt<=4UL );
  ctx->relay_cnt = tile->gravity.relay_cnt;
  for( ulong i=0UL; i<ctx->relay_cnt; i++ ) {
    relay_t * r = ctx->relay+i;
    fd_cstr_ncpy( r->host, tile->gravity.relay_host[ i ], sizeof(r->host) );
    r->port  = tile->gravity.relay_port[ i ];
    r->sock  = -1;
    r->state = STATE_DISCONNECTED;
  }
  ctx->active        = ULONG_MAX;
  ctx->lost          = ULONG_MAX;
  ctx->shred_applied = ULONG_MAX;
  /* As the connector reports its build: v{version}+{sha8}[.dirty] ({branch}/{sha}[-dirty]) */
  fd_cstr_printf( ctx->version, sizeof(ctx->version), NULL, "v%s+%.8s%s (%s/%s%s)", FD_GRAVITY_CONNECTOR_VERSION,
                  fd_commit_ref_cstr, FD_GRAVITY_DIRTY ? ".dirty" : "", FD_GRAVITY_BRANCH_CSTR,
                  fd_commit_ref_cstr, FD_GRAVITY_DIRTY ? "-dirty" : "" );
  ctx->execle_cnt          = tile->gravity.execle_cnt;
  ctx->jito_tip_weight_bps = tile->gravity.jito_tip_weight_bps;
  ctx->filter_ofac         = tile->gravity.filter_ofac;
  ctx->blacklisted_cnt     = tile->gravity.blacklisted_cnt;
  fd_memcpy( ctx->blacklisted, tile->gravity.blacklisted, sizeof(ctx->blacklisted) );

  ctx->tick_per_ns      = fd_tempo_tick_per_ns( NULL );
  ctx->progress_slot    = ULONG_MAX;
  ctx->next_leader_slot = ULONG_MAX;
  ctx->leader_slot      = ULONG_MAX;
  ctx->mode_slot        = ULONG_MAX;
  ctx->next_id          = FD_GRAVITY_ID_BIT;
  ctx->next_rx_poll     = LONG_MAX;

  ctx->waker_client_idx = tile->waker_client_idx;
  ctx->waker_fseq       = fd_fseq_join( fd_topo_obj_laddr( topo, tile->waker_fseq_obj_id ) );
  FD_TEST( ctx->waker_fseq );

  ulong mode_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "gbx_mode" );
  FD_TEST( mode_obj_id!=ULONG_MAX );
  ctx->mode = fd_fseq_join( fd_topo_obj_laddr( topo, mode_obj_id ) );
  FD_TEST( ctx->mode );
  fd_fseq_update( ctx->mode, 0UL );

  ulong relay_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "gbx_relay" );
  FD_TEST( relay_obj_id!=ULONG_MAX );
  ctx->relay_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, relay_obj_id ) );
  FD_TEST( ctx->relay_fseq );
  fd_fseq_update( ctx->relay_fseq, 0UL );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ulong wait_info_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "wait_info" );
  FD_TEST( wait_info_obj_id!=ULONG_MAX );
  ctx->wait_info = fd_wait_info_box_join( fd_topo_obj_laddr( topo, wait_info_obj_id ) );
  FD_TEST( ctx->wait_info );
  ctx->asleep    = 1;
  ctx->caught_up = 0;

  ulong polled = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( !tile->in_link_poll[ i ] ) continue;
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if(      !strcmp( link->name, "replay_slot"   ) ) ctx->in_kind[ polled ] = IN_KIND_REPLAY;
    else if( !strcmp( link->name, "execle_poh"    ) ) ctx->in_kind[ polled ] = IN_KIND_EXECLE;
    else if( !strcmp( link->name, "pack_gbx"      ) ) ctx->in_kind[ polled ] = IN_KIND_PACK;
    else if( !strcmp( link->name, "resolv_gbx"    ) ) ctx->in_kind[ polled ] = IN_KIND_RESOLV;
    else if( !strcmp( link->name, "bundle_gbx"    ) ) ctx->in_kind[ polled ] = IN_KIND_BUNDLE;
    else FD_LOG_ERR(( "gravity tile has unexpected input link %s", link->name ));
    ctx->in_execle[ polled ] = link->kind_id;
    ctx->in[ polled ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in[ polled ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ polled ].mem, link->dcache );
    ctx->in[ polled ].wmark  = fd_dcache_compact_wmark ( ctx->in[ polled ].mem, link->dcache, link->mtu );
    ctx->in[ polled ].mtu    = link->mtu;
    polled++;
  }

  out_init( ctx->resolv_out, topo, tile, "gbx_resolv" );
  out_init( ctx->pack_out,   topo, tile, "gbx_pack"   );
  out_init( ctx->gossip_out, topo, tile, "gbx_gossip" );
  out_init( ctx->shred_out,  topo, tile, "gbx_shred"  );

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_gbx", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "gbx_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX && sign_out_idx!=ULONG_MAX );
  fd_topo_link_t const * sign_in  = &topo->links[ tile->in_link_id [ sign_in_idx  ] ];
  fd_topo_link_t const * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
  fd_sleep_t * sleep = topo->sleep_obj_id!=ULONG_MAX ? fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) ) : NULL;
  FD_TEST( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
      sign_out->mcache, sign_out->dcache, sign_in->mcache, sign_in->dcache,
      sign_out->mtu, sign_in->mtu, sleep, sign_out->id, fd_topo_find_link_consumer( topo, sign_out ) ) ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top>(ulong)scratch+scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top-(ulong)scratch-scratch_footprint( tile ), scratch_top, (ulong)scratch+scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_gravity_tile_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_gravity_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->failsafe_fd,
                                               (uint)ctx->netdb_fds->etc_hosts, (uint)ctx->netdb_fds->etc_resolv_conf,
                                               (uint)FD_WAKER_INNER_FD( tile->waker_client_idx ), (uint)FD_WAKER_OUTER_FD );
  return sock_filter_policy_fd_gravity_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_gravity_tile_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<7UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  out_fds[ out_cnt++ ] = FD_WAKER_OUTER_FD;
  out_fds[ out_cnt++ ] = FD_WAKER_INNER_FD( tile->waker_client_idx );
  out_fds[ out_cnt++ ] = ctx->failsafe_fd;
  if( FD_LIKELY( ctx->netdb_fds->etc_hosts>=0 ) ) out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_hosts;
  out_fds[ out_cnt++ ] = ctx->netdb_fds->etc_resolv_conf;
  return out_cnt;
}

#define STEM_CALLBACK_CONTEXT_TYPE        fd_gravity_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_gravity_tile_t)
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_NEXT_DEADLINE       next_deadline
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_AFTER_POLL_OVERRUN  after_poll_overrun

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_gravity = {
  .name                     = "gbx",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .rlimit_file_cnt          = 64,
  .keep_host_networking     = 1,
  .allow_connect            = 1,
};
