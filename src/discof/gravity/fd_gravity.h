#ifndef HEADER_fd_src_discof_gravity_fd_gravity_h
#define HEADER_fd_src_discof_gravity_fd_gravity_h

/* Messages the gravity tile exchanges with resolv, pack and gossip.

   The gravity tile builds leader blocks from an external block building
   relay.  Each node of a relay graph is sent through resolv to pack as
   one bundle (fd_txn_m_t block_engine.bundle_id is the tile's running
   node counter, with FD_GRAVITY_ID_BIT set to tell it from a block
   engine bundle).  The tile sends pack each graph's dependencies, and
   pack walks the graph itself: it runs a node once its predecessors'
   microblocks completed, in the same loop that frees their account
   locks.  A loose transaction node travels as a bundle of one, and
   pack drops the bundle flag when it schedules it, so it has no revert
   protection.

   The tile sets the gravity_mode fseq to 1 while relay building is
   allowed.  Pack decides at the first slot it leads in each 4 slot
   window: the window is relay-built if the fseq is 1 then, and native
   otherwise.  If the fseq drops to 0 during a relay-built window, pack
   packs the rest of the window natively.  Pack reports its decision
   for each slot.

   The tile sets the gravity_relay fseq to 1 while it holds a relay
   session.  The bundle tile stays disconnected from the block engine
   meanwhile, so only one of the two subscribes to it. */

#include "../../disco/fd_disco_base.h"

#define FD_GRAVITY_ID_BIT (1UL<<62)

/* gravity_pack: the frag sig is one of the FD_GRAVITY_PACK_SIG_*
   values below.

   GRAPH starts a graph, with a fd_gravity_pack_graph_t payload.  Its
   node i has bundle_id base_id+i.  DAG frags follow, whose payloads
   concatenate to node_cnt+node_cnt+1+edge_cnt uints: a word per node,
   depth<<1 with the low bit set for a loose transaction node, then the
   graph's successor lists in CSR form, row offsets then column
   indices.  Graphs run one at a time, in order.

   SKIP: an array of ulong bundle_ids of nodes of a graph already sent
   that will never reach pack.  They complete as if they ran.

   CLEAR: no payload.  Pack drops every graph.

   Each node pack loads ends in a RUN report, followed by its
   microblock, or in a SCHED_FAIL report, unless a CLEAR or the end of
   pack's slot drops it first. */

#define FD_GRAVITY_PACK_SIG_GRAPH (0UL)
#define FD_GRAVITY_PACK_SIG_DAG   (1UL)
#define FD_GRAVITY_PACK_SIG_SKIP  (2UL)
#define FD_GRAVITY_PACK_SIG_CLEAR (3UL)

#define FD_GRAVITY_PACK_MTU (16384UL)

struct fd_gravity_pack_graph {
  ulong slot;
  ulong base_id;
  uint  node_cnt;
  uint  edge_cnt;
};
typedef struct fd_gravity_pack_graph fd_gravity_pack_graph_t;

/* pack_gravity: one fd_gravity_pack_report_t per frag. */

#define FD_GRAVITY_REPORT_ADMITTED   (0) /* node stored in pack */
#define FD_GRAVITY_REPORT_REJECTED   (1) /* node not stored, code is an FD_PACK_INSERT_* or FD_PACK_INSERT_REJECT_* value */
#define FD_GRAVITY_REPORT_SCHED_FAIL (2) /* node will not run, code is an FD_PACK_SCHEDULE_BUNDLE_* value */
#define FD_GRAVITY_REPORT_MODE       (3) /* pack leads slot, code is 1 if it is relay-built */
#define FD_GRAVITY_REPORT_RUN        (4) /* node sent to execle tile code at wallclock ts */

struct fd_gravity_pack_report {
  ulong bundle_id;
  ulong slot;
  long  ts;
  int   kind;
  int   code;
};
typedef struct fd_gravity_pack_report fd_gravity_pack_report_t;

/* resolv_gravity: one fd_gravity_resolv_fail_t per node resolv drops.
   err is an FD_RUNTIME_TXN_ERR_* value, or FD_GRAVITY_ERR_NO_BANK. */

#define FD_GRAVITY_ERR_NO_BANK (1)

struct fd_gravity_resolv_fail {
  ulong bundle_id;
  uchar signature[ 64 ];
  int   err;
};
typedef struct fd_gravity_resolv_fail fd_gravity_resolv_fail_t;

/* gravity_gossip: the TPU address to advertise.  ip4==0 restores the
   validator's own TPU sockets.  Otherwise the TPU and TPU forwards
   QUIC sockets point at ip4:port. */

struct fd_gravity_tpu {
  uint   ip4;  /* network byte order */
  ushort port; /* host byte order */
};
typedef struct fd_gravity_tpu fd_gravity_tpu_t;

/* gravity_shred: the shred destinations the relay asks for, which shred
   tiles add to their configured ones.  leader gets the shreds of our
   leader slots, retransmit the shreds we retransmit for other leaders.
   Each frag replaces the previous lists. */

#define FD_GRAVITY_SHRED_DEST_MAX (32UL)

struct fd_gravity_shred_dest {
  uint   ip4;  /* network byte order */
  ushort port; /* host byte order */
};
typedef struct fd_gravity_shred_dest fd_gravity_shred_dest_t;

struct fd_gravity_shred_dests {
  ulong                   leader_cnt;
  ulong                   retransmit_cnt;
  fd_gravity_shred_dest_t leader    [ FD_GRAVITY_SHRED_DEST_MAX ];
  fd_gravity_shred_dest_t retransmit[ FD_GRAVITY_SHRED_DEST_MAX ];
};
typedef struct fd_gravity_shred_dests fd_gravity_shred_dests_t;

#endif /* HEADER_fd_src_discof_gravity_fd_gravity_h */
