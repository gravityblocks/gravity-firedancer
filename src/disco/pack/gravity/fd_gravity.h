#ifndef HEADER_fd_src_disco_pack_gravity_fd_gravity_h
#define HEADER_fd_src_disco_pack_gravity_fd_gravity_h

/* fd_gravity is the in-pack client for the Gravity block building
   relay.  It plays the role gravity-connector plays for Agave:

   - keeps a TCP session to the relay (fd_gravity_sess);
   - reports slot progress (Progress) from replay events;
   - forwards every transaction pack receives to the relay
     (Transaction) and retains a copy, because the relay refers to
     forwarded transactions by signature prefix only;
   - turns the relay's mini-block graphs into a "lane" of fd_pack
     bundles, one per graph node, inserted in node index order.  The
     relay only emits forward edges, so pack's bundle FIFO plus its
     account locks executes the nodes in an order equivalent to the
     graph;
   - reports one ExecutionResult per node.

   Leader windows run in one of two modes, decided at the first leader
   slot of the window:

   GRAVITY: pack schedules only lane bundles (and the tip crank's
            initializer bundle, which runs first).  Native transactions
            stay in pack (and were forwarded to the relay).
   NATIVE:  upstream pack behaviour.

   A window is GRAVITY if the session has been READY (and sending
   Progress) for warmup_ns at its first slot.  It stays GRAVITY to its
   end, even if nothing from the relay can be scheduled, unless the
   session drops (the rest of the window is then NATIVE).  As in
   gravity-connector, a leadership (adjacent windows) whose last GRAVITY
   slot with forwarded orders scheduled nothing trips a failsafe: later
   windows are NATIVE and no Progress is sent until the relay sends
   DeleteFailsafe.  Unlike the connector, there is no failsafe file (a
   restart clears it) and nothing exits.

   Jito bundles (bundle tile enabled) are retained and, unless the
   current window is NATIVE (or there is no session), forwarded to the
   relay as BundleV2 under Jito's bundle id instead of being inserted
   into pack, so they only execute as part of relay mini-blocks.  They
   go to pack natively otherwise, and are moved between pack and the
   relay as windows change mode.

   Builder supplied transaction bytes are trusted (not signature
   verified), as with Agave and gravity-connector, but parsed.  Builder
   transactions using address lookup tables are not supported yet and
   are rejected with ALT_NOT_FOUND (forwarded transactions may use
   them: pack received those already resolved).

   The tip crank is pack's (bundle tile): gravity only tells pack's
   initializer bundle state machine whether to wait for it.  The relay's
   PreviousTipReceiver is not needed (pack reads the tip payment config
   from its bank), and ReadyForTips is not sent (the relay ignores it). */

#include "fd_gravity_sess.h"
#include "../fd_pack.h"
#include "../../fd_txn_p.h"

#define FD_GRAVITY_MODE_NATIVE  (0)
#define FD_GRAVITY_MODE_GRAVITY (1)

#define FD_GRAVITY_INFLIGHT_CNT (8192UL) /* power of 2 */
#define FD_GRAVITY_BUNDLE_META_MAX (64UL) /* max pack bundle meta size */

struct fd_gravity_cfg {
  uchar  identity[ 32 ];
  ulong  relay_cnt;
  uint   relay_ip4 [ FD_GRAVITY_SESS_RELAY_MAX ];
  ushort relay_port[ FD_GRAVITY_SESS_RELAY_MAX ];

  ulong  rx_max;        /* receive buffer bytes */
  ulong  tx_max;        /* transmit buffer bytes */
  ulong  retention_sz;  /* retention ring bytes */
  ulong  node_max;      /* max lane nodes in flight, <=UINT_MAX-1 */
  ulong  order_max;     /* max builder orders per graph */

  uchar  num_threads;
  ushort jito_tip_weight_bps;
  int    filter_ofac;
  char   version[ 32 ];
  long   warmup_ns;      /* session age (Progress sent) a window needs to be GRAVITY */

  ulong  bundle_meta_sz; /* pack bundle meta size, at most FD_GRAVITY_BUNDLE_META_MAX */
  char   bundle_uri[ 65 ]; /* source_uri of forwarded Jito bundles, at most 64 ASCII bytes */

  ulong  blacklist_cnt; /* accounts builders must not use, at most FD_GRAVITY_BLACKLIST_MAX */
  uchar  blacklist[ FD_GRAVITY_BLACKLIST_MAX ][ 32 ];
};

typedef struct fd_gravity_cfg fd_gravity_cfg_t;

struct fd_gravity_metrics {
  ulong graphs;
  ulong graphs_rejected;
  ulong nodes_inserted;
  ulong nodes_rejected;
  ulong nodes_unknown;
  ulong nodes_alt;
  ulong results_included;
  ulong results_not_included;
  ulong results_synthetic;
  ulong txn_forwarded;
  ulong txn_fwd_dropped;
  ulong retention_hit;
  ulong retention_miss;
  ulong windows_gravity;
  ulong windows_native;
  ulong slots_missed;
  ulong failsafe_trips;
  ulong fallback_session;
  ulong progress_sent;
  ulong jito_rx;          /* Jito bundles received */
  ulong jito_dup;         /* ... already retained */
  ulong jito_native;      /* ... inserted into pack natively on arrival */
  ulong jito_fwd;         /* BundleV2 sent (including re-forwards) */
  ulong jito_fwd_dropped;
  ulong jito_pulled;      /* native bundle transactions removed from pack at GRAVITY slot starts */
  ulong jito_reinserted;  /* forwarded bundles put back in pack at NATIVE transitions */
  ulong jito_hit;         /* graph bundle nodes resolved from retained Jito bundles */
};

typedef struct fd_gravity_metrics fd_gravity_metrics_t;

struct fd_gravity;
typedef struct fd_gravity fd_gravity_t;

FD_PROTOTYPES_BEGIN

/* fd_gravity_{align,footprint} return the alignment and footprint of
   the memory region for a client with the given configuration.
   fd_gravity_footprint returns 0 if cfg is invalid. */

ulong
fd_gravity_align( void );

ulong
fd_gravity_footprint( fd_gravity_cfg_t const * cfg );

/* fd_gravity_new formats mem (fd_gravity_footprint( cfg ) bytes,
   aligned to fd_gravity_align()) as a client and returns it, or NULL
   if cfg is invalid.  The client connects on the first poll. */

fd_gravity_t *
fd_gravity_new( void *                   mem,
                fd_gravity_cfg_t const * cfg );

/* fd_gravity_sess returns the client's relay session.
   fd_gravity_metrics returns its counters.  fd_gravity_failsafe
   returns 1 if the failsafe is tripped. */

fd_gravity_sess_t *
fd_gravity_sess( fd_gravity_t * g );

fd_gravity_metrics_t const *
fd_gravity_metrics( fd_gravity_t const * g );

int
fd_gravity_failsafe( fd_gravity_t const * g );

/* fd_gravity_poll drives the session and handles relay messages.
   Graphs are inserted into pack as they arrive, a bounded number of
   nodes per call.  Call once per run loop iteration.  Returns 1 if any
   work was done.  If the session needs a signature, the caller signs
   fd_gravity_sess_auth_msg and calls fd_gravity_sess_signed (see
   fd_gravity_sess.h). */

int
fd_gravity_poll( fd_gravity_t * g,
                 fd_pack_t *    pack,
                 void const *   bundle_meta,
                 long           now );

/* fd_gravity_handle_frame handles one relay session frame payload as
   if it had been received on the session, all at once.  For tests. */

void
fd_gravity_handle_frame( fd_gravity_t * g,
                         fd_pack_t *    pack,
                         void const *   bundle_meta,
                         uchar const *  payload,
                         ulong          sz,
                         long           now );

/* Replay events.

   fd_gravity_became_leader starts a leader slot, deciding the mode of
   its window at the window's first slot, and returns the mode for the
   slot.  crank is 1 if pack cranks the tip accounts with an
   initializer bundle before other bundles in this slot (bundle tile
   enabled), in which case the initializer bundle state is left to the
   crank.

   fd_gravity_slot_completed reports a completed slot (replay
   SLOT_COMPLETED).  The Progress for the next slot is sent once the
   next leader slot is known. */

int
fd_gravity_became_leader( fd_gravity_t * g,
                          fd_pack_t *    pack,
                          ulong          slot,
                          long           slot_start_ns,
                          long           slot_end_ns,
                          ulong          block_height,
                          int            crank,
                          long           now );

void
fd_gravity_slot_completed( fd_gravity_t * g,
                           ulong          slot,
                           uchar const    block_hash[ static 32 ],
                           long           now );

/* fd_gravity_next_leader reports the next slot this validator leads
   (ULONG_MAX if unknown), published by replay right after each slot
   completion.  The Progress for a completed slot is sent from here. */

void
fd_gravity_next_leader( fd_gravity_t * g,
                        ulong          next_leader_slot,
                        long           now );

/* fd_gravity_reset reports a replay RESET (published when becoming
   leader): the completed slot, its blockhash and the next leader
   slot. */

void
fd_gravity_reset( fd_gravity_t * g,
                  ulong          completed_slot,
                  uchar const    completed_blockhash[ static 32 ],
                  ulong          next_leader_slot,
                  long           now );

/* fd_gravity_slot_end is called when pack stops packing the current
   leader slot (for any reason).  Removes undispatched lane nodes from
   pack and reports them as SLOT_ENDED.  abandoned is 1 if the slot was
   cut short by a consensus reset or a switch to another leader slot (it
   then doesn't count for the failsafe). */

void
fd_gravity_slot_end( fd_gravity_t * g,
                     fd_pack_t *    pack,
                     int            abandoned,
                     long           now );

/* fd_gravity_check_fallback is called every iteration while leader.
   Falls back to NATIVE for the rest of the window if the session was
   lost. */

void
fd_gravity_check_fallback( fd_gravity_t * g,
                           fd_pack_t *    pack,
                           long           now );

/* fd_gravity_mode returns the mode of the current leader slot. */

int
fd_gravity_mode( fd_gravity_t const * g );

/* fd_gravity_on_txn retains and forwards a transaction received from
   resolv (non-bundle).  txn must be fully populated (payload, txn_t,
   alt accounts).  blockhash_height is the reference block height resolv
   computed, used to put the transaction back in pack natively if a lane
   node using it is purged. */

void
fd_gravity_on_txn( fd_gravity_t *     g,
                   fd_txn_e_t const * txn,
                   ulong              blockhash_height,
                   long               now );

/* fd_gravity_on_bundle is called with a complete Jito bundle from the
   bundle tile: bundle[0,txn_cnt) as passed to fd_pack_insert_bundle_fini,
   with the bundle's blockhash height and pack bundle meta.  Retains it
   and, while bundles go to the relay, forwards it.  Returns 1 if gravity
   took the bundle (the caller cancels the pack insert), 0 if the caller
   inserts it into pack natively. */

int
fd_gravity_on_bundle( fd_gravity_t *       g,
                      fd_txn_e_t * const * bundle,
                      ulong                txn_cnt,
                      ulong                blockhash_height,
                      void const *         meta,
                      long                 now );

/* fd_gravity_on_schedule is called when pack scheduled a bundle
   microblock (txn_cnt transactions in out, in execution order) that
   will be published with the given pack_idx.  If it is a lane node,
   records it as dispatched, and for single transaction nodes clears the
   bundle flag on out so it executes (and pays fees) like a normal
   transaction.  Also deletes native copies of the transactions from
   pack.  For other bundles (Jito bundles packed natively), records
   that the retained copy executed. */

void
fd_gravity_on_schedule( fd_gravity_t * g,
                        fd_pack_t *    pack,
                        fd_txn_e_t *   out,
                        ulong          txn_cnt,
                        uint           pack_idx,
                        long           now );

/* fd_gravity_is_inflight returns 1 if pack_idx belongs to a dispatched
   lane node (cheap filter for execle frags).  A node of txn_cnt
   transactions scheduled with pack_idx p owns [p,p+txn_cnt). */

int
fd_gravity_is_inflight( fd_gravity_t const * g,
                        uint                 pack_idx );

/* fd_gravity_on_executed records the execution outcome of txn_cnt
   transactions starting at pack_idx, from one execle frag.  flags and
   cus are per transaction.  The execle tiles publish a microblock in
   one frag but a bundle one transaction per frag (with pack_idx+i), so
   the node's ExecutionResult is sent once all its transactions are
   in. */

void
fd_gravity_on_executed( fd_gravity_t * g,
                        ulong          slot,
                        uint           pack_idx,
                        ulong          txn_cnt,
                        uint const *   flags,
                        uint const *   cus,
                        uchar          worker,
                        long           now );

/* fd_gravity_set_identity changes the identity and resets the
   session. */

void
fd_gravity_set_identity( fd_gravity_t * g,
                         uchar const    identity[ static 32 ],
                         long           now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_pack_gravity_fd_gravity_h */
