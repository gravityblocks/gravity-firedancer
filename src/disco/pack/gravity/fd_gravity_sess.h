#ifndef HEADER_fd_src_disco_pack_gravity_fd_gravity_sess_h
#define HEADER_fd_src_disco_pack_gravity_fd_gravity_sess_h

/* fd_gravity_sess is a non-blocking TCP client session to a Gravity
   relay.  It owns the socket, the bootstrap/authentication exchange,
   frame (de)serialization buffers, timers and reconnects.  It never
   blocks and never calls anything but socket, connect, setsockopt,
   recvfrom, sendto and close, so it can run inside a tile's run loop.

   The identity signature is produced by the caller (e.g. via a
   keyguard client): when fd_gravity_sess_need_sign returns non-zero,
   the caller signs fd_gravity_sess_auth_msg with the identity key and
   passes the result to fd_gravity_sess_signed.

   Lifecycle:

     IDLE -> CONNECTING -> HELLO -> SIGN -> ACCEPT -> READY
       ^                                                |
       +--------------- reset (any error) --------------+

   Once READY, the caller sends messages with tx_prepare/tx_publish and
   receives relay messages with next_frame.  All times are wallclock
   nanoseconds provided by the caller. */

#include "fd_gravity_wire.h"

#define FD_GRAVITY_SESS_STATE_IDLE       (0)
#define FD_GRAVITY_SESS_STATE_CONNECTING (1)
#define FD_GRAVITY_SESS_STATE_HELLO      (2)
#define FD_GRAVITY_SESS_STATE_SIGN       (3)
#define FD_GRAVITY_SESS_STATE_ACCEPT     (4)
#define FD_GRAVITY_SESS_STATE_READY      (5)

#define FD_GRAVITY_SESS_RELAY_MAX        (4UL)

#define FD_GRAVITY_SESS_RECONNECT_NS     (1000000000L) /* 1 s */
#define FD_GRAVITY_SESS_CONNECT_NS       (3000000000L) /* 3 s */
#define FD_GRAVITY_SESS_BOOTSTRAP_NS    (10000000000L) /* 10 s per step */
#define FD_GRAVITY_SESS_RX_SILENCE_NS    (3000000000L) /* relay pings every 1 s */
#define FD_GRAVITY_SESS_REJECT_BACKOFF_NS (10000000000L)

/* Reset reasons, for metrics and logging */

#define FD_GRAVITY_SESS_RESET_CONNECT    (0)
#define FD_GRAVITY_SESS_RESET_TIMEOUT    (1)
#define FD_GRAVITY_SESS_RESET_PEER_CLOSE (2)
#define FD_GRAVITY_SESS_RESET_IO         (3)
#define FD_GRAVITY_SESS_RESET_DECODE     (4)
#define FD_GRAVITY_SESS_RESET_REJECTED   (5)
#define FD_GRAVITY_SESS_RESET_TX_FULL    (6)
#define FD_GRAVITY_SESS_RESET_CALLER     (7)
#define FD_GRAVITY_SESS_RESET_CNT        (8)

struct fd_gravity_sess {
  int    fd;
  int    state;

  ulong  relay_cnt;
  uint   relay_ip4 [ FD_GRAVITY_SESS_RELAY_MAX ]; /* network byte order */
  ushort relay_port[ FD_GRAVITY_SESS_RELAY_MAX ]; /* host byte order */
  ulong  relay_idx;
  ulong  connect_fail_cnt;
  int    identity_switched; /* set_identity called since the last READY */

  uchar  identity [ 32 ];
  uchar  auth_msg [ FD_GRAVITY_AUTH_MSG_SZ ];

  /* Pre-encoded HandshakeV2 payload, sent right after the AuthProof. */
  ulong  handshake_sz;
  uchar  handshake[ 1024 ];

  long   deadline;     /* state timeout or reconnect time */
  long   last_rx;      /* last time any bytes were received */
  ulong  session_cnt;  /* number of sessions that reached READY */
  int    session_new;  /* set when READY is reached, cleared by caller */

  ulong  rx_max;
  ulong  rx_lo;
  ulong  rx_hi;
  uchar * rx;

  ulong  tx_max;
  ulong  tx_lo;
  ulong  tx_hi;
  uchar * tx;

  ulong  reset_cnt[ FD_GRAVITY_SESS_RESET_CNT ];
  ulong  rx_bytes;
  ulong  tx_bytes;
  ulong  rx_frames;
  ulong  tx_frames;
};

typedef struct fd_gravity_sess fd_gravity_sess_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_gravity_sess_align( void ) {
  return 64UL;
}

FD_FN_CONST static inline ulong
fd_gravity_sess_footprint( ulong rx_max,
                           ulong tx_max ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gravity_sess_t), sizeof(fd_gravity_sess_t) );
  l = FD_LAYOUT_APPEND( l, 64UL,                       rx_max );
  l = FD_LAYOUT_APPEND( l, 64UL,                       tx_max );
  return FD_LAYOUT_FINI( l, fd_gravity_sess_align() );
}

/* fd_gravity_sess_new formats mem (aligned, footprint bytes) as a
   session.  rx_max bounds the largest relay frame that can be received
   (larger frames reset the session).  identity is the validator
   identity public key.  relays are relay_cnt IPv4 addresses (network
   byte order) and ports.  handshake is the HandshakeV2 to send.  The
   session starts IDLE with an immediate connect deadline.  Returns NULL
   on bad arguments. */

fd_gravity_sess_t *
fd_gravity_sess_new( void *                         mem,
                     ulong                          rx_max,
                     ulong                          tx_max,
                     uchar const                    identity[ static 32 ],
                     ulong                          relay_cnt,
                     uint const *                   relay_ip4,
                     ushort const *                 relay_port,
                     fd_gravity_handshake_t const * handshake );

/* fd_gravity_sess_set_identity changes the identity (e.g. on a
   validator identity switch) and resets the session. */

void
fd_gravity_sess_set_identity( fd_gravity_sess_t * sess,
                              uchar const         identity[ static 32 ],
                              long                now );

/* fd_gravity_sess_poll advances the session: connects, reads available
   bytes, handles bootstrap frames, writes pending bytes and checks
   timers.  Does at most a bounded amount of work.  Returns 1 if any
   work was done, 0 otherwise. */

int
fd_gravity_sess_poll( fd_gravity_sess_t * sess,
                      long                now );

/* fd_gravity_sess_next_frame returns a pointer to the payload of the
   next complete relay session frame (setting *sz), or NULL if there is
   none.  Keepalives are skipped.  The pointer is valid until the next
   call to fd_gravity_sess_poll or fd_gravity_sess_reset.  Only returns
   frames when READY.  A frame larger than rx_max, or a bootstrap frame
   (e.g. a late Rejected{Timeout}), resets the session and returns
   NULL. */

uchar const *
fd_gravity_sess_next_frame( fd_gravity_sess_t * sess,
                            ulong *             sz );

/* Signing hand-off, see above. */

static inline int
fd_gravity_sess_need_sign( fd_gravity_sess_t const * sess ) {
  return sess->state==FD_GRAVITY_SESS_STATE_SIGN;
}

static inline uchar const *
fd_gravity_sess_auth_msg( fd_gravity_sess_t const * sess ) {
  return sess->auth_msg;
}

void
fd_gravity_sess_signed( fd_gravity_sess_t * sess,
                        uchar const         signature[ static 64 ],
                        long                now );

static inline int
fd_gravity_sess_is_ready( fd_gravity_sess_t const * sess ) {
  return sess->state==FD_GRAVITY_SESS_STATE_READY;
}

/* fd_gravity_sess_tx_prepare returns a pointer to a buffer of at least
   max_sz bytes where the caller can encode one message payload, or NULL
   if the session is not READY or the transmit buffer doesn't have room.
   fd_gravity_sess_tx_publish then frames the sz (<=max_sz) bytes
   written.  sz==0 cancels. */

uchar *
fd_gravity_sess_tx_prepare( fd_gravity_sess_t * sess,
                            ulong               max_sz );

void
fd_gravity_sess_tx_publish( fd_gravity_sess_t * sess,
                            ulong               sz,
                            long                now );

/* fd_gravity_sess_tx_free returns the number of free bytes in the
   transmit buffer (after compaction). */

static inline ulong
fd_gravity_sess_tx_free( fd_gravity_sess_t const * sess ) {
  return sess->tx_max - (sess->tx_hi-sess->tx_lo);
}

/* fd_gravity_sess_reset closes the socket (if any) and schedules a
   reconnect.  reason is one of FD_GRAVITY_SESS_RESET_*. */

void
fd_gravity_sess_reset( fd_gravity_sess_t * sess,
                       int                 reason,
                       long                now );

/* fd_gravity_sess_fd returns the socket file descriptor or -1. */

static inline int
fd_gravity_sess_fd( fd_gravity_sess_t const * sess ) {
  return sess->fd;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_pack_gravity_fd_gravity_sess_h */
