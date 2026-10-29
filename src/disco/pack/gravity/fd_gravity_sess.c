#include "fd_gravity_sess.h"
#include "../../../util/fd_util.h"
#include "../../../util/net/fd_ip4.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* Bound the work done per poll so the caller's loop stays responsive. */
#define RX_BYTES_PER_POLL (256UL<<10)

static char const * const reset_str[ FD_GRAVITY_SESS_RESET_CNT ] = {
  "connect", "timeout", "peer_close", "io", "decode", "rejected", "tx_full", "caller"
};

fd_gravity_sess_t *
fd_gravity_sess_new( void *                         mem,
                     ulong                          rx_max,
                     ulong                          tx_max,
                     uchar const                    identity[ static 32 ],
                     ulong                          relay_cnt,
                     uint const *                   relay_ip4,
                     ushort const *                 relay_port,
                     fd_gravity_handshake_t const * handshake ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_gravity_sess_align() ) ) ) return NULL;
  if( FD_UNLIKELY( !relay_cnt || relay_cnt>FD_GRAVITY_SESS_RELAY_MAX ) ) return NULL;
  if( FD_UNLIKELY( rx_max<4096UL || tx_max<4096UL ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_gravity_sess_t * sess = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gravity_sess_t), sizeof(fd_gravity_sess_t) );
  uchar *             rx   = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                       rx_max );
  uchar *             tx   = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                       tx_max );
  FD_SCRATCH_ALLOC_FINI( l, fd_gravity_sess_align() );

  memset( sess, 0, sizeof(fd_gravity_sess_t) );
  sess->fd        = -1;
  sess->state     = FD_GRAVITY_SESS_STATE_IDLE;
  sess->relay_cnt = relay_cnt;
  for( ulong i=0UL; i<relay_cnt; i++ ) {
    sess->relay_ip4 [ i ] = relay_ip4 [ i ];
    sess->relay_port[ i ] = relay_port[ i ];
  }
  fd_memcpy( sess->identity, identity, 32UL );

  fd_gravity_handshake_t hs = *handshake;
  fd_memcpy( hs.identity, identity, 32UL );
  sess->handshake_sz = fd_gravity_encode_handshake_v2( sess->handshake, sizeof(sess->handshake), &hs );
  if( FD_UNLIKELY( !sess->handshake_sz ) ) return NULL;

  sess->deadline = 0L; /* connect right away */
  sess->rx_max   = rx_max;
  sess->rx       = rx;
  sess->tx_max   = tx_max;
  sess->tx       = tx;
  return sess;
}

void
fd_gravity_sess_reset( fd_gravity_sess_t * sess,
                       int                 reason,
                       long                now ) {
  if( FD_LIKELY( sess->fd>=0 ) ) {
    if( FD_UNLIKELY( close( sess->fd ) ) ) FD_LOG_WARNING(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    sess->fd = -1;
  }
  if( sess->state!=FD_GRAVITY_SESS_STATE_IDLE ) {
    FD_LOG_NOTICE(( "gravity: session reset (%s) in state %i", reset_str[ reason ], sess->state ));
  }
  sess->reset_cnt[ reason ]++;

  /* Right after an identity switch, the sign tile may still hold the old
     key when the auth message is signed (it switches concurrently), and
     the relay rejects the proof.  Retry soon rather than back off. */
  int switch_reject = reason==FD_GRAVITY_SESS_RESET_REJECTED && sess->identity_switched;

  /* Rotate relays after 3 consecutive attempts that failed to reach
     READY (connect failure, bootstrap timeout, rejection, malformed
     bootstrap frame).  The count is cleared when a session reaches
     READY.  Caller requested resets (e.g. identity change) are not
     the relay's fault. */
  if( reason!=FD_GRAVITY_SESS_RESET_CALLER && !switch_reject && sess->state<FD_GRAVITY_SESS_STATE_READY ) {
    if( ++sess->connect_fail_cnt>=3UL ) {
      sess->connect_fail_cnt = 0UL;
      sess->relay_idx = (sess->relay_idx+1UL) % sess->relay_cnt;
    }
  }

  long backoff = reason==FD_GRAVITY_SESS_RESET_REJECTED && !switch_reject ? FD_GRAVITY_SESS_REJECT_BACKOFF_NS : FD_GRAVITY_SESS_RECONNECT_NS;
  sess->state    = FD_GRAVITY_SESS_STATE_IDLE;
  sess->deadline = now + backoff;
  sess->rx_lo    = 0UL;
  sess->rx_hi    = 0UL;
  sess->tx_lo    = 0UL;
  sess->tx_hi    = 0UL;
}

void
fd_gravity_sess_set_identity( fd_gravity_sess_t * sess,
                              uchar const         identity[ static 32 ],
                              long                now ) {
  fd_memcpy( sess->identity, identity, 32UL );
  fd_memcpy( sess->handshake+4UL, identity, 32UL ); /* HandshakeV2 identity follows the tag */
  fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_CALLER, now );
  sess->deadline          = now;
  sess->identity_switched = 1;
}

/* tx_raw appends a frame regardless of the session state (used during
   the bootstrap).  Returns 0 on success, -1 if out of space. */

static int
tx_raw( fd_gravity_sess_t * sess,
        uchar const *       payload,
        ulong               sz,
        long                now ) {
  if( FD_UNLIKELY( sess->tx_lo==sess->tx_hi ) ) { sess->tx_lo = 0UL; sess->tx_hi = 0UL; }
  if( FD_UNLIKELY( sess->tx_max-sess->tx_hi<FD_GRAVITY_FRAME_HDR_SZ+sz ) ) return -1;
  uchar * p = sess->tx+sess->tx_hi;
  fd_gravity_frame_hdr_write( p, sz, (ulong)now );
  fd_memcpy( p+FD_GRAVITY_FRAME_HDR_SZ, payload, sz );
  sess->tx_hi += FD_GRAVITY_FRAME_HDR_SZ+sz;
  sess->tx_frames++;
  return 0;
}

uchar *
fd_gravity_sess_tx_prepare( fd_gravity_sess_t * sess,
                            ulong               max_sz ) {
  if( FD_UNLIKELY( sess->state!=FD_GRAVITY_SESS_STATE_READY ) ) return NULL;
  if( FD_UNLIKELY( sess->tx_lo==sess->tx_hi ) ) { sess->tx_lo = 0UL; sess->tx_hi = 0UL; }
  ulong need = FD_GRAVITY_FRAME_HDR_SZ+max_sz;
  if( FD_UNLIKELY( sess->tx_max-sess->tx_hi<need ) ) {
    /* Compact */
    ulong used = sess->tx_hi-sess->tx_lo;
    if( FD_UNLIKELY( sess->tx_max-used<need ) ) return NULL;
    memmove( sess->tx, sess->tx+sess->tx_lo, used );
    sess->tx_lo = 0UL;
    sess->tx_hi = used;
  }
  return sess->tx+sess->tx_hi+FD_GRAVITY_FRAME_HDR_SZ;
}

void
fd_gravity_sess_tx_publish( fd_gravity_sess_t * sess,
                            ulong               sz,
                            long                now ) {
  if( FD_UNLIKELY( !sz ) ) return;
  fd_gravity_frame_hdr_write( sess->tx+sess->tx_hi, sz, (ulong)now );
  sess->tx_hi += FD_GRAVITY_FRAME_HDR_SZ+sz;
  sess->tx_frames++;
}

static int
do_connect( fd_gravity_sess_t * sess,
            long                now ) {
  int fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "gravity: socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    sess->state = FD_GRAVITY_SESS_STATE_CONNECTING; /* so reset counts it */
    fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_CONNECT, now );
    return 1;
  }
  sess->fd = fd;

  int one = 1;
  if( FD_UNLIKELY( setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(int) ) ) ) {
    FD_LOG_WARNING(( "gravity: setsockopt(TCP_NODELAY) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( sess->relay_port[ sess->relay_idx ] ),
    .sin_addr.s_addr = sess->relay_ip4[ sess->relay_idx ],
  };
  sess->state    = FD_GRAVITY_SESS_STATE_CONNECTING;
  sess->deadline = now + FD_GRAVITY_SESS_CONNECT_NS;
  if( FD_UNLIKELY( connect( fd, fd_type_pun_const( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
    fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_CONNECT, now );
  }
  return 1;
}

/* check_connected polls a pending non-blocking connect by calling
   connect again, which avoids needing poll/epoll.  Returns 1 once
   connected, 0 if still pending, -1 on failure. */

static int
check_connected( fd_gravity_sess_t * sess ) {
  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( sess->relay_port[ sess->relay_idx ] ),
    .sin_addr.s_addr = sess->relay_ip4[ sess->relay_idx ],
  };
  if( !connect( sess->fd, fd_type_pun_const( &addr ), sizeof(addr) ) ) return 1;
  switch( errno ) {
  case EISCONN:     return 1;
  case EALREADY:
  case EINPROGRESS: return 0;
  default:          return -1;
  }
}

static void
on_connected( fd_gravity_sess_t * sess,
              long                now ) {
  uchar hello[ 64 ];
  ulong sz = fd_gravity_encode_client_hello( hello, sizeof(hello), sess->identity );
  FD_TEST( sz );
  sess->state    = FD_GRAVITY_SESS_STATE_HELLO;
  sess->deadline = now + FD_GRAVITY_SESS_BOOTSTRAP_NS;
  sess->last_rx  = now;
  FD_TEST( !tx_raw( sess, hello, sz, now ) );
}

void
fd_gravity_sess_signed( fd_gravity_sess_t * sess,
                        uchar const         signature[ static 64 ],
                        long                now ) {
  if( FD_UNLIKELY( sess->state!=FD_GRAVITY_SESS_STATE_SIGN ) ) return;
  uchar proof[ 96 ];
  ulong sz = fd_gravity_encode_auth_proof( proof, sizeof(proof), signature );
  FD_TEST( sz );
  /* The relay processes bootstrap frames one at a time in order, so the
     handshake can be pipelined right behind the proof. */
  if( FD_UNLIKELY( tx_raw( sess, proof, sz, now ) || tx_raw( sess, sess->handshake, sess->handshake_sz, now ) ) ) {
    fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_TX_FULL, now );
    return;
  }
  sess->state    = FD_GRAVITY_SESS_STATE_ACCEPT;
  sess->deadline = now + FD_GRAVITY_SESS_BOOTSTRAP_NS;
}

/* frame_peek returns a pointer to the payload of the next complete
   frame in the receive buffer, or NULL.  Returns NULL and sets *err if
   the frame is too large to ever fit. */

static uchar const *
frame_peek( fd_gravity_sess_t * sess,
            ulong *             sz,
            int *               err ) {
  for(;;) {
    ulong avail = sess->rx_hi-sess->rx_lo;
    if( avail<FD_GRAVITY_FRAME_HDR_SZ ) return NULL;
    uchar const * hdr = sess->rx+sess->rx_lo;
    ulong payload_sz = fd_gravity_frame_hdr_payload_sz( hdr );
    if( FD_UNLIKELY( payload_sz>sess->rx_max-FD_GRAVITY_FRAME_HDR_SZ ) ) { *err = 1; return NULL; }
    if( avail<FD_GRAVITY_FRAME_HDR_SZ+payload_sz ) return NULL;
    if( FD_UNLIKELY( !payload_sz ) ) { sess->rx_lo += FD_GRAVITY_FRAME_HDR_SZ; continue; } /* keepalive */
    *sz = payload_sz;
    return hdr+FD_GRAVITY_FRAME_HDR_SZ;
  }
}

static inline void
frame_pop( fd_gravity_sess_t * sess,
           ulong               sz ) {
  sess->rx_lo += FD_GRAVITY_FRAME_HDR_SZ+sz;
  sess->rx_frames++;
}

/* handle_bootstrap processes bootstrap frames until the session is
   READY or there are no more complete frames. */

static void
handle_bootstrap( fd_gravity_sess_t * sess,
                  long                now ) {
  while( sess->state==FD_GRAVITY_SESS_STATE_HELLO || sess->state==FD_GRAVITY_SESS_STATE_ACCEPT ) {
    int err = 0;
    ulong sz;
    uchar const * payload = frame_peek( sess, &sz, &err );
    if( FD_UNLIKELY( err ) ) { fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_DECODE, now ); return; }
    if( !payload ) return;

    uint  tag;
    uint  reason = 0U;
    uchar challenge[ 32 ];
    if( FD_UNLIKELY( fd_gravity_decode_bootstrap( payload, sz, &tag, challenge, &reason ) ) ) {
      FD_LOG_WARNING(( "gravity: malformed bootstrap frame" ));
      fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_DECODE, now );
      return;
    }
    frame_pop( sess, sz );

    if( FD_UNLIKELY( tag==FD_GRAVITY_BOOT_REJECTED ) ) {
      FD_LOG_WARNING(( "gravity: relay rejected the connection (reason %u)", reason ));
      fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_REJECTED, now );
      return;
    }

    if( sess->state==FD_GRAVITY_SESS_STATE_HELLO && tag==FD_GRAVITY_BOOT_SERVER_HELLO ) {
      fd_gravity_auth_msg( sess->auth_msg, sess->identity, challenge );
      sess->state    = FD_GRAVITY_SESS_STATE_SIGN;
      sess->deadline = now + FD_GRAVITY_SESS_BOOTSTRAP_NS;
      return;
    }
    if( sess->state==FD_GRAVITY_SESS_STATE_ACCEPT && tag==FD_GRAVITY_BOOT_ACCEPTED ) {
      sess->state             = FD_GRAVITY_SESS_STATE_READY;
      sess->connect_fail_cnt  = 0UL;
      sess->identity_switched = 0;
      sess->session_new      = 1;
      sess->session_cnt++;
      FD_LOG_NOTICE(( "gravity: session ready (relay " FD_IP4_ADDR_FMT ":%hu)",
                      FD_IP4_ADDR_FMT_ARGS( sess->relay_ip4[ sess->relay_idx ] ), sess->relay_port[ sess->relay_idx ] ));
      return;
    }

    FD_LOG_WARNING(( "gravity: unexpected bootstrap frame %u in state %i", tag, sess->state ));
    fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_DECODE, now );
    return;
  }
}

static int
do_rx( fd_gravity_sess_t * sess,
       long                now ) {
  /* Compact so the largest frame fits contiguously. */
  if( sess->rx_lo==sess->rx_hi ) {
    sess->rx_lo = 0UL;
    sess->rx_hi = 0UL;
  } else if( sess->rx_lo && sess->rx_max-sess->rx_hi<RX_BYTES_PER_POLL ) {
    ulong used = sess->rx_hi-sess->rx_lo;
    memmove( sess->rx, sess->rx+sess->rx_lo, used );
    sess->rx_lo = 0UL;
    sess->rx_hi = used;
  }

  ulong room = fd_ulong_min( sess->rx_max-sess->rx_hi, RX_BYTES_PER_POLL );
  if( FD_UNLIKELY( !room ) ) return 0; /* caller must consume frames */

  long n = recvfrom( sess->fd, sess->rx+sess->rx_hi, room, MSG_DONTWAIT, NULL, NULL );
  if( n>0L ) {
    sess->rx_hi   += (ulong)n;
    sess->rx_bytes += (ulong)n;
    sess->last_rx  = now;
    return 1;
  }
  if( n==0L ) {
    fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_PEER_CLOSE, now );
    return 1;
  }
  if( FD_LIKELY( errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ) ) return 0;
  FD_LOG_WARNING(( "gravity: recv failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_IO, now );
  return 1;
}

static int
do_tx( fd_gravity_sess_t * sess,
       long                now ) {
  if( sess->tx_lo==sess->tx_hi ) return 0;
  long n = sendto( sess->fd, sess->tx+sess->tx_lo, sess->tx_hi-sess->tx_lo, MSG_DONTWAIT|MSG_NOSIGNAL, NULL, 0 );
  if( n>0L ) {
    sess->tx_lo    += (ulong)n;
    sess->tx_bytes += (ulong)n;
    if( sess->tx_lo==sess->tx_hi ) { sess->tx_lo = 0UL; sess->tx_hi = 0UL; }
    return 1;
  }
  if( FD_LIKELY( n<0L && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) ) ) return 0;
  FD_LOG_WARNING(( "gravity: send failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_IO, now );
  return 1;
}

int
fd_gravity_sess_poll( fd_gravity_sess_t * sess,
                      long                now ) {
  switch( sess->state ) {
  case FD_GRAVITY_SESS_STATE_IDLE:
    if( now<sess->deadline ) return 0;
    return do_connect( sess, now );

  case FD_GRAVITY_SESS_STATE_CONNECTING: {
    int r = check_connected( sess );
    if( r>0 ) { on_connected( sess, now ); break; }
    if( r<0 || now>=sess->deadline ) { fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_CONNECT, now ); return 1; }
    return 0;
  }

  case FD_GRAVITY_SESS_STATE_SIGN:
    /* Waiting on the caller.  Still flush and time out. */
  case FD_GRAVITY_SESS_STATE_HELLO:
  case FD_GRAVITY_SESS_STATE_ACCEPT:
    if( FD_UNLIKELY( now>=sess->deadline ) ) {
      fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_TIMEOUT, now );
      return 1;
    }
    break;

  case FD_GRAVITY_SESS_STATE_READY:
    if( FD_UNLIKELY( now-sess->last_rx>=FD_GRAVITY_SESS_RX_SILENCE_NS ) ) {
      fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_TIMEOUT, now );
      return 1;
    }
    break;

  default:
    break;
  }

  int work = 0;
  work |= do_tx( sess, now );
  if( sess->fd<0 ) return 1;
  work |= do_rx( sess, now );
  if( sess->fd<0 ) return 1;
  if( sess->state==FD_GRAVITY_SESS_STATE_HELLO || sess->state==FD_GRAVITY_SESS_STATE_ACCEPT ) {
    handle_bootstrap( sess, now );
    if( sess->fd>=0 ) work |= do_tx( sess, now );
  }
  return work;
}

uchar const *
fd_gravity_sess_next_frame( fd_gravity_sess_t * sess,
                            ulong *             sz ) {
  if( FD_UNLIKELY( sess->state!=FD_GRAVITY_SESS_STATE_READY ) ) return NULL;
  int err = 0;
  uchar const * payload = frame_peek( sess, sz, &err );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "gravity: relay frame larger than the %lu byte receive buffer", sess->rx_max ));
    fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_DECODE, sess->last_rx );
    return NULL;
  }
  if( !payload ) return NULL;

  /* No session message starts with the bootstrap magic.  The relay
     sends Rejected{Timeout} after Accepted if the HandshakeV2 arrived
     late, then closes the socket: treat any bootstrap frame here as
     the end of the session. */
  if( FD_UNLIKELY( *sz>=FD_GRAVITY_MAGIC_SZ && !memcmp( payload, FD_GRAVITY_MAGIC, FD_GRAVITY_MAGIC_SZ ) ) ) {
    uint  tag;
    uint  reason = 0U;
    uchar challenge[ 32 ];
    int   rejected = !fd_gravity_decode_bootstrap( payload, *sz, &tag, challenge, &reason ) && tag==FD_GRAVITY_BOOT_REJECTED;
    FD_LOG_WARNING(( "gravity: bootstrap frame in session (rejected %i, reason %u)", rejected, reason ));
    fd_gravity_sess_reset( sess, rejected ? FD_GRAVITY_SESS_RESET_REJECTED : FD_GRAVITY_SESS_RESET_DECODE, sess->last_rx );
    return NULL;
  }

  frame_pop( sess, *sz );
  return payload;
}
