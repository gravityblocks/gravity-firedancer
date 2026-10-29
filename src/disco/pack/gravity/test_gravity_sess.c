/* test_gravity_sess runs fd_gravity_sess against an in-process relay:
   a non-blocking TCP listener on 127.0.0.1 driven from the same thread
   between session polls.  Times passed to the session are explicit, so
   every timer is exercised exactly; real time is only spent waiting on
   loopback I/O.  Expected bytes come from the golden wire vectors. */

#include "fd_gravity_sess.h"
#include "../../../util/fd_util.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/sha512/fd_sha512.h"
#include "fixtures/test_gravity_wire_vectors.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define RX_MAX     (8192UL)
#define TX_MAX     (65536UL)
#define WAIT_ITERS (40000UL)  /* x 50 us = 2 s of real time per wait */
#define SEC        (1000000000L)

static uchar sess_mem[ 1UL<<20 ] __attribute__((aligned(64)));

static fd_sha512_t * sha;
static uchar         key_seed[ 2 ][ 32 ]; /* test key, RFC 8032 TEST 1 key */
static uchar         key_pub [ 2 ][ 32 ];

static struct gravity_wire_vec const *
vec( char const * name ) {
  for( ulong i=0UL; i<GRAVITY_WIRE_VEC_CNT; i++ ) {
    if( !strcmp( gravity_wire_vecs[ i ].name, name ) ) return gravity_wire_vecs+i;
  }
  FD_LOG_ERR(( "missing vector %s", name ));
}

static void
nap( void ) {
  fd_log_sleep( 50000L );
}

/* In-process relay *****************************************************/

struct srv {
  int    lfd;
  ushort port;      /* host byte order */
  int    cfd;       /* accepted connection, or -1 */
  ulong  rx_sz;
  ulong  consumed;
  uchar  rx[ 1UL<<21 ];
};

typedef struct srv srv_t;

static srv_t srv[ 2 ];

static void
srv_listen( srv_t * s,
            int     backlog ) {
  s->lfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  FD_TEST( s->lfd>=0 );
  /* Small receive buffer so the client sees partial sends */
  int rcvbuf = 8192;
  FD_TEST( !setsockopt( s->lfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int) ) );
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = 0, .sin_addr.s_addr = FD_IP4_ADDR( 127, 0, 0, 1 ) };
  FD_TEST( !bind( s->lfd, fd_type_pun_const( &addr ), sizeof(addr) ) );
  FD_TEST( !listen( s->lfd, backlog ) );
  socklen_t addr_sz = sizeof(addr);
  FD_TEST( !getsockname( s->lfd, fd_type_pun( &addr ), &addr_sz ) );
  s->port     = fd_ushort_bswap( addr.sin_port );
  s->cfd      = -1;
  s->rx_sz    = 0UL;
  s->consumed = 0UL;
}

static void
srv_drop( srv_t * s ) {
  if( s->cfd>=0 ) FD_TEST( !close( s->cfd ) );
  s->cfd      = -1;
  s->rx_sz    = 0UL;
  s->consumed = 0UL;
}

/* srv_accept polls the session at now until it is connected to s and
   s accepted that connection (stale connections are closed). */

static void
srv_accept( srv_t *             s,
            fd_gravity_sess_t * sess,
            long                now ) {
  srv_drop( s );
  for( ulong i=0UL; i<WAIT_ITERS; i++ ) {
    fd_gravity_sess_poll( sess, now );
    if( sess->state>=FD_GRAVITY_SESS_STATE_HELLO ) {
      struct sockaddr_in local; socklen_t local_sz = sizeof(local);
      FD_TEST( !getsockname( fd_gravity_sess_fd( sess ), fd_type_pun( &local ), &local_sz ) );
      for(;;) {
        struct sockaddr_in peer; socklen_t peer_sz = sizeof(peer);
        int fd = accept( s->lfd, fd_type_pun( &peer ), &peer_sz );
        if( fd<0 ) { FD_TEST( errno==EAGAIN || errno==EWOULDBLOCK ); break; }
        if( peer.sin_port!=local.sin_port ) { FD_TEST( !close( fd ) ); continue; }
        FD_TEST( !fcntl( fd, F_SETFL, O_NONBLOCK ) );
        s->cfd = fd;
        return;
      }
    }
    nap();
  }
  FD_LOG_ERR(( "timed out accepting the session (state %i)", sess->state ));
}

/* srv_frame waits for one complete client frame, polling the session at
   now so it flushes, and returns its payload (valid until the next
   call). */

static uchar const *
srv_frame( srv_t *             s,
           fd_gravity_sess_t * sess,
           long                now,
           ulong *             sz,
           ulong *             ts ) {
  if( s->consumed ) {
    memmove( s->rx, s->rx+s->consumed, s->rx_sz-s->consumed );
    s->rx_sz   -= s->consumed;
    s->consumed = 0UL;
  }
  for( ulong i=0UL; i<WAIT_ITERS; i++ ) {
    if( s->rx_sz>=FD_GRAVITY_FRAME_HDR_SZ ) {
      ulong psz = FD_LOAD( uint, s->rx );
      if( s->rx_sz>=FD_GRAVITY_FRAME_HDR_SZ+psz ) {
        *sz         = psz;
        *ts         = FD_LOAD( ulong, s->rx+4UL );
        s->consumed = FD_GRAVITY_FRAME_HDR_SZ+psz;
        return s->rx+FD_GRAVITY_FRAME_HDR_SZ;
      }
    }
    fd_gravity_sess_poll( sess, now );
    long n = recv( s->cfd, s->rx+s->rx_sz, sizeof(s->rx)-s->rx_sz, MSG_DONTWAIT );
    if( n>0L ) { s->rx_sz += (ulong)n; continue; }
    if( !n ) FD_LOG_ERR(( "client closed the connection (state %i)", sess->state ));
    FD_TEST( errno==EAGAIN || errno==EWOULDBLOCK );
    nap();
  }
  FD_LOG_ERR(( "timed out waiting for a client frame" ));
}

/* srv_expect waits for a client frame equal to want (ts==now). */

static void
srv_expect( srv_t *             s,
            fd_gravity_sess_t * sess,
            long                now,
            uchar const *       want,
            ulong               want_sz ) {
  ulong sz; ulong ts;
  uchar const * p = srv_frame( s, sess, now, &sz, &ts );
  if( FD_UNLIKELY( sz!=want_sz || memcmp( p, want, sz ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "got",  p,    sz      ));
    FD_LOG_HEXDUMP_WARNING(( "want", want, want_sz ));
    FD_LOG_ERR(( "unexpected client frame" ));
  }
  FD_TEST( ts==(ulong)now );
}

static void
srv_send( srv_t *      s,
          void const * data,
          ulong        sz ) {
  uchar const * p = data;
  for( ulong i=0UL; sz && i<WAIT_ITERS; i++ ) {
    long n = send( s->cfd, p, sz, MSG_DONTWAIT|MSG_NOSIGNAL );
    if( n>0L ) { p += n; sz -= (ulong)n; continue; }
    FD_TEST( n<0L && (errno==EAGAIN || errno==EWOULDBLOCK) );
    nap();
  }
  FD_TEST( !sz );
}

static ulong
frame( uchar *       out,
       uchar const * payload,
       ulong         sz ) {
  fd_gravity_frame_hdr_write( out, sz, 1234UL );
  if( sz ) memcpy( out+FD_GRAVITY_FRAME_HDR_SZ, payload, sz );
  return FD_GRAVITY_FRAME_HDR_SZ+sz;
}

static void
srv_send_frame( srv_t *       s,
                uchar const * payload,
                ulong         sz ) {
  static uchar buf[ 1UL<<16 ];
  srv_send( s, buf, frame( buf, payload, sz ) );
}

static void
srv_send_vec( srv_t *      s,
              char const * name ) {
  struct gravity_wire_vec const * v = vec( name );
  srv_send_frame( s, v->payload, v->payload_sz );
}

/* Session helpers ******************************************************/

static fd_gravity_sess_t *
sess_create( ulong          relay_cnt,
             srv_t * const * relays,
             ushort const * ports,
             uchar const *  identity ) {
  uint   ip4 [ FD_GRAVITY_SESS_RELAY_MAX ];
  ushort port[ FD_GRAVITY_SESS_RELAY_MAX ];
  for( ulong i=0UL; i<relay_cnt; i++ ) {
    ip4 [ i ] = FD_IP4_ADDR( 127, 0, 0, 1 );
    port[ i ] = relays && relays[ i ] ? relays[ i ]->port : ports[ i ];
  }
  /* Encodes to c2r_handshake_v2_basic for the test identity */
  fd_gravity_handshake_t hs = { .version = "fd-gravity/0.1.0", .num_threads = 4, .filter_ofac = 0, .jito_tip_weight_bps = 10000 };
  FD_TEST( fd_gravity_sess_footprint( RX_MAX, TX_MAX )<=sizeof(sess_mem) );
  fd_gravity_sess_t * sess = fd_gravity_sess_new( sess_mem, RX_MAX, TX_MAX, identity, relay_cnt, ip4, port, &hs );
  FD_TEST( sess );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE && fd_gravity_sess_fd( sess )==-1 );
  return sess;
}

static void
sess_destroy( fd_gravity_sess_t * sess,
              long                now ) {
  fd_gravity_sess_reset( sess, FD_GRAVITY_SESS_RESET_CALLER, now );
  FD_TEST( fd_gravity_sess_fd( sess )==-1 );
}

/* poll_until polls the session at now until its state is want. */

static void
poll_until( fd_gravity_sess_t * sess,
            long                now,
            int                 want ) {
  for( ulong i=0UL; i<WAIT_ITERS; i++ ) {
    fd_gravity_sess_poll( sess, now );
    if( sess->state==want ) return;
    nap();
  }
  FD_LOG_ERR(( "timed out waiting for state %i (state %i)", want, sess->state ));
}

/* poll_rx polls the session at now until it has received rx_bytes. */

static void
poll_rx( fd_gravity_sess_t * sess,
         long                now,
         ulong               rx_bytes ) {
  for( ulong i=0UL; i<WAIT_ITERS; i++ ) {
    fd_gravity_sess_poll( sess, now );
    FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_READY );
    if( sess->rx_bytes>=rx_bytes ) { FD_TEST( sess->rx_bytes==rx_bytes ); return; }
    nap();
  }
  FD_LOG_ERR(( "timed out waiting for %lu received bytes (have %lu)", rx_bytes, sess->rx_bytes ));
}

/* wait_frame polls the session at now until a relay frame is available
   and returns it. */

static uchar const *
wait_frame( fd_gravity_sess_t * sess,
            long                now,
            ulong *             sz ) {
  for( ulong i=0UL; i<WAIT_ITERS; i++ ) {
    uchar const * p = fd_gravity_sess_next_frame( sess, sz );
    if( p ) return p;
    FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_READY );
    fd_gravity_sess_poll( sess, now );
    nap();
  }
  FD_LOG_ERR(( "timed out waiting for a relay frame" ));
}

/* sign_challenge signs the session's auth message with key k. */

static void
sign_challenge( fd_gravity_sess_t * sess,
                ulong               k,
                uchar               sig[ 64 ] ) {
  FD_TEST( fd_ed25519_sign( sig, fd_gravity_sess_auth_msg( sess ), FD_GRAVITY_AUTH_MSG_SZ, key_pub[ k ], key_seed[ k ], sha )==sig );
}

/* bootstrap runs a complete bootstrap from IDLE with key k at now,
   checking every frame against the vectors (test key) or the expected
   layout (other keys).  extra (may be NULL) is appended to the Accepted
   frame in the same send. */

static void
bootstrap( srv_t *             s,
           fd_gravity_sess_t * sess,
           ulong               k,
           long                now,
           uchar const *       extra,
           ulong               extra_sz ) {
  ulong session_cnt = sess->session_cnt;
  srv_accept( s, sess, now );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_HELLO );

  /* ClientHello */
  uchar want[ 1024 ];
  ulong want_sz = fd_gravity_encode_client_hello( want, sizeof(want), key_pub[ k ] );
  FD_TEST( want_sz==44UL );
  if( !k ) FD_TEST( !memcmp( want, vec( "boot_client_hello" )->payload, want_sz ) );
  srv_expect( s, sess, now, want, want_sz );

  /* Nothing is exposed before READY */
  ulong sz;
  FD_TEST( !fd_gravity_sess_need_sign( sess ) );
  FD_TEST( !fd_gravity_sess_next_frame( sess, &sz ) );
  FD_TEST( !fd_gravity_sess_tx_prepare( sess, 16UL ) );
  FD_TEST( !fd_gravity_sess_is_ready( sess ) );

  /* ServerHello with challenge 00..1f */
  struct gravity_wire_vec const * sh = vec( "boot_server_hello" );
  srv_send_frame( s, sh->payload, sh->payload_sz );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_SIGN );
  FD_TEST( fd_gravity_sess_need_sign( sess ) );
  uchar msg[ FD_GRAVITY_AUTH_MSG_SZ ];
  fd_gravity_auth_msg( msg, key_pub[ k ], sh->payload+12UL );
  FD_TEST( !memcmp( fd_gravity_sess_auth_msg( sess ), msg, FD_GRAVITY_AUTH_MSG_SZ ) );
  if( !k ) FD_TEST( !memcmp( msg, vec( "auth_message" )->payload, FD_GRAVITY_AUTH_MSG_SZ ) );

  /* Waiting on the signer does not time out early or send anything */
  fd_gravity_sess_poll( sess, now+SEC );
  FD_TEST( fd_gravity_sess_need_sign( sess ) );

  uchar sig[ 64 ];
  sign_challenge( sess, k, sig );
  if( !k ) FD_TEST( !memcmp( sig, vec( "auth_signature" )->payload, 64UL ) );
  fd_gravity_sess_signed( sess, sig, now );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_ACCEPT && !fd_gravity_sess_need_sign( sess ) );
  fd_gravity_sess_signed( sess, sig, now ); /* ignored outside SIGN */
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_ACCEPT );

  /* AuthProof (verified like the relay does), then HandshakeV2 */
  want_sz = fd_gravity_encode_auth_proof( want, sizeof(want), sig );
  if( !k ) FD_TEST( want_sz==vec( "boot_auth_proof" )->payload_sz && !memcmp( want, vec( "boot_auth_proof" )->payload, want_sz ) );
  ulong ts;
  uchar const * proof = srv_frame( s, sess, now, &sz, &ts );
  FD_TEST( sz==want_sz && !memcmp( proof, want, sz ) && ts==(ulong)now );
  FD_TEST( fd_ed25519_verify( msg, FD_GRAVITY_AUTH_MSG_SZ, proof+12UL, key_pub[ k ], sha )==FD_ED25519_SUCCESS );

  fd_gravity_handshake_t hs = { .version = "fd-gravity/0.1.0", .num_threads = 4, .jito_tip_weight_bps = 10000 };
  memcpy( hs.identity, key_pub[ k ], 32UL );
  want_sz = fd_gravity_encode_handshake_v2( want, sizeof(want), &hs );
  if( !k ) FD_TEST( want_sz==vec( "c2r_handshake_v2_basic" )->payload_sz && !memcmp( want, vec( "c2r_handshake_v2_basic" )->payload, want_sz ) );
  srv_expect( s, sess, now, want, want_sz );

  /* Accepted (and optionally more frames in the same send) */
  static uchar buf[ 1UL<<16 ];
  struct gravity_wire_vec const * acc = vec( "boot_accepted" );
  ulong buf_sz = frame( buf, acc->payload, acc->payload_sz );
  FD_TEST( buf_sz+extra_sz<=sizeof(buf) );
  if( extra_sz ) memcpy( buf+buf_sz, extra, extra_sz );
  srv_send( s, buf, buf_sz+extra_sz );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_READY );
  FD_TEST( fd_gravity_sess_is_ready( sess ) );
  FD_TEST( sess->session_new );
  FD_TEST( sess->session_cnt==session_cnt+1UL );
  FD_TEST( !sess->connect_fail_cnt );
  sess->session_new = 0;
}

/* Tests ****************************************************************/

static void
test_bootstrap_and_framing( long now ) {
  srv_t * relays[1] = { srv };
  fd_gravity_sess_t * sess = sess_create( 1UL, relays, NULL, key_pub[ 0 ] );

  /* Accepted, ShredReceiverAddresses and a Ping arrive in one segment */
  static uchar extra[ 1024 ];
  ulong extra_sz = 0UL;
  struct gravity_wire_vec const * shred = vec( "r2c_shred_receivers_empty" );
  struct gravity_wire_vec const * ping  = vec( "r2c_ping_seq" );
  extra_sz += frame( extra+extra_sz, shred->payload, shred->payload_sz );
  extra_sz += frame( extra+extra_sz, ping->payload,  ping->payload_sz  );
  bootstrap( srv, sess, 0UL, now, extra, extra_sz );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_CONNECT ]==0UL );

  ulong sz;
  uchar const * p;
  p = wait_frame( sess, now, &sz );
  FD_TEST( sz==shred->payload_sz && !memcmp( p, shred->payload, sz ) );
  p = wait_frame( sess, now, &sz );
  FD_TEST( sz==ping->payload_sz && !memcmp( p, ping->payload, sz ) );
  FD_TEST( !fd_gravity_sess_next_frame( sess, &sz ) );

  /* Client -> relay: a Pong and a large Transaction */
  struct gravity_wire_vec const * pong = vec( "c2r_pong_7" );
  uchar * buf = fd_gravity_sess_tx_prepare( sess, 16UL );
  FD_TEST( buf );
  ulong pong_sz = fd_gravity_encode_pong( buf, 16UL, 7UL );
  fd_gravity_sess_tx_publish( sess, pong_sz, now );
  srv_expect( srv, sess, now, pong->payload, pong->payload_sz );

  struct gravity_wire_vec const * txv = vec( "c2r_transaction_v1_uri64" );
  struct gravity_wire_vec const * tx1 = vec( "tx_v1" );
  buf = fd_gravity_sess_tx_prepare( sess, 2048UL );
  FD_TEST( buf );
  uchar src[ 16 ]; memset( src, 0xfe, 16UL );
  char uri[ 65 ]; memset( uri, 'u', 64UL ); uri[ 64 ] = '\0';
  sz = fd_gravity_encode_transaction( buf, 2048UL, tx1->payload, tx1->payload_sz, ULONG_MAX, 0UL, src, uri );
  FD_TEST( sz==txv->payload_sz );
  fd_gravity_sess_tx_publish( sess, sz, now+1L );
  srv_expect( srv, sess, now+1L, txv->payload, txv->payload_sz );

  /* sz==0 cancels */
  ulong tx_frames = sess->tx_frames;
  FD_TEST( fd_gravity_sess_tx_prepare( sess, 64UL ) );
  fd_gravity_sess_tx_publish( sess, 0UL, now );
  FD_TEST( sess->tx_frames==tx_frames );

  /* A prepare larger than the buffer fails */
  FD_TEST( !fd_gravity_sess_tx_prepare( sess, TX_MAX ) );
  FD_TEST( fd_gravity_sess_tx_free( sess )==TX_MAX );

  /* Client -> relay stream with a tiny socket send buffer: the client
     sees partial sends, fills its transmit buffer, and compacts it.
     Every frame must arrive intact and in order. */
  int sndbuf = 4096;
  FD_TEST( !setsockopt( fd_gravity_sess_fd( sess ), SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int) ) );
  ulong const stream_cnt = 3000UL;
  ulong published = 0UL; ulong received = 0UL;
  int   saw_full = 0;    int   saw_partial = 0;
  for( ulong iter=0UL; received<stream_cnt && iter<1000000UL; iter++ ) {
    /* Publish until the buffer is full (the relay doesn't read in the
       first phase) */
    while( published<stream_cnt ) {
      buf = fd_gravity_sess_tx_prepare( sess, 512UL );
      if( !buf ) { saw_full = 1; break; }
      sz = fd_gravity_encode_transaction( buf, 512UL, tx1->payload, tx1->payload_sz, published, ~published, src, NULL );
      FD_TEST( sz );
      fd_gravity_sess_tx_publish( sess, sz, now+(long)published );
      published++;
      if( !saw_full ) break;
    }
    fd_gravity_sess_poll( sess, now );
    FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_READY );
    if( sess->tx_lo && sess->tx_lo!=sess->tx_hi ) saw_partial = 1;
    if( !saw_full && published<stream_cnt ) continue;

    /* Relay drains */
    long n = recv( srv->cfd, srv->rx+srv->rx_sz, sizeof(srv->rx)-srv->rx_sz, MSG_DONTWAIT );
    if( n>0L ) srv->rx_sz += (ulong)n;
    else       FD_TEST( n<0L && (errno==EAGAIN || errno==EWOULDBLOCK) );
    ulong off = srv->consumed;
    while( srv->rx_sz-off>=12UL && srv->rx_sz-off>=12UL+FD_LOAD( uint, srv->rx+off ) ) {
      ulong psz = FD_LOAD( uint, srv->rx+off );
      uchar const * pl = srv->rx+off+12UL;
      FD_TEST( FD_LOAD( ulong, srv->rx+off+4UL )==(ulong)now+received );
      FD_TEST( FD_LOAD( uint, pl )==FD_GRAVITY_C2R_TRANSACTION );
      FD_TEST( FD_LOAD( ulong, pl+4UL )==tx1->payload_sz && !memcmp( pl+12UL, tx1->payload, tx1->payload_sz ) );
      FD_TEST( FD_LOAD( ulong, pl+12UL+tx1->payload_sz )==received );
      FD_TEST( FD_LOAD( ulong, pl+20UL+tx1->payload_sz )==~received );
      FD_TEST( psz==12UL+tx1->payload_sz+16UL+16UL+1UL && !pl[ psz-1UL ] );
      off += 12UL+psz;
      received++;
    }
    memmove( srv->rx, srv->rx+off, srv->rx_sz-off );
    srv->rx_sz   -= off;
    srv->consumed = 0UL;
    if( n<=0L ) nap();
  }
  FD_TEST( received==stream_cnt && published==stream_cnt );
  FD_TEST( saw_full && saw_partial );
  FD_TEST( sess->tx_frames==tx_frames+stream_cnt );
  FD_LOG_NOTICE(( "client -> relay: %lu frames in order (buffer full and partial sends seen)", stream_cnt ));

  /* Relay -> client: a keepalive then a Ping */
  static uchar sbuf[ 1UL<<17 ];
  ulong sbuf_sz = frame( sbuf, NULL, 0UL );
  sbuf_sz += frame( sbuf+sbuf_sz, ping->payload, ping->payload_sz );
  ulong rx_bytes = sess->rx_bytes;
  srv_send( srv, sbuf, sbuf_sz );
  poll_rx( sess, now, rx_bytes+sbuf_sz );
  p = fd_gravity_sess_next_frame( sess, &sz );
  FD_TEST( p && sz==ping->payload_sz && !memcmp( p, ping->payload, sz ) );
  FD_TEST( !fd_gravity_sess_next_frame( sess, &sz ) );

  /* A keepalive and a graph frame split across 1 byte sends */
  struct gravity_wire_vec const * graph = vec( "r2c_graph_mixed_dag" );
  sbuf_sz  = frame( sbuf, NULL, 0UL );
  sbuf_sz += frame( sbuf+sbuf_sz, graph->payload, graph->payload_sz );
  rx_bytes = sess->rx_bytes;
  for( ulong i=0UL; i<sbuf_sz; i++ ) {
    srv_send( srv, sbuf+i, 1UL );
    poll_rx( sess, now, rx_bytes+i+1UL );
    p = fd_gravity_sess_next_frame( sess, &sz );
    if( i+1UL<sbuf_sz ) { FD_TEST( !p ); continue; }
    FD_TEST( p && sz==graph->payload_sz && !memcmp( p, graph->payload, sz ) );
  }
  FD_TEST( !fd_gravity_sess_next_frame( sess, &sz ) );

  /* Several frames (and keepalives) in one send */
  static char const * const many[] = {
    "r2c_ping_0", NULL, "r2c_graph_single_tx", "r2c_ping_max", NULL, NULL, "r2c_graph_connector_sourced", "r2c_delete_failsafe"
  };
  sbuf_sz = 0UL;
  for( ulong i=0UL; i<sizeof(many)/sizeof(many[0]); i++ ) {
    if( !many[ i ] ) { sbuf_sz += frame( sbuf+sbuf_sz, NULL, 0UL ); continue; }
    struct gravity_wire_vec const * v = vec( many[ i ] );
    sbuf_sz += frame( sbuf+sbuf_sz, v->payload, v->payload_sz );
  }
  rx_bytes = sess->rx_bytes;
  ulong rx_frames = sess->rx_frames;
  srv_send( srv, sbuf, sbuf_sz );
  poll_rx( sess, now, rx_bytes+sbuf_sz );
  for( ulong i=0UL; i<sizeof(many)/sizeof(many[0]); i++ ) {
    if( !many[ i ] ) continue;
    struct gravity_wire_vec const * v = vec( many[ i ] );
    p = fd_gravity_sess_next_frame( sess, &sz );
    FD_TEST( p && sz==v->payload_sz && !memcmp( p, v->payload, sz ) );
  }
  FD_TEST( !fd_gravity_sess_next_frame( sess, &sz ) );
  FD_TEST( sess->rx_frames==rx_frames+5UL );

  /* A stream much larger than rx_max, consumed as it arrives (the
     receive buffer is compacted many times) */
  ulong const graph_cnt = 100UL;
  ulong frame_sz = frame( sbuf, graph->payload, graph->payload_sz );
  for( ulong i=1UL; i<graph_cnt; i++ ) memcpy( sbuf+i*frame_sz, sbuf, frame_sz );
  FD_TEST( graph_cnt*frame_sz<=sizeof(sbuf) && graph_cnt*frame_sz>8UL*RX_MAX );
  ulong sent = 0UL; ulong got = 0UL;
  for( ulong iter=0UL; got<graph_cnt && iter<1000000UL; iter++ ) {
    long n = 0L;
    if( sent<graph_cnt*frame_sz ) {
      n = send( srv->cfd, sbuf+sent, graph_cnt*frame_sz-sent, MSG_DONTWAIT|MSG_NOSIGNAL );
      if( n>0L ) sent += (ulong)n;
      else       FD_TEST( n<0L && (errno==EAGAIN || errno==EWOULDBLOCK) );
    }
    int work = fd_gravity_sess_poll( sess, now );
    FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_READY );
    while( (p = fd_gravity_sess_next_frame( sess, &sz )) ) {
      FD_TEST( sz==graph->payload_sz && !memcmp( p, graph->payload, sz ) );
      got++;
    }
    if( n<=0L && !work ) nap();
  }
  FD_TEST( got==graph_cnt );
  FD_LOG_NOTICE(( "relay -> client: keepalives, 1 byte splits, coalesced frames and a %lu byte stream ok", graph_cnt*frame_sz ));

  /* A caller that stops consuming: the receive buffer fills up to
     rx_max, polling stops reading (the rest waits in the socket), and
     nothing is lost once the caller consumes again */
  ulong const ping_cnt = 2UL*RX_MAX/24UL;
  sbuf_sz = 0UL;
  for( ulong i=0UL; i<ping_cnt; i++ ) {
    uchar pl[ 12 ];
    FD_STORE( uint,  pl,     FD_GRAVITY_R2C_PING );
    FD_STORE( ulong, pl+4UL, i                   );
    sbuf_sz += frame( sbuf+sbuf_sz, pl, 12UL );
  }
  rx_bytes = sess->rx_bytes;
  srv_send( srv, sbuf, sbuf_sz );
  for( ulong i=0UL; i<WAIT_ITERS && sess->rx_bytes<rx_bytes+RX_MAX-RX_MAX%24UL; i++ ) { fd_gravity_sess_poll( sess, now ); nap(); }
  for( ulong i=0UL; i<16UL; i++ ) fd_gravity_sess_poll( sess, now );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_READY );
  FD_TEST( sess->rx_hi-sess->rx_lo<=RX_MAX && sess->rx_bytes-rx_bytes<sbuf_sz );
  for( ulong i=0UL; i<ping_cnt; i++ ) {
    p = wait_frame( sess, now, &sz );
    FD_TEST( sz==12UL && FD_LOAD( uint, p )==FD_GRAVITY_R2C_PING && FD_LOAD( ulong, p+4UL )==i );
  }
  FD_TEST( sess->rx_bytes==rx_bytes+sbuf_sz && !fd_gravity_sess_next_frame( sess, &sz ) );

  /* A frame of exactly rx_max bytes fits (unknown tag 6 payload) */
  memset( sbuf, 0, RX_MAX );
  fd_gravity_frame_hdr_write( sbuf, RX_MAX-FD_GRAVITY_FRAME_HDR_SZ, 0UL );
  FD_STORE( uint, sbuf+FD_GRAVITY_FRAME_HDR_SZ, 6U );
  sbuf[ RX_MAX-1UL ] = 0x77;
  rx_bytes = sess->rx_bytes;
  srv_send( srv, sbuf, RX_MAX );
  p = wait_frame( sess, now, &sz );
  FD_TEST( sess->rx_bytes==rx_bytes+RX_MAX );
  FD_TEST( sz==RX_MAX-FD_GRAVITY_FRAME_HDR_SZ && FD_LOAD( uint, p )==6U && p[ sz-1UL ]==0x77 );

  /* One byte more resets the session (DECODE) */
  fd_gravity_frame_hdr_write( sbuf, RX_MAX-FD_GRAVITY_FRAME_HDR_SZ+1UL, 0UL );
  rx_bytes = sess->rx_bytes;
  srv_send( srv, sbuf, FD_GRAVITY_FRAME_HDR_SZ );
  poll_rx( sess, now+2L, rx_bytes+FD_GRAVITY_FRAME_HDR_SZ );
  FD_TEST( !fd_gravity_sess_next_frame( sess, &sz ) );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE && fd_gravity_sess_fd( sess )==-1 );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ]==1UL );
  FD_TEST( sess->deadline==now+2L+FD_GRAVITY_SESS_RECONNECT_NS ); /* reset at the last receive time */
  FD_TEST( !sess->rx_lo && !sess->rx_hi && !sess->tx_lo && !sess->tx_hi );
  FD_TEST( !fd_gravity_sess_tx_prepare( sess, 16UL ) );

  sess_destroy( sess, now );
  srv_drop( srv );
  FD_LOG_NOTICE(( "bootstrap and framing: ok" ));
}

static void
test_resets( long now ) {
  srv_t * relays[1] = { srv };
  fd_gravity_sess_t * sess = sess_create( 1UL, relays, NULL, key_pub[ 0 ] );
  ulong sz;

  /* Peer close -> IDLE, reconnect after the backoff */
  bootstrap( srv, sess, 0UL, now, NULL, 0UL );
  srv_drop( srv );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_PEER_CLOSE ]==1UL );
  FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_RECONNECT_NS );
  FD_TEST( !fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_RECONNECT_NS-1L ) );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE && fd_gravity_sess_fd( sess )==-1 );
  now += FD_GRAVITY_SESS_RECONNECT_NS;
  FD_TEST( fd_gravity_sess_poll( sess, now ) );
  FD_TEST( sess->state>=FD_GRAVITY_SESS_STATE_CONNECTING && fd_gravity_sess_fd( sess )>=0 );
  bootstrap( srv, sess, 0UL, now, NULL, 0UL );
  FD_TEST( sess->session_cnt==2UL );
  FD_LOG_NOTICE(( "peer close: ok" ));

  /* Connection reset (RST) -> IO error */
  struct linger lg = { .l_onoff = 1, .l_linger = 0 };
  FD_TEST( !setsockopt( srv->cfd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg) ) );
  srv_drop( srv );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_IO ]==1UL );
  FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_RECONNECT_NS );
  now += FD_GRAVITY_SESS_RECONNECT_NS;
  bootstrap( srv, sess, 0UL, now, NULL, 0UL );
  FD_LOG_NOTICE(( "connection reset: ok" ));

  /* RX silence in READY: a Ping at +2 s extends the deadline */
  srv_send_vec( srv, "r2c_ping_0" );
  poll_rx( sess, now+2L*SEC, sess->rx_bytes+24UL );
  FD_TEST( fd_gravity_sess_next_frame( sess, &sz ) && sz==12UL );
  FD_TEST( sess->last_rx==now+2L*SEC );
  fd_gravity_sess_poll( sess, now+2L*SEC+FD_GRAVITY_SESS_RX_SILENCE_NS-1L );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_READY );
  fd_gravity_sess_poll( sess, now+2L*SEC+FD_GRAVITY_SESS_RX_SILENCE_NS );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_TIMEOUT ]==1UL );
  now += 2L*SEC+FD_GRAVITY_SESS_RX_SILENCE_NS;
  FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_RECONNECT_NS );
  now += FD_GRAVITY_SESS_RECONNECT_NS;
  FD_LOG_NOTICE(( "rx silence: ok" ));

  /* Rejected{UnknownIdentity} -> longer backoff */
  srv_accept( srv, sess, now );
  srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
  srv_send_vec( srv, "boot_rejected_unknownidentity" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_REJECTED ]==1UL );
  FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_REJECT_BACKOFF_NS );
  FD_TEST( FD_GRAVITY_SESS_REJECT_BACKOFF_NS>FD_GRAVITY_SESS_RECONNECT_NS );
  FD_TEST( !fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_RECONNECT_NS ) );
  FD_TEST( !fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_REJECT_BACKOFF_NS-1L ) );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  now += FD_GRAVITY_SESS_REJECT_BACKOFF_NS;
  FD_LOG_NOTICE(( "rejected: ok" ));

  /* Rejected{InvalidProof} after the AuthProof */
  srv_accept( srv, sess, now );
  srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
  srv_send_vec( srv, "boot_server_hello" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_SIGN );
  uchar sig[ 64 ];
  sign_challenge( sess, 0UL, sig );
  fd_gravity_sess_signed( sess, sig, now );
  srv_expect( srv, sess, now, vec( "boot_auth_proof" )->payload, 76UL );
  srv_send_vec( srv, "boot_rejected_invalidproof" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_REJECTED ]==2UL );
  FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_REJECT_BACKOFF_NS );
  now += FD_GRAVITY_SESS_REJECT_BACKOFF_NS;

  /* Bootstrap step timeouts: HELLO, SIGN and ACCEPT each time out 10 s
     after the step starts */
  ulong timeouts = sess->reset_cnt[ FD_GRAVITY_SESS_RESET_TIMEOUT ];
  srv_accept( srv, sess, now );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_HELLO );
  fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_BOOTSTRAP_NS-1L );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_HELLO );
  fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_BOOTSTRAP_NS );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_TIMEOUT ]==++timeouts );
  now += FD_GRAVITY_SESS_BOOTSTRAP_NS+FD_GRAVITY_SESS_RECONNECT_NS;

  srv_accept( srv, sess, now );
  srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
  now += SEC;
  srv_send_vec( srv, "boot_server_hello" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_SIGN ); /* SIGN starts now */
  fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_BOOTSTRAP_NS-1L );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_SIGN );
  fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_BOOTSTRAP_NS );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_TIMEOUT ]==++timeouts );
  fd_gravity_sess_signed( sess, sig, now ); /* late signature is ignored */
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  now += FD_GRAVITY_SESS_BOOTSTRAP_NS+FD_GRAVITY_SESS_RECONNECT_NS;

  srv_accept( srv, sess, now );
  srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
  srv_send_vec( srv, "boot_server_hello" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_SIGN );
  now += SEC;
  sign_challenge( sess, 0UL, sig );
  fd_gravity_sess_signed( sess, sig, now ); /* ACCEPT starts now */
  srv_expect( srv, sess, now, vec( "boot_auth_proof" )->payload, 76UL );
  srv_expect( srv, sess, now, vec( "c2r_handshake_v2_basic" )->payload, 72UL );
  fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_BOOTSTRAP_NS-1L );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_ACCEPT );
  fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_BOOTSTRAP_NS );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_TIMEOUT ]==++timeouts );
  now += FD_GRAVITY_SESS_BOOTSTRAP_NS+FD_GRAVITY_SESS_RECONNECT_NS;
  FD_LOG_NOTICE(( "bootstrap timeouts: ok" ));

  /* Unexpected or malformed bootstrap frames reset (DECODE) */
  static char const * const bad_hello[] = { "boot_accepted", "neg_boot_tag_5", "neg_boot_session_msg", "neg_boot_reject_reason_4" };
  for( ulong i=0UL; i<sizeof(bad_hello)/sizeof(bad_hello[0]); i++ ) {
    ulong decode = sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ];
    srv_accept( srv, sess, now );
    srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
    srv_send_vec( srv, bad_hello[ i ] );
    poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
    FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ]==decode+1UL );
    FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_RECONNECT_NS );
    now += FD_GRAVITY_SESS_RECONNECT_NS;
  }

  /* ServerHello while waiting for Accepted */
  ulong decode = sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ];
  srv_accept( srv, sess, now );
  srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
  srv_send_vec( srv, "boot_server_hello" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_SIGN );
  sign_challenge( sess, 0UL, sig );
  fd_gravity_sess_signed( sess, sig, now );
  srv_send_vec( srv, "boot_server_hello" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ]==decode+1UL );
  now += FD_GRAVITY_SESS_RECONNECT_NS;

  /* A bootstrap frame larger than rx_max */
  srv_accept( srv, sess, now );
  srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
  uchar hdr[ FD_GRAVITY_FRAME_HDR_SZ ];
  fd_gravity_frame_hdr_write( hdr, UINT_MAX, 0UL );
  srv_send( srv, hdr, sizeof(hdr) );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ]==decode+2UL );
  now += FD_GRAVITY_SESS_RECONNECT_NS;
  FD_LOG_NOTICE(( "bad bootstrap frames: ok" ));

  /* Bootstrap frames once READY: a late Rejected{Timeout} ends the
     session with the reject backoff, anything else is a decode error */
  bootstrap( srv, sess, 0UL, now, NULL, 0UL );
  srv_send_vec( srv, "r2c_ping_max" );
  srv_send_vec( srv, "boot_rejected_timeout" );
  ulong rejected = sess->reset_cnt[ FD_GRAVITY_SESS_RESET_REJECTED ];
  poll_rx( sess, now+5L, sess->rx_bytes+24UL+28UL );
  uchar const * p = fd_gravity_sess_next_frame( sess, &sz );
  FD_TEST( p && sz==12UL && FD_LOAD( uint, p )==FD_GRAVITY_R2C_PING );
  FD_TEST( !fd_gravity_sess_next_frame( sess, &sz ) );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_REJECTED ]==rejected+1UL );
  FD_TEST( sess->deadline==now+5L+FD_GRAVITY_SESS_REJECT_BACKOFF_NS );
  now += 5L+FD_GRAVITY_SESS_REJECT_BACKOFF_NS;

  bootstrap( srv, sess, 0UL, now, NULL, 0UL );
  decode = sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ];
  srv_send_vec( srv, "boot_accepted" );
  poll_rx( sess, now, sess->rx_bytes+24UL );
  FD_TEST( !fd_gravity_sess_next_frame( sess, &sz ) );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_DECODE ]==decode+1UL );
  now += FD_GRAVITY_SESS_RECONNECT_NS;
  FD_LOG_NOTICE(( "bootstrap frames in session: ok" ));

  /* Identity switch: immediate reconnect with the new identity in the
     ClientHello, the signed message and the HandshakeV2 */
  bootstrap( srv, sess, 0UL, now, NULL, 0UL );
  ulong caller = sess->reset_cnt[ FD_GRAVITY_SESS_RESET_CALLER ];
  fd_gravity_sess_set_identity( sess, key_pub[ 1 ], now );
  FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE && sess->deadline==now );
  FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_CALLER ]==caller+1UL );
  FD_TEST( !sess->connect_fail_cnt );
  bootstrap( srv, sess, 1UL, now, NULL, 0UL );
  FD_TEST( !sess->identity_switched );

  /* A proof rejected right after a switch (the sign tile may not have
     switched keys yet) is retried after the normal reconnect delay and
     does not count towards relay rotation */
  fd_gravity_sess_set_identity( sess, key_pub[ 0 ], now );
  srv_accept( srv, sess, now );
  srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
  srv_send_vec( srv, "boot_server_hello" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_SIGN );
  uchar sig2[ 64 ];
  sign_challenge( sess, 0UL, sig2 );
  fd_gravity_sess_signed( sess, sig2, now );
  srv_expect( srv, sess, now, vec( "boot_auth_proof" )->payload, 76UL );
  srv_send_vec( srv, "boot_rejected_invalidproof" );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_RECONNECT_NS && !sess->connect_fail_cnt );
  now += FD_GRAVITY_SESS_RECONNECT_NS;
  bootstrap( srv, sess, 0UL, now, NULL, 0UL );
  FD_TEST( !sess->identity_switched );

  sess_destroy( sess, now );
  srv_drop( srv );
  FD_LOG_NOTICE(( "identity switch: ok" ));
}

static void
test_rotation( long now ) {
  /* A closed port: bind, then close */
  int tfd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( tfd>=0 );
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = 0, .sin_addr.s_addr = FD_IP4_ADDR( 127, 0, 0, 1 ) };
  FD_TEST( !bind( tfd, fd_type_pun_const( &addr ), sizeof(addr) ) );
  socklen_t addr_sz = sizeof(addr);
  FD_TEST( !getsockname( tfd, fd_type_pun( &addr ), &addr_sz ) );
  FD_TEST( !close( tfd ) );
  ushort closed_port = fd_ushort_bswap( addr.sin_port );

  /* Relay 0 is closed, relay 1 is srv[1] */
  srv_t *  relays[2] = { NULL, srv+1 };
  ushort   ports [2] = { closed_port, 0 };
  fd_gravity_sess_t * sess = sess_create( 2UL, relays, ports, key_pub[ 0 ] );
  for( ulong fail=1UL; fail<=3UL; fail++ ) {
    FD_TEST( sess->relay_idx==0UL );
    FD_TEST( fd_gravity_sess_poll( sess, now ) );
    poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
    FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_CONNECT ]==fail );
    FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_RECONNECT_NS );
    FD_TEST( fd_gravity_sess_fd( sess )==-1 );
    now += FD_GRAVITY_SESS_RECONNECT_NS;
  }
  FD_TEST( sess->relay_idx==1UL && !sess->connect_fail_cnt );
  bootstrap( srv+1, sess, 0UL, now, NULL, 0UL );
  FD_TEST( sess->relay_idx==1UL );
  srv_drop( srv+1 );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  sess_destroy( sess, now );
  FD_LOG_NOTICE(( "connect failures rotate relays: ok" ));

  /* A relay that accepts TCP but rejects the bootstrap also rotates
     after 3 attempts */
  srv_t * relays2[2] = { srv, srv+1 };
  sess = sess_create( 2UL, relays2, NULL, key_pub[ 0 ] );
  for( ulong fail=1UL; fail<=3UL; fail++ ) {
    FD_TEST( sess->relay_idx==0UL );
    srv_accept( srv, sess, now );
    srv_expect( srv, sess, now, vec( "boot_client_hello" )->payload, 44UL );
    srv_send_vec( srv, "boot_rejected_unknownidentity" );
    poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
    FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_REJECTED ]==fail );
    now += FD_GRAVITY_SESS_REJECT_BACKOFF_NS;
  }
  FD_TEST( sess->relay_idx==1UL );
  bootstrap( srv+1, sess, 0UL, now, NULL, 0UL );
  /* A READY session that drops does not count as a failure */
  srv_drop( srv+1 );
  poll_until( sess, now, FD_GRAVITY_SESS_STATE_IDLE );
  FD_TEST( sess->relay_idx==1UL && !sess->connect_fail_cnt );
  sess_destroy( sess, now );
  srv_drop( srv );
  FD_LOG_NOTICE(( "bootstrap failures rotate relays: ok" ));
}

static void
test_connect_timeout( long now ) {
  /* A listener whose accept queue is full drops SYNs, so the connect
     stays pending until the session's connect timeout. */
  srv_t * s = srv+1;
  FD_TEST( !close( s->lfd ) );
  srv_listen( s, 0 );
  int filler = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( filler>=0 );
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = fd_ushort_bswap( s->port ), .sin_addr.s_addr = FD_IP4_ADDR( 127, 0, 0, 1 ) };
  FD_TEST( !connect( filler, fd_type_pun_const( &addr ), sizeof(addr) ) );

  srv_t * relays[1] = { s };
  fd_gravity_sess_t * sess = sess_create( 1UL, relays, NULL, key_pub[ 0 ] );
  FD_TEST( fd_gravity_sess_poll( sess, now ) );
  for( ulong i=0UL; i<20UL && sess->state==FD_GRAVITY_SESS_STATE_CONNECTING; i++ ) { fd_gravity_sess_poll( sess, now ); nap(); }
  if( FD_UNLIKELY( sess->state!=FD_GRAVITY_SESS_STATE_CONNECTING ) ) {
    FD_LOG_WARNING(( "kernel completed or refused the connect to a full listener (state %i), skipping", sess->state ));
  } else {
    fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_CONNECT_NS-1L );
    FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_CONNECTING );
    fd_gravity_sess_poll( sess, now+FD_GRAVITY_SESS_CONNECT_NS );
    FD_TEST( sess->state==FD_GRAVITY_SESS_STATE_IDLE );
    FD_TEST( sess->reset_cnt[ FD_GRAVITY_SESS_RESET_CONNECT ]==1UL );
    FD_TEST( sess->deadline==now+FD_GRAVITY_SESS_CONNECT_NS+FD_GRAVITY_SESS_RECONNECT_NS );
    FD_LOG_NOTICE(( "connect timeout: ok" ));
  }
  sess_destroy( sess, now );
  FD_TEST( !close( filler ) );
}

static void
test_new( void ) {
  uint   ip4 [ 5 ] = { 0 };
  ushort port[ 5 ] = { 0 };
  fd_gravity_handshake_t hs = { .version = "v", .num_threads = 1 };
  uchar const * id = key_pub[ 0 ];
  FD_TEST( !fd_gravity_sess_new( NULL,         RX_MAX, TX_MAX, id, 1UL, ip4, port, &hs ) );
  FD_TEST( !fd_gravity_sess_new( sess_mem+1,   RX_MAX, TX_MAX, id, 1UL, ip4, port, &hs ) );
  FD_TEST( !fd_gravity_sess_new( sess_mem,     RX_MAX, TX_MAX, id, 0UL, ip4, port, &hs ) );
  FD_TEST( !fd_gravity_sess_new( sess_mem,     RX_MAX, TX_MAX, id, 5UL, ip4, port, &hs ) );
  FD_TEST( !fd_gravity_sess_new( sess_mem,     4095UL, TX_MAX, id, 1UL, ip4, port, &hs ) );
  FD_TEST( !fd_gravity_sess_new( sess_mem,     RX_MAX, 4095UL, id, 1UL, ip4, port, &hs ) );
  hs.num_threads = 0;
  FD_TEST( !fd_gravity_sess_new( sess_mem,     RX_MAX, TX_MAX, id, 1UL, ip4, port, &hs ) );
  hs.num_threads = 1;
  fd_gravity_sess_t * sess = fd_gravity_sess_new( sess_mem, RX_MAX, TX_MAX, id, 4UL, ip4, port, &hs );
  FD_TEST( sess && sess->relay_cnt==4UL && !sess->deadline && sess->state==FD_GRAVITY_SESS_STATE_IDLE );
  /* The handshake carries the session identity, whatever hs had */
  FD_TEST( !memcmp( sess->handshake+4UL, id, 32UL ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_sha512_t _sha[1];
  sha = fd_sha512_join( fd_sha512_new( _sha ) );
  FD_TEST( sha );
  memcpy( key_seed[ 0 ], vec( "test_keypair_seed" )->payload, 32UL );
  for( ulong i=0UL; i<32UL; i++ ) {
    char const * hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    char b[3] = { hex[ 2UL*i ], hex[ 2UL*i+1UL ], '\0' };
    key_seed[ 1 ][ i ] = (uchar)strtoul( b, NULL, 16 );
  }
  for( ulong k=0UL; k<2UL; k++ ) FD_TEST( fd_ed25519_public_from_private( key_pub[ k ], key_seed[ k ], sha ) );
  FD_TEST( !memcmp( key_pub[ 0 ], vec( "boot_client_hello" )->payload+12UL, 32UL ) );
  FD_TEST( !memcmp( key_pub[ 1 ], vec( "boot_rfc8032_client_hello" )->payload+12UL, 32UL ) );

  srv_listen( srv+0, 16 );
  srv_listen( srv+1, 16 );

  long now = 1761436800000000000L;
  test_new();
  test_bootstrap_and_framing( now ); now += 1000L*SEC;
  test_resets( now );                now += 1000L*SEC;
  test_rotation( now );              now += 1000L*SEC;
  test_connect_timeout( now );

  FD_TEST( !close( srv[0].lfd ) );
  FD_TEST( !close( srv[1].lfd ) );
  fd_sha512_delete( fd_sha512_leave( sha ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
