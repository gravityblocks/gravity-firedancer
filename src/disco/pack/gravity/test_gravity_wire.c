/* test_gravity_wire drives every golden vector generated from the
   gravity-types crate the relay pins (fixtures/test_gravity_wire_vectors.h,
   see /tmp/gravity-env/wire-vectors/SPEC.md) through the C codec:

   - encoders: inputs are reconstructed from each vector's JSON field
     description and the output must match the payload byte for byte;
     the frame header must match the vector's frame.
   - decoders: relay frames are decoded and every field is checked
     against the JSON description.
   - NEG vectors: rejected wherever the Rust decoder rejects them, or the
     intentional difference is asserted (see test_neg).
   - robustness: every truncation and many single byte mutations of the
     valid relay payloads are decoded with the payload ending right
     before a PROT_NONE page, so an out of bounds read crashes. */

#include "fd_gravity_wire.h"
#include "../../../util/fd_util.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/sha512/fd_sha512.h"
#include "../../../flamenco/runtime/fd_runtime_err.h"
#include "fixtures/test_gravity_wire_vectors.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

/* Vector lookup with coverage tracking ********************************/

static int vec_used[ GRAVITY_WIRE_VEC_CNT ];

static struct gravity_wire_vec const *
vec( char const * name ) {
  for( ulong i=0UL; i<GRAVITY_WIRE_VEC_CNT; i++ ) {
    if( !strcmp( gravity_wire_vecs[ i ].name, name ) ) {
      vec_used[ i ] = 1;
      return gravity_wire_vecs+i;
    }
  }
  FD_LOG_ERR(( "missing vector %s", name ));
}

/* Minimal JSON field access.  The vector JSON has no whitespace, keys
   are unique enough to find by "key": and strings have no escapes in
   the fields read here. */

static char const *
jval( char const * p,
      char const * key ) {
  char pat[ 128 ];
  FD_TEST( fd_cstr_printf_check( pat, sizeof(pat), NULL, "\"%s\":", key ) );
  char const * r = strstr( p, pat );
  if( FD_UNLIKELY( !r ) ) FD_LOG_ERR(( "key %s not found in %s", key, p ));
  return r+strlen( pat );
}

static int
jnull( char const * v ) {
  return !strncmp( v, "null", 4UL );
}

static ulong
jnum( char const * v ) {
  FD_TEST( *v>='0' && *v<='9' );
  return strtoul( v, NULL, 10 );
}

static int
jbool( char const * v ) {
  if( !strncmp( v, "true", 4UL ) ) return 1;
  FD_TEST( !strncmp( v, "false", 5UL ) );
  return 0;
}

static uint
hexval( char c ) {
  if( c>='0' && c<='9' ) return (uint)( c-'0'    );
  if( c>='a' && c<='f' ) return (uint)( c-'a'+10 );
  FD_LOG_ERR(( "bad hex digit %c", c ));
}

/* jhex decodes the hex string at v into out[0,max) and returns a
   pointer past the closing quote. */

static char const *
jhex( char const * v,
      uchar *      out,
      ulong        max,
      ulong *      sz ) {
  FD_TEST( *v=='"' ); v++;
  ulong n = 0UL;
  while( *v!='"' ) {
    FD_TEST( n<max );
    out[ n++ ] = (uchar)( (hexval( v[0] )<<4) | hexval( v[1] ) );
    v += 2;
  }
  *sz = n;
  return v+1;
}

static void
jhex_exact( char const * json,
            char const * key,
            uchar *      out,
            ulong        sz ) {
  ulong got;
  jhex( jval( json, key ), out, sz, &got );
  FD_TEST( got==sz );
}

/* jstr copies the string at v into out (NUL terminated). */

static char const *
jstr( char const * v,
      char *       out,
      ulong        max ) {
  FD_TEST( *v=='"' ); v++;
  ulong n = 0UL;
  while( *v!='"' ) {
    FD_TEST( *v!='\\' );
    FD_TEST( n+1UL<max );
    out[ n++ ] = *v++;
  }
  out[ n ] = '\0';
  return v+1;
}

/* jhex_list decodes a JSON array of hex strings into out (each item at
   most item_max bytes, item i at out+i*item_max). */

static ulong
jhex_list( char const * v,
           uchar *      out,
           ulong        item_max,
           ulong *      item_sz,
           ulong        cnt_max ) {
  FD_TEST( *v=='[' ); v++;
  ulong n = 0UL;
  while( *v!=']' ) {
    FD_TEST( n<cnt_max );
    v = jhex( v, out+n*item_max, item_max, item_sz+n );
    n++;
    if( *v==',' ) v++;
  }
  return n;
}

/* Guarded buffer: data copied with guard_copy ends right before a
   PROT_NONE page, so a decoder reading past the end segfaults. */

static uchar * guard_lo;
static ulong   guard_sz;

static void
guard_init( void ) {
  ulong page = (ulong)sysconf( _SC_PAGESIZE );
  guard_sz = 16UL*page;
  void * m = mmap( NULL, guard_sz+page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( m!=MAP_FAILED );
  guard_lo = (uchar *)m;
  FD_TEST( !mprotect( guard_lo+guard_sz, page, PROT_NONE ) );
}

static uchar const *
guard_copy( void const * p,
            ulong        sz ) {
  FD_TEST( sz<=guard_sz );
  uchar * dst = guard_lo+guard_sz-sz;
  if( sz ) memcpy( dst, p, sz );
  return dst;
}

/* REASON vectors *******************************************************/

/* reason_wire returns the NotIncludedReason wire tag of the reason
   with the given (upper case) name, from the REASON vectors. */

static uint
reason_wire( char const * name ) {
  for( ulong i=0UL; i<GRAVITY_WIRE_VEC_CNT; i++ ) {
    struct gravity_wire_vec const * v = gravity_wire_vecs+i;
    if( strcmp( v->kind, "REASON" ) ) continue;
    char n[ 64 ];
    jstr( jval( v->json, "name" ), n, sizeof(n) );
    if( strcmp( n, name ) ) continue;
    vec_used[ i ] = 1;
    uint wire = (uint)jnum( jval( v->json, "wire_tag" ) );
    FD_TEST( v->payload_sz==4UL );
    FD_TEST( FD_LOAD( uint, v->payload )==wire );
    return wire;
  }
  FD_LOG_ERR(( "no REASON vector for %s", name ));
}

/* Encoder harness ******************************************************/

typedef ulong (*enc_fn_t)( uchar * buf, ulong buf_sz, void const * ctx );

static uchar enc_buf[ 1UL<<16 ];
static int   enc_tag_seen[ 16 ];

/* check_enc runs fn into a large buffer and requires the result to
   match vector v byte for byte (and the frame header to match the
   vector's frame).  It then requires every smaller buffer to be
   refused without writing past its end. */

static void
check_enc( struct gravity_wire_vec const * v,
           enc_fn_t                        fn,
           void const *                    ctx ) {
  ulong sz = fn( enc_buf, sizeof(enc_buf), ctx );
  if( FD_UNLIKELY( sz!=v->payload_sz || memcmp( enc_buf, v->payload, sz ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "got",  enc_buf,    sz            ));
    FD_LOG_HEXDUMP_WARNING(( "want", v->payload, v->payload_sz ));
    FD_LOG_ERR(( "encoder mismatch for %s", v->name ));
  }

  FD_TEST( v->frame && v->frame_sz==sz+FD_GRAVITY_FRAME_HDR_SZ );
  uchar hdr[ FD_GRAVITY_FRAME_HDR_SZ ];
  fd_gravity_frame_hdr_write( hdr, sz, GRAVITY_WIRE_VEC_SEND_TS );
  FD_TEST( !memcmp( hdr, v->frame, FD_GRAVITY_FRAME_HDR_SZ ) );
  FD_TEST( !memcmp( v->frame+FD_GRAVITY_FRAME_HDR_SZ, enc_buf, sz ) );

  if( strcmp( v->kind, "BOOT" ) ) {
    uint tag = FD_LOAD( uint, enc_buf );
    FD_TEST( tag<16U );
    enc_tag_seen[ tag ] = 1;
  }

  for( ulong buf_sz=0UL; buf_sz<sz; buf_sz++ ) {
    memset( enc_buf, 0xa5, sz+16UL );
    FD_TEST( !fn( enc_buf, buf_sz, ctx ) );
    for( ulong i=buf_sz; i<sz+16UL; i++ ) FD_TEST( enc_buf[ i ]==0xa5 );
  }
}

static ulong
enc_client_hello( uchar *      buf,
                  ulong        buf_sz,
                  void const * ctx ) {
  return fd_gravity_encode_client_hello( buf, buf_sz, ctx );
}

static ulong
enc_auth_proof( uchar *      buf,
                ulong        buf_sz,
                void const * ctx ) {
  return fd_gravity_encode_auth_proof( buf, buf_sz, ctx );
}

static ulong
enc_handshake( uchar *      buf,
               ulong        buf_sz,
               void const * ctx ) {
  return fd_gravity_encode_handshake_v2( buf, buf_sz, ctx );
}

static ulong
enc_progress( uchar *      buf,
              ulong        buf_sz,
              void const * ctx ) {
  return fd_gravity_encode_progress( buf, buf_sz, ctx );
}

static ulong
enc_pong( uchar *      buf,
          ulong        buf_sz,
          void const * ctx ) {
  return fd_gravity_encode_pong( buf, buf_sz, *(ulong const *)ctx );
}

struct txn_args {
  uchar const * txn;
  ulong         txn_sz;
  ulong         sent_at;
  ulong         received_at;
  uchar const * src_addr;
  char const *  source_uri;
};

static ulong
enc_txn( uchar *      buf,
         ulong        buf_sz,
         void const * ctx ) {
  struct txn_args const * a = ctx;
  return fd_gravity_encode_transaction( buf, buf_sz, a->txn, a->txn_sz, a->sent_at, a->received_at, a->src_addr, a->source_uri );
}

struct bundle_args {
  uchar const *         ext_uuid;
  ulong                 txn_cnt;
  uchar const * const * txn;
  ulong const *         txn_sz;
  char const *          source_uri;
  ulong                 received_at;
  ulong                 sent_at;
};

static ulong
enc_bundle( uchar *      buf,
            ulong        buf_sz,
            void const * ctx ) {
  struct bundle_args const * a = ctx;
  return fd_gravity_encode_bundle_v2( buf, buf_sz, a->ext_uuid, a->txn_cnt, a->txn, a->txn_sz, a->source_uri, a->received_at, a->sent_at );
}

static ulong
enc_exec( uchar *      buf,
          ulong        buf_sz,
          void const * ctx ) {
  return fd_gravity_encode_exec_result( buf, buf_sz, ctx );
}

/* Frames ***************************************************************/

static void
test_frames( void ) {
  ulong framed = 0UL;
  for( ulong i=0UL; i<GRAVITY_WIRE_VEC_CNT; i++ ) {
    struct gravity_wire_vec const * v = gravity_wire_vecs+i;
    int is_msg = !strcmp( v->kind, "BOOT" ) || !strcmp( v->kind, "C2R" ) || !strcmp( v->kind, "R2C" );
    FD_TEST( is_msg==!!v->frame );
    if( !v->frame ) continue;
    FD_TEST( v->frame_sz==v->payload_sz+FD_GRAVITY_FRAME_HDR_SZ );
    uchar hdr[ FD_GRAVITY_FRAME_HDR_SZ ];
    fd_gravity_frame_hdr_write( hdr, v->payload_sz, GRAVITY_WIRE_VEC_SEND_TS );
    FD_TEST( !memcmp( hdr, v->frame, FD_GRAVITY_FRAME_HDR_SZ ) );
    FD_TEST( fd_gravity_frame_hdr_payload_sz( v->frame )==v->payload_sz );
    FD_TEST( FD_LOAD( ulong, v->frame+4UL )==GRAVITY_WIRE_VEC_SEND_TS );
    FD_TEST( !memcmp( v->frame+FD_GRAVITY_FRAME_HDR_SZ, v->payload, v->payload_sz ) );
    framed++;
  }
  FD_TEST( framed>=50UL );

  /* keepalive and maximum size headers */
  uchar hdr[ FD_GRAVITY_FRAME_HDR_SZ ];
  fd_gravity_frame_hdr_write( hdr, 0UL, 0UL );
  for( ulong i=0UL; i<FD_GRAVITY_FRAME_HDR_SZ; i++ ) FD_TEST( !hdr[ i ] );
  fd_gravity_frame_hdr_write( hdr, FD_GRAVITY_FRAME_MAX, ULONG_MAX );
  FD_TEST( fd_gravity_frame_hdr_payload_sz( hdr )==FD_GRAVITY_FRAME_MAX );
  FD_TEST( FD_LOAD( ulong, hdr+4UL )==ULONG_MAX );
  FD_LOG_NOTICE(( "frames: %lu framed vectors ok", framed ));
}

/* Bootstrap and auth ***************************************************/

static void
test_bootstrap( fd_sha512_t * sha ) {
  /* Test identity: seed 07*32 */
  struct gravity_wire_vec const * seed_v = vec( "test_keypair_seed" );
  FD_TEST( seed_v->payload_sz==32UL );
  uchar identity[ 32 ];
  jhex_exact( seed_v->json, "pubkey_hex", identity, 32UL );
  uchar pub[ 32 ];
  FD_TEST( fd_ed25519_public_from_private( pub, seed_v->payload, sha )==pub );
  FD_TEST( !memcmp( pub, identity, 32UL ) );

  /* ClientHello */
  struct gravity_wire_vec const * hello_v = vec( "boot_client_hello" );
  uchar hello_id[ 32 ];
  jhex_exact( hello_v->json, "identity", hello_id, 32UL );
  FD_TEST( !memcmp( hello_id, identity, 32UL ) );
  FD_TEST( jnum( jval( hello_v->json, "tag" ) )==FD_GRAVITY_BOOT_CLIENT_HELLO );
  check_enc( hello_v, enc_client_hello, hello_id );

  /* ServerHello decode */
  struct gravity_wire_vec const * sh_v = vec( "boot_server_hello" );
  uchar want_challenge[ 32 ];
  jhex_exact( sh_v->json, "challenge", want_challenge, 32UL );
  uint  tag    = 99U;
  uint  reason = 99U;
  uchar challenge[ 32 ];
  FD_TEST( !fd_gravity_decode_bootstrap( sh_v->payload, sh_v->payload_sz, &tag, challenge, &reason ) );
  FD_TEST( tag==FD_GRAVITY_BOOT_SERVER_HELLO );
  FD_TEST( tag==jnum( jval( sh_v->json, "tag" ) ) );
  FD_TEST( !memcmp( challenge, want_challenge, 32UL ) );

  /* Auth message from the decoded challenge */
  struct gravity_wire_vec const * msg_v = vec( "auth_message" );
  uchar msg_id[ 32 ]; uchar msg_challenge[ 32 ];
  jhex_exact( msg_v->json, "identity",  msg_id,        32UL );
  jhex_exact( msg_v->json, "challenge", msg_challenge, 32UL );
  FD_TEST( !memcmp( msg_id, identity, 32UL ) && !memcmp( msg_challenge, challenge, 32UL ) );
  uchar msg[ FD_GRAVITY_AUTH_MSG_SZ ];
  fd_gravity_auth_msg( msg, identity, challenge );
  FD_TEST( msg_v->payload_sz==FD_GRAVITY_AUTH_MSG_SZ );
  FD_TEST( !memcmp( msg, msg_v->payload, FD_GRAVITY_AUTH_MSG_SZ ) );

  /* Signature: verify the vector, re-sign deterministically */
  struct gravity_wire_vec const * sig_v = vec( "auth_signature" );
  FD_TEST( sig_v->payload_sz==64UL );
  FD_TEST( fd_ed25519_verify( msg, FD_GRAVITY_AUTH_MSG_SZ, sig_v->payload, identity, sha )==FD_ED25519_SUCCESS );
  uchar sig[ 64 ];
  FD_TEST( fd_ed25519_sign( sig, msg, FD_GRAVITY_AUTH_MSG_SZ, pub, seed_v->payload, sha )==sig );
  FD_TEST( !memcmp( sig, sig_v->payload, 64UL ) );
  uchar bad_msg[ FD_GRAVITY_AUTH_MSG_SZ ];
  memcpy( bad_msg, msg, FD_GRAVITY_AUTH_MSG_SZ );
  bad_msg[ FD_GRAVITY_AUTH_MSG_SZ-1UL ] ^= 1;
  FD_TEST( fd_ed25519_verify( bad_msg, FD_GRAVITY_AUTH_MSG_SZ, sig, identity, sha )!=FD_ED25519_SUCCESS );

  /* AuthProof */
  struct gravity_wire_vec const * proof_v = vec( "boot_auth_proof" );
  uchar proof_sig[ 64 ];
  jhex_exact( proof_v->json, "signature", proof_sig, 64UL );
  FD_TEST( !memcmp( proof_sig, sig, 64UL ) );
  check_enc( proof_v, enc_auth_proof, sig );

  /* RFC 8032 TEST 1 key, independent of the generator's key */
  struct gravity_wire_vec const * rmsg_v = vec( "rfc8032_auth_message" );
  uchar rseed[ 32 ]; uchar rid[ 32 ]; uchar rchallenge[ 32 ];
  jhex_exact( rmsg_v->json, "secret_seed", rseed,      32UL );
  jhex_exact( rmsg_v->json, "identity",    rid,        32UL );
  jhex_exact( rmsg_v->json, "challenge",   rchallenge, 32UL );
  FD_TEST( fd_ed25519_public_from_private( pub, rseed, sha )==pub );
  FD_TEST( !memcmp( pub, rid, 32UL ) );
  fd_gravity_auth_msg( msg, rid, rchallenge );
  FD_TEST( !memcmp( msg, rmsg_v->payload, FD_GRAVITY_AUTH_MSG_SZ ) );
  struct gravity_wire_vec const * rsig_v = vec( "rfc8032_auth_signature" );
  FD_TEST( fd_ed25519_verify( msg, FD_GRAVITY_AUTH_MSG_SZ, rsig_v->payload, rid, sha )==FD_ED25519_SUCCESS );
  FD_TEST( fd_ed25519_sign( sig, msg, FD_GRAVITY_AUTH_MSG_SZ, pub, rseed, sha )==sig );
  FD_TEST( !memcmp( sig, rsig_v->payload, 64UL ) );

  struct gravity_wire_vec const * rhello_v = vec( "boot_rfc8032_client_hello" );
  jhex_exact( rhello_v->json, "identity", hello_id, 32UL );
  FD_TEST( !memcmp( hello_id, rid, 32UL ) );
  check_enc( rhello_v, enc_client_hello, rid );
  struct gravity_wire_vec const * rproof_v = vec( "boot_rfc8032_auth_proof" );
  jhex_exact( rproof_v->json, "signature", proof_sig, 64UL );
  FD_TEST( !memcmp( proof_sig, sig, 64UL ) );
  check_enc( rproof_v, enc_auth_proof, sig );

  /* Accepted / Rejected decode */
  struct gravity_wire_vec const * acc_v = vec( "boot_accepted" );
  tag = 99U;
  FD_TEST( !fd_gravity_decode_bootstrap( acc_v->payload, acc_v->payload_sz, &tag, challenge, &reason ) );
  FD_TEST( tag==FD_GRAVITY_BOOT_ACCEPTED && tag==jnum( jval( acc_v->json, "tag" ) ) );

  static struct { char const * name; char const * reason; uint want; } const rej[] = {
    { "boot_rejected_invalidhello",    "InvalidHello",    FD_GRAVITY_REJECT_INVALID_HELLO    },
    { "boot_rejected_unknownidentity", "UnknownIdentity", FD_GRAVITY_REJECT_UNKNOWN_IDENTITY },
    { "boot_rejected_invalidproof",    "InvalidProof",    FD_GRAVITY_REJECT_INVALID_PROOF    },
    { "boot_rejected_timeout",         "Timeout",         FD_GRAVITY_REJECT_TIMEOUT          },
  };
  for( ulong i=0UL; i<sizeof(rej)/sizeof(rej[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( rej[ i ].name );
    char name[ 32 ];
    jstr( jval( v->json, "reason" ), name, sizeof(name) );
    FD_TEST( !strcmp( name, rej[ i ].reason ) );
    FD_TEST( jnum( jval( v->json, "reason_tag" ) )==rej[ i ].want );
    tag = 99U; reason = 99U;
    FD_TEST( !fd_gravity_decode_bootstrap( v->payload, v->payload_sz, &tag, challenge, &reason ) );
    FD_TEST( tag==FD_GRAVITY_BOOT_REJECTED && tag==jnum( jval( v->json, "tag" ) ) );
    FD_TEST( reason==rej[ i ].want );
  }

  /* Every truncation of a relay bootstrap frame is rejected */
  static char const * const relay_boot[] = {
    "boot_server_hello", "boot_accepted", "boot_rejected_invalidhello", "boot_rejected_unknownidentity",
    "boot_rejected_invalidproof", "boot_rejected_timeout"
  };
  for( ulong i=0UL; i<sizeof(relay_boot)/sizeof(relay_boot[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( relay_boot[ i ] );
    for( ulong sz=0UL; sz<v->payload_sz; sz++ ) {
      FD_TEST( fd_gravity_decode_bootstrap( guard_copy( v->payload, sz ), sz, &tag, challenge, &reason )==-1 );
    }
    FD_TEST( !fd_gravity_decode_bootstrap( guard_copy( v->payload, v->payload_sz ), v->payload_sz, &tag, challenge, &reason ) );
  }

  /* Frames only a connector sends are not valid relay bootstrap frames
     (the Rust decode_bootstrap_frame decodes them, but the Rust
     connector disconnects on them as unexpected, as the C client
     does). */
  static char const * const client_boot[] = {
    "boot_client_hello", "boot_auth_proof", "boot_rfc8032_client_hello", "boot_rfc8032_auth_proof"
  };
  for( ulong i=0UL; i<sizeof(client_boot)/sizeof(client_boot[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( client_boot[ i ] );
    FD_TEST( fd_gravity_decode_bootstrap( v->payload, v->payload_sz, &tag, challenge, &reason )==-1 );
  }
  FD_LOG_NOTICE(( "bootstrap: ok" ));
}

/* HandshakeV2 **********************************************************/

static void
test_handshake( void ) {
  static char const * const names[] = { "c2r_handshake_v2_basic", "c2r_handshake_v2_blacklist", "c2r_handshake_v2_maxthreads" };
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( names[ i ] );
    FD_TEST( jnum( jval( v->json, "tag" ) )==FD_GRAVITY_C2R_HANDSHAKE_V2 );
    static uchar bl[ 16UL*32UL ];
    ulong        bl_sz[ 16 ];
    char         version[ 128 ];
    fd_gravity_handshake_t hs = {0};
    jhex_exact( v->json, "identity", hs.identity, 32UL );
    jstr( jval( v->json, "conn_version" ), version, sizeof(version) );
    hs.version             = version;
    hs.num_threads         = (uchar)jnum( jval( v->json, "num_threads" ) );
    hs.filter_ofac         = jbool( jval( v->json, "filter_ofac" ) );
    hs.blacklist_cnt       = jhex_list( jval( v->json, "blacklisted_accounts" ), bl, 32UL, bl_sz, 16UL );
    hs.blacklist           = bl;
    hs.jito_tip_weight_bps = (ushort)jnum( jval( v->json, "jito_tip_weight_bps" ) );
    for( ulong j=0UL; j<hs.blacklist_cnt; j++ ) FD_TEST( bl_sz[ j ]==32UL );
    check_enc( v, enc_handshake, &hs );

    /* NULL version is the same as "" and blacklist may be NULL when empty */
    if( !version[0] ) {
      hs.version = NULL;
      check_enc( v, enc_handshake, &hs );
    }
    if( !hs.blacklist_cnt ) {
      hs.blacklist = NULL;
      check_enc( v, enc_handshake, &hs );
    }
  }

  /* Legacy Handshake (tag 0) is never sent by this client: check it is
     the identity, version and flags of the basic V2 layout. */
  struct gravity_wire_vec const * legacy = vec( "c2r_handshake_v1_legacy" );
  FD_TEST( FD_LOAD( uint, legacy->payload )==0U );
  FD_TEST( jnum( jval( legacy->json, "tag" ) )==0UL );

  /* Out of range input is refused */
  fd_gravity_handshake_t hs = { .version = "v", .num_threads = 1, .jito_tip_weight_bps = 10000 };
  FD_TEST( fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  hs.num_threads = 0;
  FD_TEST( !fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  hs.num_threads = 1;
  hs.jito_tip_weight_bps = 10001;
  FD_TEST( !fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  hs.jito_tip_weight_bps = USHORT_MAX;
  FD_TEST( !fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  hs.jito_tip_weight_bps = 0;
  static uchar bl[ 17UL*32UL ];
  hs.blacklist     = bl;
  hs.blacklist_cnt = 16UL;
  FD_TEST( fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs )==56UL+1UL+16UL*32UL );
  hs.blacklist_cnt = 17UL;
  FD_TEST( !fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  hs.blacklist_cnt = 1UL;
  hs.blacklist     = NULL;
  FD_TEST( !fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  hs.blacklist_cnt = 0UL;
  hs.version = "\xff";
  FD_TEST( !fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  hs.version = "fd-gravity/\xc3\xa9\xe2\x82\xac\xf0\x9d\x84\x9e"; /* e-acute, euro, G clef */
  FD_TEST( fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  FD_LOG_NOTICE(( "handshake: ok" ));
}

/* Progress *************************************************************/

static void
progress_from_json( char const *            json,
                    fd_gravity_progress_t * p ) {
  memset( p, 0, sizeof(fd_gravity_progress_t) );
  p->slot                  = jnum( jval( json, "slot_num" ) );
  p->observed_at           = jnum( jval( json, "observed_at" ) );
  p->current_slot_progress = (uchar)jnum( jval( json, "current_slot_progress" ) );
  char const * o = jval( json, "slot_duration_override_ms" );
  if( !jnull( o ) ) { p->has_duration_override = 1; p->duration_override_ms = jnum( o ); }
  char const * n = jval( json, "next_leadership" );
  if( !jnull( n ) ) {
    p->has_next_leadership   = 1;
    p->next_leadership_start = jnum( jval( n, "start" ) );
    p->next_leadership_end   = jnum( jval( n, "end"   ) );
  }
  char const * b = jval( json, "latest_blockhash" );
  if( !jnull( b ) ) {
    ulong sz;
    jhex( b, p->latest_blockhash, 32UL, &sz );
    FD_TEST( sz==32UL );
    p->has_latest_blockhash = 1;
  }
}

static void
test_progress( void ) {
  static char const * const names[] = {
    "c2r_progress_all_none", "c2r_progress_all_some", "c2r_progress_leader_no_override", "c2r_progress_max"
  };
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( names[ i ] );
    FD_TEST( jnum( jval( v->json, "tag" ) )==FD_GRAVITY_C2R_PROGRESS );
    fd_gravity_progress_t p;
    progress_from_json( v->json, &p );
    check_enc( v, enc_progress, &p );
  }

  /* All 8 combinations of the optional fields: the expected bytes are
     spliced from the all_some vector (tag, slot, observed_at, progress
     = 21 bytes, then override = 01+8, next = 01+16, blockhash = 01+32). */
  struct gravity_wire_vec const * all = vec( "c2r_progress_all_some" );
  FD_TEST( all->payload_sz==80UL );
  fd_gravity_progress_t base;
  progress_from_json( all->json, &base );
  for( uint combo=0U; combo<8U; combo++ ) {
    uchar want[ 80 ];
    ulong want_sz = 21UL;
    memcpy( want, all->payload, 21UL );
    if( combo&1U ) { memcpy( want+want_sz, all->payload+21UL, 9UL  ); want_sz += 9UL;  } else want[ want_sz++ ] = 0;
    if( combo&2U ) { memcpy( want+want_sz, all->payload+30UL, 17UL ); want_sz += 17UL; } else want[ want_sz++ ] = 0;
    if( combo&4U ) { memcpy( want+want_sz, all->payload+47UL, 33UL ); want_sz += 33UL; } else want[ want_sz++ ] = 0;
    fd_gravity_progress_t p = base;
    /* Non-zero flags other than 1 still encode the option tag as 1
       (neg_c2r_progress_ffioption_tag_2 can't be produced). */
    p.has_duration_override = (combo&1U) ? 2  : 0;
    p.has_next_leadership   = (combo&2U) ? -1 : 0;
    p.has_latest_blockhash  = (combo&4U) ? 7  : 0;
    ulong sz = fd_gravity_encode_progress( enc_buf, sizeof(enc_buf), &p );
    FD_TEST( sz==want_sz && !memcmp( enc_buf, want, sz ) );
    for( ulong buf_sz=0UL; buf_sz<sz; buf_sz++ ) FD_TEST( !fd_gravity_encode_progress( enc_buf, buf_sz, &p ) );
  }

  fd_gravity_progress_t p = base;
  p.current_slot_progress = 100;
  FD_TEST( fd_gravity_encode_progress( enc_buf, sizeof(enc_buf), &p ) );
  p.current_slot_progress = 101;
  FD_TEST( !fd_gravity_encode_progress( enc_buf, sizeof(enc_buf), &p ) );
  p.current_slot_progress = 255;
  FD_TEST( !fd_gravity_encode_progress( enc_buf, sizeof(enc_buf), &p ) );
  FD_LOG_NOTICE(( "progress: ok" ));
}

/* Pong *****************************************************************/

static void
test_pong( void ) {
  static char const * const names[] = { "c2r_pong_0", "c2r_pong_7", "c2r_pong_max" };
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( names[ i ] );
    FD_TEST( jnum( jval( v->json, "tag" ) )==FD_GRAVITY_C2R_PONG );
    ulong seq = jnum( jval( v->json, "seq" ) );
    check_enc( v, enc_pong, &seq );
  }
  FD_LOG_NOTICE(( "pong: ok" ));
}

/* Transaction **********************************************************/

static uchar txn_store[ 8 ][ 4096 ];
static ulong txn_store_sz[ 8 ];

static void
test_transaction( void ) {
  static struct { char const * name; char const * raw; } const tv[] = {
    { "c2r_transaction_tpu",             "tx_legacy" },
    { "c2r_transaction_block_engine_v0", "tx_v0"     },
    { "c2r_transaction_v1_uri64",        "tx_v1"     },
  };
  for( ulong i=0UL; i<sizeof(tv)/sizeof(tv[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( tv[ i ].name );
    FD_TEST( jnum( jval( v->json, "tag" ) )==FD_GRAVITY_C2R_TRANSACTION );
    uchar * txn = txn_store[ 0 ];
    ulong   txn_sz;
    jhex( jval( v->json, "tx" ), txn, 4096UL, &txn_sz );
    struct gravity_wire_vec const * raw = vec( tv[ i ].raw );
    FD_TEST( raw->payload_sz==txn_sz && !memcmp( raw->payload, txn, txn_sz ) );
    uchar src[ 16 ];
    jhex_exact( v->json, "src_addr", src, 16UL );
    char uri[ 128 ];
    char const * uv = jval( v->json, "source_uri" );
    int has_uri = !jnull( uv );
    if( has_uri ) jstr( uv, uri, sizeof(uri) );
    struct txn_args a = {
      .txn         = txn,
      .txn_sz      = txn_sz,
      .sent_at     = jnum( jval( v->json, "sent_at" ) ),
      .received_at = jnum( jval( v->json, "received_at" ) ),
      .src_addr    = src,
      .source_uri  = has_uri ? uri : NULL,
    };
    check_enc( v, enc_txn, &a );

    /* An all zero source address may be passed as NULL */
    int zero_src = 1;
    for( ulong j=0UL; j<16UL; j++ ) zero_src &= !src[ j ];
    if( zero_src ) {
      a.src_addr = NULL;
      check_enc( v, enc_txn, &a );
      a.src_addr = src;
    }

    /* The other source_uri option, spliced from the vector */
    uchar want[ 512 ];
    ulong want_sz;
    if( has_uri ) {
      ulong uri_sz = strlen( uri );
      want_sz = v->payload_sz-1UL-8UL-uri_sz;
      memcpy( want, v->payload, want_sz );
      FD_TEST( v->payload[ want_sz ]==1 );
      want[ want_sz++ ] = 0;
      a.source_uri = NULL;
    } else {
      want_sz = v->payload_sz;
      memcpy( want, v->payload, want_sz );
      FD_TEST( want[ want_sz-1UL ]==0 );
      want[ want_sz-1UL ] = 1;
      FD_STORE( ulong, want+want_sz, 3UL );
      memcpy( want+want_sz+8UL, "abc", 3UL );
      want_sz += 11UL;
      a.source_uri = "abc";
    }
    ulong sz = fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), a.txn, a.txn_sz, a.sent_at, a.received_at, a.src_addr, a.source_uri );
    FD_TEST( sz==want_sz && !memcmp( enc_buf, want, sz ) );
  }

  /* Refused input */
  struct gravity_wire_vec const * raw = vec( "tx_legacy" );
  char uri[ 80 ];
  memset( uri, 'u', 65UL ); uri[ 65 ] = '\0';
  FD_TEST( !fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), raw->payload, raw->payload_sz, 0UL, 0UL, NULL, uri ) );
  uri[ 64 ] = '\0';
  FD_TEST( fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), raw->payload, raw->payload_sz, 0UL, 0UL, NULL, uri ) );
  FD_TEST( !fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), raw->payload, 0UL, 0UL, 0UL, NULL, NULL ) );
  static char const * const bad_utf8[] = {
    "\xff", "\x80", "abc\xc0\x80", "\xc1\xbf", "\xe0\x80\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80",
    "\xf8\x88\x80\x80\x80", "\xe2\x82", "x\xf0\x9d\x84", "\xc3\x28"
  };
  for( ulong i=0UL; i<sizeof(bad_utf8)/sizeof(bad_utf8[0]); i++ ) {
    FD_TEST( !fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), raw->payload, raw->payload_sz, 0UL, 0UL, NULL, bad_utf8[ i ] ) );
  }
  static char const * const good_utf8[] = {
    "", "https://mainnet.block-engine.jito.wtf", "\x7f", "\xc2\x80", "\xdf\xbf", "\xe0\xa0\x80", "\xed\x9f\xbf",
    "\xee\x80\x80", "\xef\xbf\xbf", "\xf0\x90\x80\x80", "\xf4\x8f\xbf\xbf"
  };
  for( ulong i=0UL; i<sizeof(good_utf8)/sizeof(good_utf8[0]); i++ ) {
    FD_TEST( fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), raw->payload, raw->payload_sz, 0UL, 0UL, NULL, good_utf8[ i ] ) );
  }
  FD_LOG_NOTICE(( "transaction: ok" ));
}

/* BundleV2 *************************************************************/

static void
test_bundle( void ) {
  static char const * const names[] = { "c2r_bundle_v2_one_tx", "c2r_bundle_v2_five_txs_empty_uri" };
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( names[ i ] );
    FD_TEST( jnum( jval( v->json, "tag" ) )==FD_GRAVITY_C2R_BUNDLE_V2 );
    uchar ext_uuid[ 32 ];
    jhex_exact( v->json, "ext_uuid", ext_uuid, 32UL );
    ulong cnt = jhex_list( jval( v->json, "txs" ), txn_store[ 0 ], 4096UL, txn_store_sz, 8UL );
    uchar const * txn[ 8 ];
    for( ulong j=0UL; j<cnt; j++ ) txn[ j ] = txn_store[ j ];
    char uri[ 128 ];
    jstr( jval( v->json, "source_uri" ), uri, sizeof(uri) );
    struct bundle_args a = {
      .ext_uuid    = ext_uuid,
      .txn_cnt     = cnt,
      .txn         = txn,
      .txn_sz      = txn_store_sz,
      .source_uri  = uri,
      .received_at = jnum( jval( v->json, "received_at" ) ),
      .sent_at     = jnum( jval( v->json, "sent_at" ) ),
    };
    check_enc( v, enc_bundle, &a );
  }

  /* Refused input */
  struct gravity_wire_vec const * raw = vec( "tx_legacy" );
  uchar const * txn[ 6 ];
  ulong         txn_sz[ 6 ];
  for( ulong j=0UL; j<6UL; j++ ) { txn[ j ] = raw->payload; txn_sz[ j ] = raw->payload_sz; }
  uchar uuid[ 32 ] = {0};
  FD_TEST(  fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), uuid, 5UL, txn, txn_sz, "", 0UL, 0UL ) );
  FD_TEST( !fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), uuid, 6UL, txn, txn_sz, "", 0UL, 0UL ) );
  FD_TEST( !fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), uuid, 0UL, txn, txn_sz, "", 0UL, 0UL ) );
  FD_TEST( !fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), uuid, 1UL, txn, txn_sz, NULL, 0UL, 0UL ) );
  FD_TEST( !fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), uuid, 1UL, txn, txn_sz, "\xff", 0UL, 0UL ) );
  char uri[ 80 ];
  memset( uri, 'u', 65UL ); uri[ 65 ] = '\0';
  FD_TEST( !fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), uuid, 1UL, txn, txn_sz, uri, 0UL, 0UL ) );
  uri[ 64 ] = '\0';
  FD_TEST(  fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), uuid, 1UL, txn, txn_sz, uri, 0UL, 0UL ) );
  txn_sz[ 2 ] = 0UL;
  FD_TEST( !fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), uuid, 3UL, txn, txn_sz, "", 0UL, 0UL ) );
  FD_LOG_NOTICE(( "bundle: ok" ));
}

/* ExecutionResult ******************************************************/

static ulong
results_from_json( char const *          json,
                   fd_gravity_result_t * res,
                   ulong                 res_max ) {
  char const * v = jval( json, "results" );
  FD_TEST( *v++=='[' );
  ulong n = 0UL;
  while( *v!=']' ) {
    FD_TEST( n<res_max );
    FD_TEST( *v++=='{' );
    memset( res+n, 0, sizeof(fd_gravity_result_t) );
    if( !strncmp( v, "\"Included\":", 11UL ) ) {
      res[ n ].kind = FD_GRAVITY_RESULT_INCLUDED;
      res[ n ].cus  = jnum( jval( v, "cost_units"     ) );
      res[ n ].slot = jnum( jval( v, "execution_slot" ) );
      v = strstr( v, "}}" );
      FD_TEST( v );
      v += 2;
    } else {
      FD_TEST( !strncmp( v, "\"NotIncluded\":", 14UL ) );
      char name[ 64 ];
      v = jstr( v+14, name, sizeof(name) );
      res[ n ].kind   = FD_GRAVITY_RESULT_NOT_INCLUDED;
      res[ n ].reason = reason_wire( name );
      FD_TEST( *v++=='}' );
    }
    n++;
    if( *v==',' ) v++;
  }
  return n;
}

static void
test_exec_result( void ) {
  static char const * const names[] = {
    "c2r_exec_tx_included", "c2r_exec_tx_instruction_error", "c2r_exec_bundle_ok", "c2r_exec_bundle_failed_mid",
    "c2r_exec_reject_unknown_orders_tx", "c2r_exec_reject_slot_ended_bundle", "c2r_exec_reject_bank_not_available",
    "c2r_exec_16_txs_max", "c2r_exec_empty"
  };
  ulong tx_cnt = 0UL; ulong bundle_cnt = 0UL; ulong incl_cnt = 0UL; ulong not_incl_cnt = 0UL;
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( names[ i ] );
    FD_TEST( jnum( jval( v->json, "tag" ) )==FD_GRAVITY_C2R_EXEC_RESULT );
    static uchar         sigs[ 32 ][ 16 ];
    ulong                sig_sz[ 32 ];
    uchar                bundle_id[ 32 ];
    fd_gravity_result_t  res[ 32 ];
    fd_gravity_exec_result_t r = {0};
    r.slot = jnum( jval( v->json, "slot" ) );
    jhex_exact( v->json, "mini_block_uuid", r.uuid, 16UL );
    char const * o = jval( v->json, "orders" );
    if( !strncmp( o, "{\"Transactions\":", 16UL ) ) {
      r.sig_prefix_cnt = jhex_list( o+16, sigs[ 0 ], 16UL, sig_sz, 32UL );
      for( ulong j=0UL; j<r.sig_prefix_cnt; j++ ) FD_TEST( sig_sz[ j ]==16UL );
      r.sig_prefixes = sigs[ 0 ];
      tx_cnt++;
    } else {
      FD_TEST( !strncmp( o, "{\"Bundle\":", 10UL ) );
      ulong sz;
      jhex( o+10, bundle_id, 32UL, &sz );
      FD_TEST( sz==32UL );
      r.bundle_id = bundle_id;
      bundle_cnt++;
    }
    r.result_cnt        = results_from_json( v->json, res, 32UL );
    r.results           = res;
    r.batch_received_at = jnum( jval( v->json, "batch_received_at" ) );
    r.forwarded_at      = jnum( jval( v->json, "forwarded_at" ) );
    r.res_received_at   = jnum( jval( v->json, "res_received_at" ) );
    r.worker            = (uchar)jnum( jval( v->json, "worker" ) );
    for( ulong j=0UL; j<r.result_cnt; j++ ) {
      if( res[ j ].kind==FD_GRAVITY_RESULT_INCLUDED ) incl_cnt++;
      else                                            not_incl_cnt++;
    }

    if( !strcmp( v->name, "c2r_exec_empty" ) ) {
      /* Encoding edge case the connector never sends (no orders, no
         results): the C encoder refuses it by design. */
      FD_TEST( !r.sig_prefix_cnt && !r.result_cnt );
      FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
      continue;
    }
    check_enc( v, enc_exec, &r );
  }
  FD_TEST( tx_cnt && bundle_cnt && incl_cnt && not_incl_cnt );

  /* Refused input */
  static uchar sigs[ 17 ][ 16 ];
  fd_gravity_result_t res[ 17 ];
  for( ulong j=0UL; j<17UL; j++ ) {
    memset( sigs[ j ], (int)(0x60+j), 16UL );
    res[ j ] = (fd_gravity_result_t){ .kind = FD_GRAVITY_RESULT_INCLUDED, .slot = 1UL, .cus = 2UL };
  }
  uchar bid[ 32 ] = {0};
  fd_gravity_exec_result_t r = { .sig_prefix_cnt = 16UL, .sig_prefixes = sigs[ 0 ], .result_cnt = 16UL, .results = res };
  FD_TEST( fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
  r.sig_prefix_cnt = 17UL;
  FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
  r.sig_prefix_cnt = 16UL; r.result_cnt = 17UL;
  FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
  r.result_cnt = 0UL;
  FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
  r.result_cnt = 1UL; r.bundle_id = bid;
  FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) ); /* both orders kinds */
  r.sig_prefix_cnt = 0UL;
  FD_TEST(  fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
  r.bundle_id = NULL;
  FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) ); /* neither */
  r.sig_prefix_cnt = 1UL;

  res[ 0 ].kind = FD_GRAVITY_RESULT_NOT_INCLUDED;
  for( uint reason=0U; reason<300U; reason++ ) {
    res[ 0 ].reason = reason;
    int ok = reason>=1U && reason<=FD_GRAVITY_NI_SLOT_ENDED; /* NONE, 45 and the repr values are refused */
    FD_TEST( !!fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r )==ok );
  }
  res[ 0 ].kind = 2U; res[ 0 ].reason = FD_GRAVITY_NI_SLOT_ENDED;
  FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
  FD_LOG_NOTICE(( "exec result: ok" ));
}

/* Messages this client never sends *************************************/

static void
test_c2r_unsent( void ) {
  /* The relay accepts these, but the in-validator client never emits
     them: legacy Handshake (0), ReadyForTips (4), CrankBundle (5),
     Bundle v1 (6), JoinSession (12) and Stats (13).  Check the vector
     tags and that no encoder produced those tags. */
  static struct { char const * name; uint tag; } const unsent[] = {
    { "c2r_handshake_v1_legacy",  0U }, { "c2r_ready_for_tips", 4U }, { "c2r_crank_bundle", 5U },
    { "c2r_bundle_v1_legacy",     6U }, { "c2r_join_session",  12U }, { "c2r_stats_empty", 13U },
    { "c2r_stats_two",           13U },
  };
  for( ulong i=0UL; i<sizeof(unsent)/sizeof(unsent[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( unsent[ i ].name );
    FD_TEST( FD_LOAD( uint, v->payload )==unsent[ i ].tag );
    FD_TEST( jnum( jval( v->json, "tag" ) )==unsent[ i ].tag );
    FD_TEST( !enc_tag_seen[ unsent[ i ].tag ] );
  }

  /* The encoders produced exactly the tags the client uses. */
  for( uint t=0U; t<16U; t++ ) {
    int used = t==FD_GRAVITY_C2R_TRANSACTION || t==FD_GRAVITY_C2R_EXEC_RESULT || t==FD_GRAVITY_C2R_PONG ||
               t==FD_GRAVITY_C2R_PROGRESS    || t==FD_GRAVITY_C2R_HANDSHAKE_V2 || t==FD_GRAVITY_C2R_BUNDLE_V2;
    FD_TEST( enc_tag_seen[ t ]==used );
  }
}

/* RelayToConnector decoders ********************************************/

static void
test_ping( void ) {
  static char const * const names[] = { "r2c_ping_0", "r2c_ping_seq", "r2c_ping_max" };
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( names[ i ] );
    uint tag;
    FD_TEST( !fd_gravity_decode_tag( v->payload, v->payload_sz, &tag ) );
    FD_TEST( tag==FD_GRAVITY_R2C_PING && tag==jnum( jval( v->json, "tag" ) ) );
    ulong seq = 0UL;
    FD_TEST( !fd_gravity_decode_ping( v->payload, v->payload_sz, &seq ) );
    FD_TEST( seq==jnum( jval( v->json, "seq" ) ) );
    fd_gravity_graph_t g;
    FD_TEST( fd_gravity_decode_graph( v->payload, v->payload_sz, &g )==-1 );
    for( ulong sz=0UL; sz<v->payload_sz; sz++ ) {
      FD_TEST( fd_gravity_decode_ping( guard_copy( v->payload, sz ), sz, &seq )==-1 );
      if( sz<4UL ) FD_TEST( fd_gravity_decode_tag( guard_copy( v->payload, sz ), sz, &tag )==-1 );
    }
  }
  FD_LOG_NOTICE(( "ping: ok" ));
}

static void
test_r2c_ignored( void ) {
  /* Messages the client recognizes by tag but skips (it has no failsafe,
     tips are cranked by pack, shred destinations are static).  The
     SocketAddr ADDR vectors are the elements of the shred receiver
     lists. */
  static struct { char const * name; uint tag; } const ign[] = {
    { "r2c_delete_failsafe",               FD_GRAVITY_R2C_DELETE_FAILSAFE            },
    { "r2c_previous_tip_receiver",         FD_GRAVITY_R2C_PREVIOUS_TIP_RECEIVER      },
    { "r2c_shred_receivers_empty",         FD_GRAVITY_R2C_SHRED_RECEIVERS            },
    { "r2c_shred_receivers_v4_v6",         FD_GRAVITY_R2C_SHRED_RECEIVERS            },
    { "r2c_shred_retransmit_receivers_v4", FD_GRAVITY_R2C_SHRED_RETRANSMIT_RECEIVERS },
  };
  for( ulong i=0UL; i<sizeof(ign)/sizeof(ign[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( ign[ i ].name );
    uint tag;
    FD_TEST( !fd_gravity_decode_tag( v->payload, v->payload_sz, &tag ) );
    FD_TEST( tag==ign[ i ].tag && tag==jnum( jval( v->json, "tag" ) ) );
    ulong seq; fd_gravity_graph_t g;
    FD_TEST( fd_gravity_decode_ping ( v->payload, v->payload_sz, &seq )==-1 );
    FD_TEST( fd_gravity_decode_graph( v->payload, v->payload_sz, &g   )==-1 );
  }

  struct gravity_wire_vec const * a4 = vec( "addr_v4" );
  struct gravity_wire_vec const * a6 = vec( "addr_v6" );
  static uchar const want4[] = { 0,0,0,0, 10,0,0,7, 0x41,0x1f };              /* V4 10.0.0.7:8001 */
  static uchar const want6[] = { 1,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1, 0xcd,0xab }; /* V6 [::1]:43981 */
  FD_TEST( a4->payload_sz==sizeof(want4) && !memcmp( a4->payload, want4, sizeof(want4) ) );
  FD_TEST( a6->payload_sz==sizeof(want6) && !memcmp( a6->payload, want6, sizeof(want6) ) );
  struct gravity_wire_vec const * l2 = vec( "r2c_shred_receivers_v4_v6" );
  FD_TEST( FD_LOAD( ulong, l2->payload+4UL )==2UL );
  FD_TEST( !memcmp( l2->payload+12UL, a4->payload, a4->payload_sz ) );
  FD_TEST( !memcmp( l2->payload+12UL+a4->payload_sz, a6->payload, a6->payload_sz ) );
  FD_TEST( l2->payload_sz==12UL+a4->payload_sz+a6->payload_sz );
  struct gravity_wire_vec const * l1 = vec( "r2c_shred_retransmit_receivers_v4" );
  FD_TEST( FD_LOAD( ulong, l1->payload+4UL )==1UL );
  FD_TEST( !memcmp( l1->payload+12UL, a4->payload, a4->payload_sz ) );
  FD_LOG_NOTICE(( "ignored relay messages: ok" ));
}

/* check_graph_bounds walks a decoded graph with the iterators and
   requires every pointer to stay within [payload,payload+sz). */

static void
check_graph_bounds( fd_gravity_graph_t const * g,
                    uchar const *              payload,
                    ulong                      sz ) {
  uchar const * end = payload+sz;
  FD_TEST( g->node_cnt );
  uchar const * cur = g->nodes;
  for( ulong i=0UL; i<g->node_cnt; i++ ) {
    fd_gravity_node_t n;
    cur = fd_gravity_node_next( cur, &n );
    FD_TEST( n.kind==FD_GRAVITY_NODE_TX || n.kind==FD_GRAVITY_NODE_BUNDLE );
    FD_TEST( n.id>=payload && cur<=end );
  }
  FD_TEST( cur==g->nodes_end );
  cur = g->order_txns;
  for( ulong i=0UL; i<g->order_txn_cnt; i++ ) {
    uchar const * txn; ulong txn_sz;
    cur = fd_gravity_order_txn_next( cur, &txn, &txn_sz );
    FD_TEST( txn>=payload && txn_sz<=(ulong)(end-txn) && cur<=end );
  }
  FD_TEST( cur==g->order_txns_end );
  cur = g->order_bundles;
  for( ulong i=0UL; i<g->order_bundle_cnt; i++ ) {
    fd_gravity_bundle_t b;
    cur = fd_gravity_order_bundle_next( cur, &b );
    FD_TEST( b.txn_cnt<=FD_GRAVITY_MAX_TXN_PER_BUNDLE );
    for( ulong j=0UL; j<b.txn_cnt; j++ ) FD_TEST( b.txn[ j ]>=payload && b.txn_sz[ j ]<=(ulong)(end-b.txn[ j ]) );
    FD_TEST( cur<=end );
  }
  FD_TEST( cur==g->order_bundles_end );
  FD_TEST( g->order_bundles_end<=end );
}

static void
test_graph( void ) {
  static char const * const names[] = { "r2c_graph_single_tx", "r2c_graph_mixed_dag", "r2c_graph_connector_sourced" };
  ulong mutated_ok = 0UL;
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) {
    struct gravity_wire_vec const * v = vec( names[ i ] );
    char const * json = v->json;
    uint tag;
    FD_TEST( !fd_gravity_decode_tag( v->payload, v->payload_sz, &tag ) );
    FD_TEST( tag==FD_GRAVITY_R2C_MINI_BLOCK_GRAPH && tag==jnum( jval( json, "tag" ) ) );

    fd_gravity_graph_t g;
    FD_TEST( !fd_gravity_decode_graph( v->payload, v->payload_sz, &g ) );
    FD_TEST( g.slot==jnum( jval( json, "slot" ) ) );
    FD_TEST( g.index_in_slot==jnum( jval( json, "index_in_slot" ) ) );
    uchar uuid[ 16 ];
    jhex_exact( json, "uuid", uuid, 16UL );
    FD_TEST( !memcmp( g.uuid, uuid, 16UL ) );
    FD_TEST( g.order_bundles_end==v->payload+v->payload_sz );

    /* Nodes */
    char const * n = jval( json, "nodes" );
    FD_TEST( *n++=='[' );
    uchar const * cur = g.nodes;
    ulong node_cnt = 0UL;
    while( *n!=']' ) {
      FD_TEST( node_cnt<g.node_cnt );
      ulong depth = jnum( jval( n, "depth" ) );
      char const * ref = jval( n, "order_ref" );
      uint  kind;
      uchar id[ 32 ];
      ulong id_sz;
      if( !strncmp( ref, "{\"Tx\":", 6UL ) ) { kind = FD_GRAVITY_NODE_TX;     n = jhex( ref+6,  id, 32UL, &id_sz ); FD_TEST( id_sz==16UL ); }
      else { FD_TEST( !strncmp( ref, "{\"Bundle\":", 10UL ) );
                                               kind = FD_GRAVITY_NODE_BUNDLE; n = jhex( ref+10, id, 32UL, &id_sz ); FD_TEST( id_sz==32UL ); }
      FD_TEST( !strncmp( n, "}}", 2UL ) );
      n += 2;
      if( *n==',' ) n++;
      fd_gravity_node_t gn;
      cur = fd_gravity_node_next( cur, &gn );
      FD_TEST( gn.kind==kind && gn.depth==depth && !memcmp( gn.id, id, id_sz ) );
      node_cnt++;
    }
    FD_TEST( node_cnt==g.node_cnt && cur==g.nodes_end );

    /* Loose builder transactions (orders.txs is the last "txs" key,
       the ones before it are inside orders.bundles) */
    char const * orders = jval( json, "orders" );
    char const * txs    = jval( orders, "txs" );
    for( char const * nxt=strstr( txs, "\"txs\":" ); nxt; nxt=strstr( nxt+1, "\"txs\":" ) ) txs = nxt+6;
    ulong txn_cnt = jhex_list( txs, txn_store[ 0 ], 4096UL, txn_store_sz, 8UL );
    FD_TEST( txn_cnt==g.order_txn_cnt );
    cur = g.order_txns;
    for( ulong j=0UL; j<txn_cnt; j++ ) {
      uchar const * txn; ulong txn_sz;
      cur = fd_gravity_order_txn_next( cur, &txn, &txn_sz );
      FD_TEST( txn_sz==txn_store_sz[ j ] && !memcmp( txn, txn_store[ j ], txn_sz ) );
      /* Tx nodes reference builder transactions by SigPrefix */
      uchar prefix[ 16 ];
      FD_TEST( !fd_gravity_sig_prefix( txn, txn_sz, prefix ) );
    }
    FD_TEST( cur==g.order_txns_end );

    /* Builder bundles */
    char const * b = jval( orders, "bundles" );
    FD_TEST( *b++=='[' );
    cur = g.order_bundles;
    ulong bundle_cnt = 0UL;
    while( *b!=']' ) {
      FD_TEST( bundle_cnt<g.order_bundle_cnt );
      uchar ext_uuid[ 32 ];
      ulong sz;
      jhex( jval( b, "ext_uuid" ), ext_uuid, 32UL, &sz );
      FD_TEST( sz==32UL );
      char const * t = jval( b, "txs" );
      ulong cnt = jhex_list( t, txn_store[ 0 ], 4096UL, txn_store_sz, 8UL );
      fd_gravity_bundle_t gb;
      cur = fd_gravity_order_bundle_next( cur, &gb );
      FD_TEST( !memcmp( gb.ext_uuid, ext_uuid, 32UL ) && gb.txn_cnt==cnt );
      for( ulong j=0UL; j<cnt; j++ ) FD_TEST( gb.txn_sz[ j ]==txn_store_sz[ j ] && !memcmp( gb.txn[ j ], txn_store[ j ], gb.txn_sz[ j ] ) );
      b = strchr( t, ']' );
      FD_TEST( b && b[1]=='}' );
      b += 2;
      if( *b==',' ) b++;
      bundle_cnt++;
    }
    FD_TEST( bundle_cnt==g.order_bundle_cnt && cur==g.order_bundles_end );
    check_graph_bounds( &g, v->payload, v->payload_sz );

    /* Every truncation is rejected (the payload ends at a guard page) */
    for( ulong sz=0UL; sz<v->payload_sz; sz++ ) {
      FD_TEST( fd_gravity_decode_graph( guard_copy( v->payload, sz ), sz, &g )==-1 );
    }

    /* Trailing bytes are ignored, as by wincode::deserialize */
    static uchar tmp[ 4096 ];
    memcpy( tmp, v->payload, v->payload_sz );
    tmp[ v->payload_sz ] = 0xee;
    uchar const * p = guard_copy( tmp, v->payload_sz+1UL );
    FD_TEST( !fd_gravity_decode_graph( p, v->payload_sz+1UL, &g ) );
    FD_TEST( g.order_bundles_end==p+v->payload_sz );

    /* Single byte mutations never crash or yield out of bounds views */
    for( ulong off=0UL; off<v->payload_sz; off++ ) {
      static uchar const xors[] = { 0x01, 0x02, 0x10, 0x80, 0xff };
      for( ulong k=0UL; k<sizeof(xors); k++ ) {
        memcpy( tmp, v->payload, v->payload_sz );
        tmp[ off ] ^= xors[ k ];
        p = guard_copy( tmp, v->payload_sz );
        if( !fd_gravity_decode_graph( p, v->payload_sz, &g ) ) {
          check_graph_bounds( &g, p, v->payload_sz );
          mutated_ok++;
        }
      }
    }
  }
  FD_LOG_NOTICE(( "graph: ok (%lu mutated payloads still decoded, all in bounds)", mutated_ok ));
}

/* Hand built graphs for the structural edge cases */

typedef struct { uchar * p; uchar * b; } wr_t;

static void
wr_u32( wr_t * w,
        uint   v ) {
  FD_STORE( uint, w->p, v );
  w->p += 4UL;
}

static void
wr_u64( wr_t * w,
        ulong  v ) {
  FD_STORE( ulong, w->p, v );
  w->p += 8UL;
}

static void
wr_mem( wr_t *       w,
        void const * src,
        ulong        sz ) {
  memcpy( w->p, src, sz );
  w->p += sz;
}

/* build_graph writes a graph with node_cnt Tx nodes (no edges unless
   row_cnt differs), the given loose txns and one bundle of bundle_txn_cnt
   copies of txn (bundle_txn_cnt==ULONG_MAX for no bundle). */

static ulong
build_graph( uchar *       out,
             ulong         node_cnt,
             ulong         row_cnt,
             ulong         loose_cnt,
             uchar const * txn,
             ulong         txn_sz,
             ulong         bundle_txn_cnt ) {
  wr_t w = { out, out };
  wr_u32( &w, FD_GRAVITY_R2C_MINI_BLOCK_GRAPH );
  wr_u64( &w, 42UL );
  wr_u32( &w, 1U );
  uchar uuid[ 16 ]; memset( uuid, 0x11, 16UL );
  wr_mem( &w, uuid, 16UL );
  wr_u64( &w, row_cnt );
  for( ulong i=0UL; i<row_cnt; i++ ) wr_u32( &w, 0U );
  wr_u64( &w, 0UL );
  wr_u64( &w, node_cnt );
  for( ulong i=0UL; i<node_cnt; i++ ) {
    uchar id[ 16 ]; memset( id, (int)i, 16UL );
    wr_u32( &w, FD_GRAVITY_NODE_TX ); wr_mem( &w, id, 16UL ); wr_u32( &w, 1U );
  }
  wr_u64( &w, loose_cnt );
  for( ulong i=0UL; i<loose_cnt; i++ ) { wr_u64( &w, txn_sz ); wr_mem( &w, txn, txn_sz ); }
  if( bundle_txn_cnt==ULONG_MAX ) {
    wr_u64( &w, 0UL );
  } else {
    wr_u64( &w, 1UL );
    uchar ext[ 32 ]; memset( ext, 0xb9, 32UL );
    wr_mem( &w, ext, 32UL );
    wr_u64( &w, bundle_txn_cnt );
    for( ulong i=0UL; i<bundle_txn_cnt; i++ ) { wr_u64( &w, txn_sz ); wr_mem( &w, txn, txn_sz ); }
  }
  return (ulong)(w.p-w.b);
}

static void
test_graph_edge_cases( void ) {
  static uchar buf[ 8192 ];
  fd_gravity_graph_t g;
  struct gravity_wire_vec const * raw = vec( "tx_v0" );
  ulong sz;

  sz = build_graph( buf, 2UL, 3UL, 1UL, raw->payload, raw->payload_sz, 5UL );
  FD_TEST( !fd_gravity_decode_graph( guard_copy( buf, sz ), sz, &g ) );
  FD_TEST( g.node_cnt==2UL && g.order_txn_cnt==1UL && g.order_bundle_cnt==1UL );

  /* 6 transactions in a bundle (ArrayVec<_,5>) */
  sz = build_graph( buf, 2UL, 3UL, 1UL, raw->payload, raw->payload_sz, 6UL );
  FD_TEST( fd_gravity_decode_graph( guard_copy( buf, sz ), sz, &g )==-1 );

  /* An empty bundle is well formed (the consumer rejects it) */
  sz = build_graph( buf, 2UL, 3UL, 0UL, raw->payload, raw->payload_sz, 0UL );
  FD_TEST( !fd_gravity_decode_graph( guard_copy( buf, sz ), sz, &g ) );
  FD_TEST( g.order_bundle_cnt==1UL );

  /* Empty transactions are well formed on the wire (wincode and the
     relay accept them, the Agave connector drops such orders): the
     graph decodes and the consumer can't key or parse them. */
  sz = build_graph( buf, 1UL, 2UL, 3UL, raw->payload, 0UL, 2UL );
  uchar const * p = guard_copy( buf, sz );
  FD_TEST( !fd_gravity_decode_graph( p, sz, &g ) );
  FD_TEST( g.order_txn_cnt==3UL );
  check_graph_bounds( &g, p, sz );
  uchar const * txn; ulong txn_sz; uchar prefix[ 16 ];
  fd_gravity_order_txn_next( g.order_txns, &txn, &txn_sz );
  FD_TEST( !txn_sz && fd_gravity_sig_prefix( txn, txn_sz, prefix )==-1 );
  fd_gravity_bundle_t b;
  fd_gravity_order_bundle_next( g.order_bundles, &b );
  FD_TEST( b.txn_cnt==2UL && !b.txn_sz[ 0 ] && !b.txn_sz[ 1 ] );
  for( ulong cut=0UL; cut<sz; cut++ ) FD_TEST( fd_gravity_decode_graph( guard_copy( buf, cut ), cut, &g )==-1 );

  /* No nodes, or row_offsets not node_cnt+1 long */
  sz = build_graph( buf, 0UL, 1UL, 0UL, raw->payload, raw->payload_sz, ULONG_MAX );
  FD_TEST( fd_gravity_decode_graph( guard_copy( buf, sz ), sz, &g )==-1 );
  sz = build_graph( buf, 2UL, 2UL, 0UL, raw->payload, raw->payload_sz, ULONG_MAX );
  FD_TEST( fd_gravity_decode_graph( guard_copy( buf, sz ), sz, &g )==-1 );
  sz = build_graph( buf, 2UL, 4UL, 0UL, raw->payload, raw->payload_sz, ULONG_MAX );
  FD_TEST( fd_gravity_decode_graph( guard_copy( buf, sz ), sz, &g )==-1 );

  /* Huge counts at every count position are rejected without
     overflowing (row, col, node, txn, bundle, bundle txn, txn len) */
  sz = build_graph( buf, 1UL, 2UL, 1UL, raw->payload, raw->payload_sz, 1UL );
  ulong const row_off = 4UL+8UL+4UL+16UL;
  ulong const col_off = row_off+8UL+2UL*4UL;
  ulong const nod_off = col_off+8UL;
  ulong const txc_off = nod_off+8UL+24UL;
  ulong const tx0_off = txc_off+8UL;
  ulong const bnc_off = tx0_off+8UL+raw->payload_sz;
  ulong const bt_off  = bnc_off+8UL+32UL;
  ulong const btx_off = bt_off+8UL;
  ulong const offs[] = { row_off, col_off, nod_off, txc_off, tx0_off, bnc_off, bt_off, btx_off };
  FD_TEST( btx_off+8UL+raw->payload_sz==sz );
  FD_TEST( !fd_gravity_decode_graph( guard_copy( buf, sz ), sz, &g ) );
  static ulong const huge[] = { ULONG_MAX, ULONG_MAX/4UL+1UL, ULONG_MAX/8UL+1UL, ULONG_MAX/24UL+1UL, 1UL<<62, 1UL<<32, 0x7fffffffUL };
  for( ulong i=0UL; i<sizeof(offs)/sizeof(offs[0]); i++ ) {
    for( ulong k=0UL; k<sizeof(huge)/sizeof(huge[0]); k++ ) {
      static uchar tmp[ 8192 ];
      memcpy( tmp, buf, sz );
      FD_STORE( ulong, tmp+offs[ i ], huge[ k ] );
      FD_TEST( fd_gravity_decode_graph( guard_copy( tmp, sz ), sz, &g )==-1 );
    }
  }
  FD_LOG_NOTICE(( "graph edge cases: ok" ));
}

/* SigPrefix ************************************************************/

/* Expected ids computed with Python: sha256( ",".join( base58( sig ) ) ) */

static void
test_jito_bundle_id( void ) {
  static uchar s[ 3 ][ 64 ];
  for( ulong i=0UL; i<64UL; i++ ) { s[0][i] = (uchar)i; s[1][i] = (uchar)(64UL+i); s[2][i] = i<3UL ? 0 : 0xff; }
  uchar const * sigs[ 3 ] = { s[0], s[1], s[2] };
  char const * want[ 3 ] = {
    "\"e589a40ca2b00c80d649dddb65a6e3d20586f1bee9222114eab21dcf2641d61b\"",
    "\"16c9cf91390b9f1b3ba890aeb75d452023ce510ab70570bf10d2dab7314919c6\"",
    "\"89fa19dd749f6a2c763461c36afb1ac1876410b8817a01697473f5d0d78ade59\"" /* leading zero bytes */
  };
  for( ulong cnt=1UL; cnt<=3UL; cnt++ ) {
    uchar out[ 32 ]; uchar w[ 32 ]; ulong sz;
    fd_gravity_jito_bundle_id( out, cnt, sigs );
    jhex( want[ cnt-1UL ], w, 32UL, &sz );
    FD_TEST( sz==32UL && !memcmp( out, w, 32UL ) );
  }
}

static void
test_sig_prefix( void ) {
  ulong ok_cnt = 0UL; ulong bad_cnt = 0UL;
  for( ulong i=0UL; i<GRAVITY_WIRE_VEC_CNT; i++ ) {
    struct gravity_wire_vec const * v = gravity_wire_vecs+i;
    if( strcmp( v->kind, "SIGPREFIX" ) ) continue;
    vec_used[ i ] = 1;
    uchar out[ 16 ];
    uchar const * p = guard_copy( v->payload, v->payload_sz );
    char const * want = jval( v->json, "sig_prefix" );
    if( jnull( want ) ) {
      FD_TEST( fd_gravity_sig_prefix( p, v->payload_sz, out )==-1 );
      bad_cnt++;
      continue;
    }
    uchar w[ 16 ];
    ulong sz;
    jhex( want, w, 16UL, &sz );
    FD_TEST( sz==16UL );
    FD_TEST( !fd_gravity_sig_prefix( p, v->payload_sz, out ) );
    FD_TEST( !memcmp( out, w, 16UL ) );
    ok_cnt++;

    if( !strstr( v->json, "\"first_signature\":" ) ) continue;
    uchar sig[ 64 ];
    jhex( jval( v->json, "first_signature" ), sig, 64UL, &sz );
    FD_TEST( sz==64UL && !memcmp( sig, w, 16UL ) );

    /* The same transaction is also a RAW vector (tx_<suffix>) */
    char raw_name[ 64 ];
    FD_TEST( fd_cstr_printf_check( raw_name, sizeof(raw_name), NULL, "tx_%s", v->name+strlen( "sigprefix_" ) ) );
    struct gravity_wire_vec const * raw = vec( raw_name );
    FD_TEST( raw->payload_sz==v->payload_sz && !memcmp( raw->payload, v->payload, v->payload_sz ) );
  }
  FD_TEST( ok_cnt==6UL && bad_cnt==7UL );

  /* Boundary cases beyond the vectors */
  uchar tx[ 256 ];
  uchar out[ 16 ];
  for( ulong i=0UL; i<sizeof(tx); i++ ) tx[ i ] = (uchar)i;
  tx[ 0 ] = 0x7f; /* legacy, 127 signatures: only 17 bytes are needed */
  FD_TEST( !fd_gravity_sig_prefix( guard_copy( tx, 17UL ), 17UL, out ) && !memcmp( out, tx+1, 16UL ) );
  tx[ 0 ] = 0x80; FD_TEST( fd_gravity_sig_prefix( guard_copy( tx, 64UL ), 64UL, out )==-1 );
  tx[ 0 ] = 0x00; FD_TEST( fd_gravity_sig_prefix( guard_copy( tx, 64UL ), 64UL, out )==-1 );
  tx[ 0 ] = 0x81; tx[ 1 ] = 1; /* v1, the transaction is exactly one signature long */
  FD_TEST( !fd_gravity_sig_prefix( guard_copy( tx, 64UL ), 64UL, out ) && !memcmp( out, tx, 16UL ) );
  FD_TEST( fd_gravity_sig_prefix( guard_copy( tx, 63UL ), 63UL, out )==-1 );
  FD_TEST( fd_gravity_sig_prefix( guard_copy( tx, 1UL ), 1UL, out )==-1 );
  tx[ 1 ] = 255; /* 255 signatures need 16320 bytes */
  FD_TEST( fd_gravity_sig_prefix( guard_copy( tx, 256UL ), 256UL, out )==-1 );
  tx[ 1 ] = 2;
  FD_TEST( !fd_gravity_sig_prefix( guard_copy( tx, 200UL ), 200UL, out ) && !memcmp( out, tx+200-128, 16UL ) );
  FD_LOG_NOTICE(( "sig prefix: ok" ));
}

/* NotIncludedReason ****************************************************/

static void
test_reasons( void ) {
  /* Every REASON vector: payload is the u32 wire tag, and wire tags are
     the variant indices 0..44 in order. */
  ulong cnt = 0UL;
  for( ulong i=0UL; i<GRAVITY_WIRE_VEC_CNT; i++ ) {
    struct gravity_wire_vec const * v = gravity_wire_vecs+i;
    if( strcmp( v->kind, "REASON" ) ) continue;
    vec_used[ i ] = 1;
    FD_TEST( v->payload_sz==4UL );
    FD_TEST( FD_LOAD( uint, v->payload )==jnum( jval( v->json, "wire_tag" ) ) );
    FD_TEST( FD_LOAD( uint, v->payload )==cnt );
    cnt++;
  }
  FD_TEST( cnt==45UL );

  /* FD_GRAVITY_NI_* constants */
  FD_TEST( FD_GRAVITY_NI_BANK_NOT_AVAILABLE        ==reason_wire( "BANK_NOT_AVAILABLE"                    ) );
  FD_TEST( FD_GRAVITY_NI_ALL_OR_NOTHING            ==reason_wire( "ALL_OR_NOTHING_BATCH_FAILURE"          ) );
  FD_TEST( FD_GRAVITY_NI_ACCOUNT_IN_USE            ==reason_wire( "ACCOUNT_IN_USE"                        ) );
  FD_TEST( FD_GRAVITY_NI_ACCOUNT_LOADED_TWICE      ==reason_wire( "ACCOUNT_LOADED_TWICE"                  ) );
  FD_TEST( FD_GRAVITY_NI_INSUFFICIENT_FUNDS_FOR_FEE==reason_wire( "INSUFFICIENT_FUNDS_FOR_FEE"            ) );
  FD_TEST( FD_GRAVITY_NI_ALREADY_PROCESSED         ==reason_wire( "ALREADY_PROCESSED"                     ) );
  FD_TEST( FD_GRAVITY_NI_BLOCKHASH_NOT_FOUND       ==reason_wire( "BLOCKHASH_NOT_FOUND"                   ) );
  FD_TEST( FD_GRAVITY_NI_SANITIZE_FAILURE          ==reason_wire( "SANITIZE_FAILURE"                      ) );
  FD_TEST( FD_GRAVITY_NI_WOULD_EXCEED_BLOCK_COST   ==reason_wire( "WOULD_EXCEED_MAX_BLOCK_COST_LIMIT"     ) );
  FD_TEST( FD_GRAVITY_NI_WOULD_EXCEED_ACCOUNT_COST ==reason_wire( "WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT"   ) );
  FD_TEST( FD_GRAVITY_NI_WOULD_EXCEED_DATA_BLOCK   ==reason_wire( "WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT" ) );
  FD_TEST( FD_GRAVITY_NI_TOO_MANY_ACCOUNT_LOCKS    ==reason_wire( "TOO_MANY_ACCOUNT_LOCKS"                ) );
  FD_TEST( FD_GRAVITY_NI_ALT_NOT_FOUND             ==reason_wire( "ADDRESS_LOOKUP_TABLE_NOT_FOUND"        ) );
  FD_TEST( FD_GRAVITY_NI_MAX_WORKING_SLOT_EXCEEDED ==reason_wire( "MAX_WORKING_SLOT_EXCEEDED"             ) );
  FD_TEST( FD_GRAVITY_NI_NOT_SEQUENCING            ==reason_wire( "NOT_SEQUENCING"                        ) );
  FD_TEST( FD_GRAVITY_NI_UNKNOWN_ORDERS            ==reason_wire( "UNKNOWN_ORDERS"                        ) );
  FD_TEST( FD_GRAVITY_NI_SLOT_ENDED                ==reason_wire( "SLOT_ENDED"                            ) );
  FD_TEST( 0U                                      ==reason_wire( "NONE"                                  ) );

  /* fd_gravity_reason_from_txn_err for every FD_RUNTIME_TXN_ERR_* */
# define E(x) { FD_RUNTIME_TXN_ERR_##x, #x }
  static struct { int err; char const * name; } const tbl[] = {
    E(ACCOUNT_LOADED_TWICE),                    E(ACCOUNT_NOT_FOUND),                    E(PROGRAM_ACCOUNT_NOT_FOUND),
    E(INSUFFICIENT_FUNDS_FOR_FEE),              E(INVALID_ACCOUNT_FOR_FEE),              E(ALREADY_PROCESSED),
    E(BLOCKHASH_NOT_FOUND),                     E(INSTRUCTION_ERROR),                    E(SIGNATURE_FAILURE),
    E(INVALID_PROGRAM_FOR_EXECUTION),           E(SANITIZE_FAILURE),                     E(WOULD_EXCEED_MAX_BLOCK_COST_LIMIT),
    E(UNSUPPORTED_VERSION),                     E(WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT),  E(WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT),
    E(TOO_MANY_ACCOUNT_LOCKS),                  E(ADDRESS_LOOKUP_TABLE_NOT_FOUND),       E(INVALID_ADDRESS_LOOKUP_TABLE_OWNER),
    E(INVALID_ADDRESS_LOOKUP_TABLE_DATA),       E(INVALID_ADDRESS_LOOKUP_TABLE_INDEX),   E(WOULD_EXCEED_MAX_VOTE_COST_LIMIT),
    E(WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT),   E(DUPLICATE_INSTRUCTION),                E(INSUFFICIENT_FUNDS_FOR_RENT),
    E(MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED),  E(INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT), E(UNBALANCED_TRANSACTION),
    { FD_RUNTIME_TXN_ERR_BUNDLE_PEER,                         "ALL_OR_NOTHING_BATCH_FAILURE" },
    { FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED,    "BLOCKHASH_NOT_FOUND"          },
    { FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR,  "BLOCKHASH_NOT_FOUND"          },
    { FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE,          "BLOCKHASH_NOT_FOUND"          },
  };
# undef E
  for( ulong i=0UL; i<sizeof(tbl)/sizeof(tbl[0]); i++ ) {
    uint got  = fd_gravity_reason_from_txn_err( tbl[ i ].err );
    uint want = reason_wire( tbl[ i ].name );
    if( FD_UNLIKELY( got!=want ) ) FD_LOG_ERR(( "err %i (%s): got %u want %u", tbl[ i ].err, tbl[ i ].name, got, want ));
    if( tbl[ i ].err>=-38 ) FD_TEST( got==(uint)(2-tbl[ i ].err) );
  }

  /* Agave indices without a Firedancer constant follow the same rule */
  FD_TEST( fd_gravity_reason_from_txn_err(  -1 )==reason_wire( "ACCOUNT_IN_USE"              ) );
  FD_TEST( fd_gravity_reason_from_txn_err( -10 )==reason_wire( "CALL_CHAIN_TOO_DEEP"         ) );
  FD_TEST( fd_gravity_reason_from_txn_err( -38 )==reason_wire( "PROGRAM_CACHE_HIT_MAX_LIMIT" ) );
  for( int err=-38; err<=-1; err++ ) FD_TEST( fd_gravity_reason_from_txn_err( err )==(uint)(2-err) );

  /* Anything else is reported as a sanitize failure, never NONE or an
     out of range tag */
  static int const other[] = { 0, 1, -39, -41, -49, -53, INT_MIN, INT_MAX };
  for( ulong i=0UL; i<sizeof(other)/sizeof(other[0]); i++ ) {
    FD_TEST( fd_gravity_reason_from_txn_err( other[ i ] )==FD_GRAVITY_NI_SANITIZE_FAILURE );
  }
  FD_LOG_NOTICE(( "reasons: ok" ));
}

/* NEG vectors **********************************************************/

static void
test_neg( void ) {
  uint  tag;
  uint  reason;
  ulong seq;
  uchar challenge[ 32 ];
  fd_gravity_graph_t g;
  struct gravity_wire_vec const * v;

  /* Bootstrap decoder: same verdicts as decode_bootstrap_frame */
  static char const * const boot_bad[] = {
    "neg_boot_short_magic", "neg_boot_tag_5", "neg_boot_reject_reason_4", "neg_boot_server_hello_short", "neg_boot_session_msg"
  };
  for( ulong i=0UL; i<sizeof(boot_bad)/sizeof(boot_bad[0]); i++ ) {
    v = vec( boot_bad[ i ] );
    FD_TEST( !strncmp( jval( v->json, "rust_result" ), "\"error", 6UL ) );
    FD_TEST( fd_gravity_decode_bootstrap( guard_copy( v->payload, v->payload_sz ), v->payload_sz, &tag, challenge, &reason )==-1 );
  }
  v = vec( "neg_boot_accepted_trailing" ); /* QUIRK: accepted by Rust and C */
  FD_TEST( !strncmp( jval( v->json, "rust_result" ), "\"accepted\"", 10UL ) );
  FD_TEST( !fd_gravity_decode_bootstrap( v->payload, v->payload_sz, &tag, challenge, &reason ) && tag==FD_GRAVITY_BOOT_ACCEPTED );

  /* RelayToConnector */
  v = vec( "neg_r2c_ping_trailing_byte" ); /* QUIRK: accepted by Rust and C */
  FD_TEST( !fd_gravity_decode_ping( v->payload, v->payload_sz, &seq ) && seq==7UL );
  v = vec( "neg_r2c_graph_huge_len" );
  FD_TEST( fd_gravity_decode_graph( guard_copy( v->payload, v->payload_sz ), v->payload_sz, &g )==-1 );
  v = vec( "neg_r2c_graph_node_tag_2" );
  FD_TEST( fd_gravity_decode_graph( guard_copy( v->payload, v->payload_sz ), v->payload_sz, &g )==-1 );

  /* Intentional difference: Rust fails the whole RelayToConnector
     decode on an unknown tag (and the Agave connector disconnects); the
     C client reads the tag and skips messages it does not use, as the
     protocol only adds tags (SPEC 3.3).  A frame is one message, so
     skipping needs no length. */
  static struct { char const * name; uint tag; } const skip[] = {
    { "neg_r2c_unused_tag_6", 6U }, { "neg_r2c_unused_tag_4294967295", UINT_MAX },
    { "neg_r2c_socketaddr_tag_2", FD_GRAVITY_R2C_SHRED_RECEIVERS }, /* no SocketAddr decoder: shred receivers are skipped */
  };
  for( ulong i=0UL; i<sizeof(skip)/sizeof(skip[0]); i++ ) {
    v = vec( skip[ i ].name );
    FD_TEST( !strncmp( jval( v->json, "rust_result" ), "\"error", 6UL ) );
    FD_TEST( !fd_gravity_decode_tag( v->payload, v->payload_sz, &tag ) && tag==skip[ i ].tag );
    FD_TEST( fd_gravity_decode_ping ( v->payload, v->payload_sz, &seq )==-1 );
    FD_TEST( fd_gravity_decode_graph( v->payload, v->payload_sz, &g   )==-1 );
  }

  /* ConnectorToRelay NEG vectors: the C side has no C2R decoder, so
     check that the encoders can't produce them. */
  v = vec( "neg_c2r_truncated_tag" );
  FD_TEST( fd_gravity_decode_tag( v->payload, v->payload_sz, &tag )==-1 );
  FD_TEST( !fd_gravity_encode_pong( enc_buf, 1UL, 0UL ) );
  v = vec( "neg_c2r_pong_truncated" );
  FD_TEST( !fd_gravity_encode_pong( enc_buf, v->payload_sz, 7UL ) );
  v = vec( "neg_c2r_pong_trailing_byte" ); /* never emitted: exact sizes */
  FD_TEST( fd_gravity_encode_pong( enc_buf, sizeof(enc_buf), 7UL )==v->payload_sz-1UL );
  FD_TEST( !memcmp( enc_buf, v->payload, v->payload_sz-1UL ) );

  static char const * const unused_tags[] = {
    "neg_c2r_unused_tag_2", "neg_c2r_unused_tag_7", "neg_c2r_unused_tag_14", "neg_c2r_unused_tag_4294967295"
  };
  for( ulong i=0UL; i<sizeof(unused_tags)/sizeof(unused_tags[0]); i++ ) {
    v = vec( unused_tags[ i ] );
    uint t = FD_LOAD( uint, v->payload );
    FD_TEST( t>=16U || !enc_tag_seen[ t ] );
  }

  /* HandshakeV2 with filter_ofac byte 2: a non-zero flag encodes as 1 */
  v = vec( "neg_c2r_handshake_bool_2" );
  fd_gravity_handshake_t hs = {0};
  memcpy( hs.identity, v->payload+4UL, 32UL );
  ulong ver_sz = FD_LOAD( ulong, v->payload+36UL );
  FD_TEST( ver_sz==1UL );
  char ver[ 2 ] = { (char)v->payload[ 44 ], '\0' };
  hs.version             = ver;
  hs.num_threads         = v->payload[ 45 ];
  hs.filter_ofac         = v->payload[ 46 ];
  FD_TEST( hs.filter_ofac==2 && !FD_LOAD( ulong, v->payload+47UL ) );
  hs.jito_tip_weight_bps = FD_LOAD( ushort, v->payload+55UL );
  ulong sz = fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs );
  FD_TEST( sz==v->payload_sz && enc_buf[ 46 ]==1 );
  enc_buf[ 46 ] = 2;
  FD_TEST( !memcmp( enc_buf, v->payload, sz ) );

  /* HandshakeV2 with a non UTF-8 version: refused */
  v = vec( "neg_c2r_handshake_bad_utf8" );
  memcpy( hs.identity, v->payload+4UL, 32UL );
  FD_TEST( FD_LOAD( ulong, v->payload+36UL )==1UL );
  ver[ 0 ] = (char)v->payload[ 44 ];
  hs.num_threads = v->payload[ 45 ];
  hs.filter_ofac = v->payload[ 46 ];
  FD_TEST( !fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );
  ver[ 0 ] = 'x';
  FD_TEST( fd_gravity_encode_handshake_v2( enc_buf, sizeof(enc_buf), &hs ) );

  /* Transaction with Option tag 2: the tag is derived from the pointer */
  v = vec( "neg_c2r_transaction_option_tag_2" );
  ulong txn_sz = FD_LOAD( ulong, v->payload+4UL );
  uchar const * txn = v->payload+12UL;
  ulong sent_at     = FD_LOAD( ulong, txn+txn_sz );
  ulong received_at = FD_LOAD( ulong, txn+txn_sz+8UL );
  uchar const * src = txn+txn_sz+16UL;
  FD_TEST( 12UL+txn_sz+32UL+1UL==v->payload_sz && v->payload[ v->payload_sz-1UL ]==2 );
  sz = fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), txn, txn_sz, sent_at, received_at, src, NULL );
  FD_TEST( sz==v->payload_sz && !memcmp( enc_buf, v->payload, sz-1UL ) && enc_buf[ sz-1UL ]==0 );

  /* Transaction with a 65 byte source_uri: refused */
  v = vec( "neg_c2r_transaction_uri_65" );
  txn_sz = FD_LOAD( ulong, v->payload+4UL );
  txn    = v->payload+12UL;
  uchar const * opt = txn+txn_sz+32UL;
  FD_TEST( opt[ 0 ]==1 && FD_LOAD( ulong, opt+1UL )==65UL && opt+9UL+65UL==v->payload+v->payload_sz );
  char uri[ 66 ];
  memcpy( uri, opt+9UL, 65UL ); uri[ 65 ] = '\0';
  FD_TEST( !fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), txn, txn_sz, 0UL, 0UL, NULL, uri ) );
  uri[ 64 ] = '\0';
  FD_TEST( fd_gravity_encode_transaction( enc_buf, sizeof(enc_buf), txn, txn_sz, 0UL, 0UL, NULL, uri ) );

  /* BundleV2 with 6 transactions: refused, the first 5 are fine */
  v = vec( "neg_c2r_bundle_6_txs" );
  FD_TEST( FD_LOAD( ulong, v->payload+36UL )==6UL );
  uchar const * btxn[ 6 ]; ulong btxn_sz[ 6 ];
  uchar const * cur = v->payload+44UL;
  for( ulong i=0UL; i<6UL; i++ ) { btxn_sz[ i ] = FD_LOAD( ulong, cur ); btxn[ i ] = cur+8UL; cur += 8UL+btxn_sz[ i ]; }
  ulong bur_sz = FD_LOAD( ulong, cur );
  FD_TEST( bur_sz<64UL );
  char bur[ 65 ];
  memcpy( bur, cur+8UL, bur_sz ); bur[ bur_sz ] = '\0';
  FD_TEST( !fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), v->payload+4UL, 6UL, btxn, btxn_sz, bur, 0UL, 0UL ) );
  FD_TEST(  fd_gravity_encode_bundle_v2( enc_buf, sizeof(enc_buf), v->payload+4UL, 5UL, btxn, btxn_sz, bur, 0UL, 0UL ) );

  /* ExecutionResult with 17 signatures: refused */
  v = vec( "neg_c2r_exec_17_sigs" );
  FD_TEST( FD_LOAD( uint, v->payload+28UL )==0U && FD_LOAD( ulong, v->payload+32UL )==17UL );
  fd_gravity_result_t res[ 16 ];
  for( ulong i=0UL; i<16UL; i++ ) res[ i ] = (fd_gravity_result_t){ .kind = FD_GRAVITY_RESULT_NOT_INCLUDED, .reason = FD_GRAVITY_NI_SLOT_ENDED };
  fd_gravity_exec_result_t r = {
    .slot = FD_LOAD( ulong, v->payload+4UL ), .sig_prefix_cnt = 17UL, .sig_prefixes = v->payload+40UL,
    .result_cnt = 16UL, .results = res
  };
  memcpy( r.uuid, v->payload+12UL, 16UL );
  FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
  r.sig_prefix_cnt = 16UL;
  FD_TEST( fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );

  /* ExecutionResult with reason 45 or the repr value 222: refused */
  static char const * const bad_reason[] = { "neg_c2r_exec_reason_45", "neg_c2r_exec_reason_repr_222" };
  for( ulong i=0UL; i<2UL; i++ ) {
    v = vec( bad_reason[ i ] );
    /* tag, slot, uuid, Transactions, 1 sig, 1 result, NotIncluded, reason */
    ulong roff = 4UL+8UL+16UL+4UL+8UL+16UL+8UL;
    FD_TEST( FD_LOAD( uint, v->payload+roff )==FD_GRAVITY_RESULT_NOT_INCLUDED );
    res[ 0 ] = (fd_gravity_result_t){ .kind = FD_GRAVITY_RESULT_NOT_INCLUDED, .reason = FD_LOAD( uint, v->payload+roff+4UL ) };
    FD_TEST( res[ 0 ].reason==45U || res[ 0 ].reason==222U );
    r = (fd_gravity_exec_result_t){ .slot = FD_LOAD( ulong, v->payload+4UL ), .sig_prefix_cnt = 1UL,
                                    .sig_prefixes = v->payload+40UL, .result_cnt = 1UL, .results = res };
    memcpy( r.uuid, v->payload+12UL, 16UL );
    FD_TEST( !fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r ) );
    /* With a valid reason the rest of the message is byte identical */
    res[ 0 ].reason = FD_GRAVITY_NI_SLOT_ENDED;
    sz = fd_gravity_encode_exec_result( enc_buf, sizeof(enc_buf), &r );
    FD_TEST( sz==v->payload_sz );
    FD_TEST( !memcmp( enc_buf, v->payload, roff+4UL ) && !memcmp( enc_buf+roff+8UL, v->payload+roff+8UL, sz-roff-8UL ) );
  }

  /* Progress with FfiOption tag 2: a non-zero flag encodes as 1 */
  v = vec( "neg_c2r_progress_ffioption_tag_2" );
  fd_gravity_progress_t p = {
    .slot = FD_LOAD( ulong, v->payload+4UL ), .observed_at = FD_LOAD( ulong, v->payload+12UL ),
    .current_slot_progress = v->payload[ 20 ], .has_duration_override = 2
  };
  FD_TEST( v->payload[ 21 ]==2 );
  sz = fd_gravity_encode_progress( enc_buf, sizeof(enc_buf), &p );
  FD_TEST( sz==v->payload_sz+8UL && enc_buf[ 21 ]==1 && !memcmp( enc_buf, v->payload, 21UL ) );

  /* All NEG vectors were visited */
  for( ulong i=0UL; i<GRAVITY_WIRE_VEC_CNT; i++ ) {
    if( !strcmp( gravity_wire_vecs[ i ].kind, "NEG" ) && !vec_used[ i ] ) FD_LOG_ERR(( "NEG vector %s not tested", gravity_wire_vecs[ i ].name ));
  }
  FD_LOG_NOTICE(( "neg: ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  guard_init();
  fd_sha512_t _sha[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  FD_TEST( sha );

  test_frames();
  test_bootstrap( sha );
  test_handshake();
  test_progress();
  test_pong();
  test_transaction();
  test_bundle();
  test_exec_result();
  test_c2r_unsent();
  test_ping();
  test_r2c_ignored();
  test_graph();
  test_graph_edge_cases();
  test_sig_prefix();
  test_jito_bundle_id();
  test_reasons();
  test_neg();

  /* Every vector in the fixture was driven by some check above */
  ulong unused = 0UL;
  for( ulong i=0UL; i<GRAVITY_WIRE_VEC_CNT; i++ ) {
    if( vec_used[ i ] ) continue;
    FD_LOG_WARNING(( "vector %s %s not tested", gravity_wire_vecs[ i ].kind, gravity_wire_vecs[ i ].name ));
    unused++;
  }
  FD_TEST( !unused );
  FD_LOG_NOTICE(( "all %lu vectors tested", (ulong)GRAVITY_WIRE_VEC_CNT ));

  fd_sha512_delete( fd_sha512_leave( sha ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
