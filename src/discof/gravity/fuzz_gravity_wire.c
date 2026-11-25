#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "fd_gravity_wire.h"

#include <stdlib.h>

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 4 );
  fd_log_level_stderr_set( 4 );
  fd_log_level_logfile_set( 4 );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  uchar const * challenge;
  uint tag = fd_gravity_wire_boot_decode( data, size, &challenge );
  if( tag==FD_GRAVITY_WIRE_BOOT_SERVER_HELLO ) FD_TEST( challenge>=data && challenge+32UL<=data+size );

  fd_gravity_wire_msg_t msg[1];
  if( fd_gravity_wire_msg_decode( data, size, msg ) ) return 0;
  if( msg->tag==FD_GRAVITY_WIRE_R2C_BE_CHALLENGE ) {
    FD_TEST( size==4UL+FD_GRAVITY_WIRE_BE_CHALLENGE_SZ && fd_memeq( msg->be_challenge, data+4UL, FD_GRAVITY_WIRE_BE_CHALLENGE_SZ ) );
    return 0;
  }
  if( msg->tag!=FD_GRAVITY_WIRE_R2C_GRAPH ) return 0;

  /* Every element of a decoded graph decodes within the payload */
  fd_gravity_wire_graph_t const * g = msg->graph;
  FD_TEST( g->row_offsets+4UL*(g->node_cnt+1UL)<=data+size && g->col_indices+4UL*g->edge_cnt<=data+size );
  ulong off = 0UL;
  for( ulong i=0UL; i<g->node_cnt; i++ ) {
    int is_bundle; uchar const * key; uint depth;
    FD_TEST( !fd_gravity_wire_graph_node( g, &off, &is_bundle, &key, &depth ) );
  }
  off = 0UL;
  for( ulong i=0UL; i<g->tx_cnt; i++ ) {
    uchar const * txn; ulong txn_sz;
    FD_TEST( !fd_gravity_wire_graph_tx( g, &off, &txn, &txn_sz ) );
    FD_TEST( txn>=data && txn+txn_sz<=data+size );
    uchar const * prefix = fd_gravity_wire_sig_prefix( txn, txn_sz );
    if( prefix ) FD_TEST( prefix>=txn && prefix+16UL<=txn+txn_sz );
  }
  off = 0UL;
  for( ulong i=0UL; i<g->bundle_cnt; i++ ) {
    uchar const * id; ulong cnt; uchar const * txn[ 5 ]; ulong txn_sz[ 5 ];
    FD_TEST( !fd_gravity_wire_graph_bundle( g, &off, &id, &cnt, txn, txn_sz ) );
  }
  return 0;
}
