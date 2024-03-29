/*
 *  Simple DTLS client demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if !(defined(USE_NET_SOCKETS) || defined(USE_SHARED_MEMORY) || defined (USE_NAMED_PIPE))
#error dtls_aio_client requires one and only one of aforementioned define
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#if !defined(MBEDTLS_SSL_CLI_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) ||    \
    !defined(MBEDTLS_NET_C)  || !defined(MBEDTLS_TIMING_C) ||             \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) ||        \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_RSA_C) ||      \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_SSL_CLI_C and/or MBEDTLS_SSL_PROTO_DTLS and/or "
            "MBEDTLS_NET_C and/or MBEDTLS_TIMING_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_RSA_C and/or "
            "MBEDTLS_CERTS_C and/or MBEDTLS_PEM_PARSE_C not defined.\n" );
    return( 0 );
}
#else

#include <string.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"
#include "channel.h"
#ifdef USE_SHARED_MEMORY
#include "mmf_communication.h"
#endif //USE_SHARED_MEMORY
#ifdef USE_NAMED_PIPE
#include <windows.h>
#include "named_pipe_communication.h"
#endif // USE_NAMED_PIPE

/* Uncomment out the following line to default to IPv4 and disable IPv6 */
//#define FORCE_IPV4

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"

#ifdef FORCE_IPV4
#define SERVER_ADDR "127.0.0.1"     /* Forces IPv4 */
#else
#define SERVER_ADDR "::1"
#endif

#define COMMISSIONER_GREETING     "commissioner greeting"
#define JOINER_GREETING           "joiner greeting"

#define READ_TIMEOUT_MS 1000
#define MAX_RETRY       5

#define DEBUG_LEVEL 5

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int main( int argc, char *argv[] )
{
    int ret, len;
    mbedtls_net_context server_fd;
    mbedtls_net_context* pContext = &server_fd;
    unsigned char buf[1024];
    const char *pers = "dtls_client";
    int retry_left = MAX_RETRY;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_timing_delay_context timer;
    int     mCipherSuites[2];
    mCipherSuites[0] = MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8;
    mCipherSuites[1] = 0;
    enum PskLength { kPskMaxLength = 32 };
    uint8_t jpsk[kPskMaxLength] = "IAMCOMMISSIONER";              // PSKc
    uint8_t jpsk_length = (uint8_t) strlen(jpsk);

    char* PSKd;
    char message[1024] = "";
    strcpy(message, COMMISSIONER_GREETING); // default commissioner greeting

    if (argc == 1)
    {
        printf("Usage: for commissioner: dtls_client PSKc PSKd;\nfor joiner: dtls_client PSKd; ");
    }

    if (argc == 3) // Commissioner case: passes PSKc for his session with router and PSKd for joiner's session
        // if Joiner try to add himself to network he passes PSKd
    {
        strcpy(jpsk, argv[1]); // PSKc is used here for DTLS handshake
        PSKd = argv[2];
        strcpy(message, PSKd); // will be passed to dtls_server(router)
    }
    else if (argc == 2) // Joiner case: tries to add himself to network passing PSKd
    {
        //PSKd = argv[1];
        strcpy(message, JOINER_GREETING);
        strcpy(jpsk, argv[1]); // PSKd is used here for DTLS handshake
    }

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    channel_init(pContext);
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 1. Start the connection
     */
    mbedtls_printf( "  . Connecting to udp/%s/%s...", SERVER_NAME, SERVER_PORT );
    fflush( stdout );
    channel_address_t address = { 0 };
#if defined(USE_NET_SOCKETS)
    address.bind_ip = SERVER_ADDR;
    address.port    = SERVER_PORT;
    address.proto   = MBEDTLS_NET_PROTO_UDP;
#elif defined(USE_SHARED_MEMORY)
    
#elif defined(USE_NAMED_PIPE)
    address.pipe_name = SERVER_PIPE;
#endif
    if ((ret = channel_connect(pContext, address)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup stuff
     */
    mbedtls_printf( "  . Setting up the DTLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                   MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                   MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_handshake_timeout(&conf, 100000, 120000);
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    mbedtls_ssl_conf_ciphersuites(&conf, mCipherSuites);
    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

#if defined(USE_NET_SOCKETS)
    mbedtls_ssl_set_bio(&ssl, &server_fd,
        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
#elif defined(USE_SHARED_MEMORY)
    mbedtls_ssl_set_bio(&ssl, &server_fd,
        mbedtls_net_send_mmf, mbedtls_net_recv_mmf, mbedtls_net_recv_timeout_mmf);
#elif defined(USE_NAMED_PIPE)
    mbedtls_ssl_set_bio(&ssl, &server_fd,
        mbedtls_net_send_pipe, mbedtls_net_recv_pipe, mbedtls_net_recv_timeout_pipe);
#endif

    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );
    mbedtls_ssl_set_hs_ecjpake_password(&ssl, jpsk, strlen(jpsk));

    mbedtls_printf( " ok\n" );

    /*
     * 4. Handshake
     */
    mbedtls_printf( "  . Performing the DTLS handshake..." );
    fflush( stdout );

    do ret = mbedtls_ssl_handshake( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 6. Write the echo request
     */
send_request:
    mbedtls_printf( "  > Write to server:" );
    fflush( stdout );

    len = strlen(message);

    do ret = mbedtls_ssl_write( &ssl, (unsigned char *)message, len );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    mbedtls_printf( " %d bytes written\n\n%s\n\n", len, message);

    /*
     * 7. Read the echo response
     */
    mbedtls_printf( "  < Read from server:" );
    fflush( stdout );

    len = strlen( buf );
    memset( buf, 0, sizeof( buf ) );

    do ret = mbedtls_ssl_read( &ssl, buf, len );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret <= 0 )
    {
        switch( ret )
        {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                mbedtls_printf( " timeout\n\n" );
                if( retry_left-- > 0 )
                    goto send_request;
                goto exit;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                mbedtls_printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n\n", (unsigned int) -ret );
                goto exit;
        }
    }

    len = ret;
    mbedtls_printf( " %d bytes read\n\n%s\n\n", len, buf );

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    mbedtls_printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
#if defined(USE_NAMED_PIPE)
    // Named pipes in current config are blocked on WriteFile until data are not read
    // therefore we need to consume close notify request
    ret = mbedtls_ssl_read(&ssl, buf, len);
#endif // USE_NAMED_PIPE
    ret = 0;
    mbedtls_printf( " done\n" );

    /*
     * 9. Final clean-ups and exit
     */
exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    channel_free(pContext);
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

    return( ret );
}
#endif /* MBEDTLS_SSL_CLI_C && MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_NET_C &&
          MBEDTLD_TIMING_C && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_RSA_C && MBEDTLS_CERTS_C &&
          MBEDTLS_PEM_PARSE_C */
