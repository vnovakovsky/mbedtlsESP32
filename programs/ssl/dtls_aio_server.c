/*
 *  Simple DTLS server demonstration program
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
#pragma warning( disable : 4996 ) // strcpy unsafe
#include <assert.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if !(defined(USE_NET_SOCKETS) || defined(USE_SHARED_MEMORY) || defined (USE_NAMED_PIPE))
#error dtls_aio_server requires one and only one of aforementioned define
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_time_t     time_t
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

/* Uncomment out the following line to default to IPv4 and disable IPv6 */
//#define FORCE_IPV4

#ifdef FORCE_IPV4
#define BIND_IP     "0.0.0.0"     /* Forces IPv4 */
#else
#define BIND_IP     "::"
#endif

#if !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) ||    \
    !defined(MBEDTLS_SSL_COOKIE_C) || !defined(MBEDTLS_NET_C) ||          \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) ||        \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_RSA_C) ||      \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C) ||         \
    !defined(MBEDTLS_TIMING_C)

int main( void )
{
    printf( "MBEDTLS_SSL_SRV_C and/or MBEDTLS_SSL_PROTO_DTLS and/or "
            "MBEDTLS_SSL_COOKIE_C and/or MBEDTLS_NET_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_RSA_C and/or "
            "MBEDTLS_CERTS_C and/or MBEDTLS_PEM_PARSE_C and/or "
            "MBEDTLS_TIMING_C not defined.\n" );
    return( 0 );
}
#else
#define USE_NET_SOCKETS
#if defined(_WIN32)
#include <windows.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif
#include "channel.h"
#if defined(USE_SHARED_MEMORY)
#include "mmf_communication.h"
#elif defined(USE_NAMED_PIPE)
#include "named_pipe_communication.h"
#endif

#define READ_TIMEOUT_MS 100000   /* 5 seconds */
#define DEBUG_LEVEL 5
#define JOINER_GREETING           "joiner greeting"


static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int main(int argc, char* argv[])
{
    int     mCipherSuites[4];
    mCipherSuites[0] = MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8;
    mCipherSuites[1] = MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8;
	mCipherSuites[2] = 0;
	mCipherSuites[3] = 0;
    // kPskc is stored persistently in router
    const char *kPskc = "IAMCOMMISSIONER";
    enum PskLength { kPskMaxLength = 32 };
    uint8_t jpsk[kPskMaxLength] = "";
    strcpy(jpsk, kPskc);
    uint8_t jpsk_length = strlen(jpsk);
	
	uint8_t psk[kPskMaxLength] = "";

    if (argc != 2)
    {
        printf("Usage: for psk client: dtls_psk_server PSK\n");
        return -1;
    }
    strcpy(psk, argv[1]); // PSK is used here for DTLS handshake
	
    int ret, len;
    mbedtls_net_context client_fd;
#if defined(USE_NET_SOCKETS)
    mbedtls_net_context listen_fd;
#elif defined(USE_SHARED_MEMORY) || defined(USE_NAMED_PIPE)
    mbedtls_net_context* pContext = &client_fd;
#endif
    unsigned char buf[1024 * 10];
    const char *pers = "dtls_server";
    unsigned char client_ip[16] = { 0 };
    size_t cliip_len;
    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_timing_delay_context timer;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif
#if defined(USE_NET_SOCKETS)
    channel_init( &listen_fd );
    
#elif defined(USE_SHARED_MEMORY)
    
#elif defined(USE_NAMED_PIPE)

#endif
    channel_init(&client_fd);
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ssl_cookie_init( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 2. Setup the "listening" UDP socket
     */
    printf( "  . Bind on udp/*/4433 ..." );
    fflush( stdout );
    channel_address_t address;

#if defined(USE_NET_SOCKETS)
    address.bind_ip = BIND_IP;
    address.port = "4433";
    address.proto = MBEDTLS_NET_PROTO_UDP;
    if ((ret = channel_setup(&listen_fd, address)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
}
#elif defined(USE_SHARED_MEMORY)
   
#elif defined(USE_NAMED_PIPE)
    address.pipe_name = SERVER_PIPE;
    if ((ret = channel_setup(pContext, address)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }
#endif 
    
    printf( " ok\n" );

    /*
     * 3. Seed the RNG
     */
    printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    printf( "  . Setting up the DTLS data..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    mbedtls_ssl_conf_handshake_timeout(&conf, 8000, 60000);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ciphersuites(&conf, mCipherSuites);
    mbedtls_ssl_conf_psk(&conf, (const unsigned char*)psk, strlen(psk),
        (const unsigned char*)"keyid", 5);

    if( ( ret = mbedtls_ssl_cookie_setup( &cookie_ctx,
                                  mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_dtls_cookies( &conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                               &cookie_ctx );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );

    printf( " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif
#if defined(USE_NET_SOCKETS)
    channel_free( &client_fd );
#endif // USE_NET_SOCKETS
    mbedtls_ssl_session_reset( &ssl );
    mbedtls_ssl_set_hs_ecjpake_password(&ssl, jpsk, strlen(jpsk));

    /*
     * 3. Wait until a client connects
     */
    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );
#if defined(USE_NET_SOCKETS)
    address.client_ip = client_ip;
    address.buf_size = sizeof(client_ip);
    address.ip_len = &cliip_len;
    
#elif defined(USE_SHARED_MEMORY) || defined(USE_NAMED_PIPE)
	cliip_len = 1;
    client_ip[0] = 1; // dummy value for shared memory implementation - varified for NULL inside library
#endif
    if ((ret = channel_accept(&listen_fd, &client_fd, address)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }
    

    /* For HelloVerifyRequest cookies */
    if( ( ret = mbedtls_ssl_set_client_transport_id( &ssl,
                    client_ip, cliip_len ) ) != 0 )
    {
        printf( " failed\n  ! "
                "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", (unsigned int) -ret );
        goto exit;
    }
#if defined(USE_NET_SOCKETS)
    mbedtls_ssl_set_bio(&ssl, &client_fd,
        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
#elif defined(USE_SHARED_MEMORY)
    mbedtls_ssl_set_bio(&ssl, &client_fd,
        mbedtls_net_send_mmf, mbedtls_net_recv_mmf, mbedtls_net_recv_timeout_mmf);
#elif defined(USE_NAMED_PIPE)
    mbedtls_ssl_set_bio(&ssl, &client_fd,
        mbedtls_net_send_pipe, mbedtls_net_recv_pipe, mbedtls_net_recv_timeout_pipe);
#endif

    printf( " ok\n" );

    /*
     * 5. Handshake
     */
    printf( "  . Performing the DTLS handshake..." );
    fflush( stdout );
    do ret = mbedtls_ssl_handshake( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        printf( " hello verification requested\n" );
        ret = 0;
        goto reset;
    }
    else if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret );
        strcpy(jpsk, kPskc); // rollback to commissioner session
        goto reset;
    }

    printf( " ok\n" );

    /*
     * 6. Read the echo Request
     */
    printf( "  < Read from client:" );
    fflush( stdout );

    len = sizeof( buf ) - 1;
    memset( buf, 0, sizeof( buf ) );

    do ret = mbedtls_ssl_read( &ssl, buf, len );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret <= 0 )
    {
        switch( ret )
        {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                printf( " timeout\n\n" );
                goto reset;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                printf( " mbedtls_ssl_read returned -0x%x\n\n", (unsigned int) -ret );
                goto reset;
        }
    }

    len = ret;
    printf( " %d bytes read\n\n%s\n\n", len, buf );
    if (strcmp("some data", buf) == 0) // regular traffic
    {
        // this is commissioner session - he passes PSKd. Server will switch to mode
        // when it will wait for Joiner. Therefore server changes jpake password to PSKd
        strcpy(jpsk, kPskc); // back to commissioner mode
        printf("regular pskc: %s\n", jpsk);
    }
    else if (strcmp(JOINER_GREETING, buf) != 0)
    {
        // this is commissioner session - he passes PSKd. Server will switch to mode
        // when it will wait for Joiner. Therefore server changes jpake password to PSKd
        strcpy(jpsk, buf);
        printf("commissioner's session: pskc: %s\n", jpsk);
    }
    else // Joiner's session
    {
        strcpy(buf, "you are joined. masterkey is 00112233445566778899aabbccddeeff");
        strcpy(jpsk, kPskc); // back to commissioner mode
        printf("joiners session: pskc: %s\n", jpsk);
    }

    /*
     * 7. Write the 200 Response
     */
    printf( "  > Write to client:" );
    fflush( stdout );

    do ret = mbedtls_ssl_write( &ssl, buf, strlen(buf) );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret < 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    printf( " %d bytes written\n\n%s\n\n", len, buf );

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    printf( "  . Closing the connection..." );
    Sleep(5000); // wait untill client will call mbedtls_ssl_close_notify (with old credentials)
                 // - otherwise server would change session password earlier then mbedtls_ssl_close_notify happens

    /* No error checking, the connection might be closed already */
#if defined(USE_NAMED_PIPE)
    // Named pipes in current config are blocked on WriteFile until data are not read
    // therefore we need to consume close notify request
    ret = mbedtls_ssl_read(&ssl, buf, len);
#endif
    do ret = mbedtls_ssl_close_notify( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

#if defined(USE_SHARED_MEMORY)

    assert(channel_close(pContext));

#elif defined(USE_NAMED_PIPE)
    channel_close(pContext);

    if ((ret = channel_setup(&pContext, SERVER_PIPE)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_bind_pipe returned %d\n\n", ret);
        goto exit;
    }
#endif

    printf( " done\n" );

    goto reset;

    /*
     * Final clean-ups and exit
     */
exit:


#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif
#if defined(USE_NET_SOCKETS)
    channel_free( &client_fd );
    channel_free( &listen_fd );
#elif defined(USE_SHARED_MEMORY)
    channel_free(pContext);

#endif
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

    return( ret );
}
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_DTLS &&
          MBEDTLS_SSL_COOKIE_C && MBEDTLS_NET_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_RSA_C
          && MBEDTLS_CERTS_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_TIMING_C */