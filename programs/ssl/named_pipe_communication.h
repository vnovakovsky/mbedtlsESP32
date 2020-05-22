#include <windows.h>
#include <stdint.h>

#include "mbedtls\net_sockets.h"


#define SERVER_PIPE "\\\\.\\PIPE\\SERVER"
#define MAX_CLIENTS  1 /* Maximum number of clients for named pipe*/

int mbedtls_net_connect_pipe(mbedtls_net_context* context, const char* pipe_name);

int mbedtls_net_bind_pipe(mbedtls_net_context* context, const char* pipe_name);

int mbedtls_net_accept_pipe(mbedtls_net_context* context);

void mbedtls_net_free_pipe(mbedtls_net_context* ctx);


/**
 * \brief          Read at most 'len' characters. If no error occurs,
 *                 the actual amount read is returned.
 *
 * \param ctx      Socket
 * \param buf      The buffer to write to
 * \param len      Maximum length of the buffer
 *
 * \return         the number of bytes received,
 *                 or a non-zero error code; with a non-blocking socket,
 *                 MBEDTLS_ERR_SSL_WANT_READ indicates read() would block.
 */
int mbedtls_net_recv_pipe(void* ctx, unsigned char* buf, size_t len);
/**
 * \brief          Write at most 'len' characters. If no error occurs,
 *                 the actual amount read is returned.
 *
 * \param ctx      Socket
 * \param buf      The buffer to read from
 * \param len      The length of the buffer
 *
 * \return         the number of bytes sent,
 *                 or a non-zero error code; with a non-blocking socket,
 *                 MBEDTLS_ERR_SSL_WANT_WRITE indicates write() would block.
 */
int mbedtls_net_send_pipe(void* ctx, const unsigned char* buf, size_t len);

/**
 * \brief          Read at most 'len' characters, blocking for at most
 *                 'timeout' seconds. If no error occurs, the actual amount
 *                 read is returned.
 *
 * \param ctx      Socket
 * \param buf      The buffer to write to
 * \param len      Maximum length of the buffer
 * \param timeout  Maximum number of milliseconds to wait for data
 *                 0 means no timeout (wait forever)
 *
 * \return         the number of bytes received,
 *                 or a non-zero error code:
 *                 MBEDTLS_ERR_SSL_TIMEOUT if the operation timed out,
 *                 MBEDTLS_ERR_SSL_WANT_READ if interrupted by a signal.
 *
 * \note           This function will block (until data becomes available or
 *                 timeout is reached) even if the socket is set to
 *                 non-blocking. Handling timeouts with non-blocking reads
 *                 requires a different strategy.
 */
int mbedtls_net_recv_timeout_pipe(void* ctx, unsigned char* buf, size_t len,
    uint32_t timeout);