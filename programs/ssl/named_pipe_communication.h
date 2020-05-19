#include <windows.h>
#include <stdint.h>

#define MAX_RQRS_LEN 0x1000

typedef struct {
	DWORD32 RqLen;	/* Total length of request, not including this field */
	CHAR Command;
	BYTE Record[MAX_RQRS_LEN];
} REQUEST;

typedef struct {
	DWORD32 RsLen;	/* Total length of response, not including this field */
	CHAR Status;
	BYTE Record[MAX_RQRS_LEN];
} RESPONSE;


#define RQ_SIZE sizeof (REQUEST)
#define RQ_HEADER_LEN RQ_SIZE-MAX_RQRS_LEN
#define RS_SIZE sizeof (RESPONSE)
#define RS_HEADER_LEN RS_SIZE-MAX_RQRS_LEN


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