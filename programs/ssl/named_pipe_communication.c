#include "named_pipe_communication.h"
#include "mbedtls/error.h"          // MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED
#include "mbedtls/net_sockets.h"    // MBEDTLS_ERR_NET_...


int mbedtls_net_connect_pipe(mbedtls_net_context* ctx/*, const char* host,
    const char* port, int proto*/)
{
    printf("################ CONNECT.");
    if (!WaitNamedPipeA(SERVER_PIPE, NMPWAIT_WAIT_FOREVER))
        printf("WaitNamedPipe error.");
    /* An instance has become available. Attempt to open it
     * Another thread could open it first, however or the server could close the instance */
    HANDLE hNamedPipe = CreateFileA(SERVER_PIPE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ctx->fd = hNamedPipe;
    DWORD NpMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    if (!SetNamedPipeHandleState(hNamedPipe, &NpMode, NULL, NULL))
        printf("SetNamedPipeHandleState error.");
    printf("################ CONNECTED.");
}

int mbedtls_net_bind_pipe(mbedtls_net_context* ctx/*, const char* bind_ip, const char* port, int proto*/)
{
    printf("################ BIND.");
    LPSECURITY_ATTRIBUTES pNPSA = NULL;
    HANDLE hNp = CreateNamedPipeA(SERVER_PIPE, PIPE_ACCESS_DUPLEX,
        PIPE_READMODE_MESSAGE | PIPE_TYPE_MESSAGE | PIPE_WAIT,
        MAX_CLIENTS, 0, 0, INFINITE, pNPSA);

    if (hNp == INVALID_HANDLE_VALUE)
        printf("Failure to open named pipe.");
    ctx->fd = (int) hNp;
}


int mbedtls_net_accept_pipe(mbedtls_net_context* bind_ctx
    /*mbedtls_net_context* client_ctx,
    void* client_ip, size_t buf_size, size_t* ip_len*/)
{
    printf("################ ACCEPT.");
    HANDLE hNp = bind_ctx->fd;
    BOOL f = ConnectNamedPipe(hNp, NULL);
    printf("ConnectNamedPipe finished: %d\n", f);
}

/*
* Read at most 'len' characters
*/
int mbedtls_net_recv_pipe(void* ctx, unsigned char* buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int fd = ((mbedtls_net_context*)ctx)->fd;

    /*if (fd < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);
    */
    //REQUEST Request;
    //RESPONSE Response;
    DWORD nXfer;
    HANDLE hNp = ((mbedtls_net_context*)ctx)->fd;
    ReadFile(hNp, buf, len/*RQ_SIZE*/, &nXfer, NULL);
    ret = nXfer;
#if 0
    if (ret < 0)
    {
        if (net_would_block(ctx) != 0)
            return(MBEDTLS_ERR_SSL_WANT_READ);

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if (WSAGetLastError() == WSAECONNRESET)
            return(MBEDTLS_ERR_NET_CONN_RESET);
#else
        if (errno == EPIPE || errno == ECONNRESET)
            return(MBEDTLS_ERR_NET_CONN_RESET);

        if (errno == EINTR)
            return(MBEDTLS_ERR_SSL_WANT_READ);
#endif

        return(MBEDTLS_ERR_NET_RECV_FAILED);
    }
#endif //0
    return(ret);
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout_pipe(void* ctx, unsigned char* buf,
    size_t len, uint32_t timeout)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    struct timeval tv;
    fd_set read_fds;
    int fd = ((mbedtls_net_context*)ctx)->fd;

    /*if (fd < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);*/

    return mbedtls_net_recv_pipe(ctx, buf, len);

#if 0
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    ret = select(fd + 1, &read_fds, NULL, NULL, timeout == 0 ? NULL : &tv);

    /* Zero fds ready means we timed out */
    if (ret == 0)
        return(MBEDTLS_ERR_SSL_TIMEOUT);

    if (ret < 0)
    {
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if (WSAGetLastError() == WSAEINTR)
            return(MBEDTLS_ERR_SSL_WANT_READ);
#else
        if (errno == EINTR)
            return(MBEDTLS_ERR_SSL_WANT_READ);
#endif

        return(MBEDTLS_ERR_NET_RECV_FAILED);
    }

    /* This call will not block */
    return(mbedtls_net_recv(ctx, buf, len));
#endif // 0
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send_pipe(void* ctx, const unsigned char* buf, size_t len)
{
    //getchar();
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int fd = ((mbedtls_net_context*)ctx)->fd;

    /*if (fd < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);*/

        //ret = (int)write(fd, buf, len);
    //RESPONSE Response;
    //Response.Status = 1; strcpy(Response.Record, "");
    HANDLE hNamedPipe = ((mbedtls_net_context*)ctx)->fd;
    DWORD length = len;
    WriteFile(hNamedPipe, buf, len/*RS_SIZE*/, &length, NULL);
    return len;
#if 0
    if (ret < 0)
    {
        if (net_would_block(ctx) != 0)
            return(MBEDTLS_ERR_SSL_WANT_WRITE);

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if (WSAGetLastError() == WSAECONNRESET)
            return(MBEDTLS_ERR_NET_CONN_RESET);
#else
        if (errno == EPIPE || errno == ECONNRESET)
            return(MBEDTLS_ERR_NET_CONN_RESET);

        if (errno == EINTR)
            return(MBEDTLS_ERR_SSL_WANT_WRITE);
#endif

        return(MBEDTLS_ERR_NET_SEND_FAILED);
    }
#endif // 0
    //return(ret);
}

mbedtls_net_free_pipe(mbedtls_net_context* ctx)
{
    HANDLE hPipe = ctx->fd;
    CloseHandle(hPipe);
}
