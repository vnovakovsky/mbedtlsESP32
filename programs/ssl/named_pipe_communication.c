#include "named_pipe_communication.h"
#include "mbedtls/error.h"          // MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED
#include "mbedtls/net_sockets.h"    // MBEDTLS_ERR_NET_...
#include "channel.h"


#ifdef USE_NAMED_PIPE

int channel_init(mbedtls_net_context* pContext)
{
    pContext->hNamedPipe = NULL;
}


int channel_connect(mbedtls_net_context* pContext, channel_address_t address)
{
    return mbedtls_net_connect_pipe(pContext, address.pipe_name);
}


int channel_setup(mbedtls_net_context* pContext, channel_address_t address)
{
    return mbedtls_net_bind_pipe(pContext, address.pipe_name);
}


int channel_accept(mbedtls_net_context* dummy_context, mbedtls_net_context* pContext, channel_address_t dummy)
{
    return mbedtls_net_accept_pipe(pContext);
}


int channel_close(mbedtls_net_context* pContext)
{
    FlushFileBuffers(pContext->hNamedPipe);
    DisconnectNamedPipe(pContext->hNamedPipe);
    CloseHandle(pContext->hNamedPipe);
}

int channel_free(mbedtls_net_context* pContext)
{
    FlushFileBuffers(pContext->hNamedPipe);
    CloseHandle(pContext->hNamedPipe);
    printf("!!!client initiated DisconnectNamedPipe:\n");
    return 0;
}

int mbedtls_net_connect_pipe(mbedtls_net_context* context, const char* pipe_name)
{
    printf("################ CONNECT.");
    HANDLE hNamedPipe = 0;

    while (1)
    {
        hNamedPipe = CreateFileA(
            pipe_name,          // pipe name 
            GENERIC_READ |      // read and write access 
            GENERIC_WRITE,
            0,                  // no sharing 
            NULL,               // default security attributes
            OPEN_EXISTING,      // opens existing pipe 
            FILE_ATTRIBUTE_NORMAL, // default attributes 
            NULL);              // no template file 

        // Break if the pipe handle is valid. 
        if (hNamedPipe != INVALID_HANDLE_VALUE)
            break;
        // Exit if an error other than ERROR_PIPE_BUSY occurs. 
        if (GetLastError() != ERROR_PIPE_BUSY)
        {
            printf("Could not open pipe. GLE=%d\n", GetLastError());
            return -1;
        }
        // All pipe instances are busy, so wait for 20 seconds. 
        if (!WaitNamedPipeA(pipe_name, 60000))
        {
            printf("Could not open pipe: 20 second wait timed out.");
            return -1;
        }
    }

    context->hNamedPipe = hNamedPipe;
    DWORD NpMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    if (!SetNamedPipeHandleState(hNamedPipe, &NpMode, NULL, NULL))
    {
        printf("SetNamedPipeHandleState error.");
        return -1;
    }
    printf("################ CONNECTED.");
    return 0;
}

int mbedtls_net_bind_pipe(mbedtls_net_context* context, const char* pipe_name)
{
    printf("################ BIND.");
    LPSECURITY_ATTRIBUTES pNPSA = NULL;
    HANDLE hNp = CreateNamedPipeA(pipe_name, PIPE_ACCESS_DUPLEX,
        PIPE_READMODE_MESSAGE | PIPE_TYPE_MESSAGE | PIPE_WAIT,
        MAX_CLIENTS, 0, 0, INFINITE, pNPSA);

    if (hNp == INVALID_HANDLE_VALUE)
    {
        printf("Failure to open named pipe.");
        return INVALID_HANDLE_VALUE;
    }
    context->hNamedPipe = hNp;
    return 0;
}


int mbedtls_net_accept_pipe(mbedtls_net_context* context)
{
    printf("################ ACCEPT. ConnectNamedPipe\n");
    HANDLE hNp = context->hNamedPipe;
    BOOL is_connected = ConnectNamedPipe(hNp, NULL) ?
        TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (is_connected)
    {
        printf("ConnectNamedPipe finished: %d\n", is_connected);
        return 0;
    }
    else
    {
        printf("ConnectNamedPipe failed. The client could not connect, so close the pipe: %d\n", is_connected);
        CloseHandle(hNp);
        return -1;
    }
}

/*
* Read at most 'len' characters
*/
int mbedtls_net_recv_pipe(void* ctx, unsigned char* buf, size_t len)
{
    HANDLE hNamedPipe = ((mbedtls_net_context*)ctx)->hNamedPipe;

    if (hNamedPipe < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);

    DWORD n_received = 0;
    HANDLE hNp = ((mbedtls_net_context*)ctx)->hNamedPipe;
    BOOL is_success = ReadFile(hNp, buf, len, &n_received, NULL);
    if (!is_success)
    {
        return(MBEDTLS_ERR_NET_RECV_FAILED);
    }
    return n_received;
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout_pipe(void* ctx, unsigned char* buf,
    size_t len, uint32_t timeout)
{
    return mbedtls_net_recv_pipe(ctx, buf, len);
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send_pipe(void* ctx, const unsigned char* buf, size_t len)
{
    HANDLE hNamedPipe = ((mbedtls_net_context*)ctx)->hNamedPipe;

    if (hNamedPipe < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);

    HANDLE hNp = ((mbedtls_net_context*)ctx)->hNamedPipe;
    DWORD bytes_written = 0;
    BOOL is_success = WriteFile(hNp, buf, len, &bytes_written, NULL);

    if (!is_success)
    {
        printf("WriteFile to pipe failed. GLE=%d\n", GetLastError());
        return(MBEDTLS_ERR_NET_SEND_FAILED);
    }
    return bytes_written;
}

void mbedtls_net_free_pipe(mbedtls_net_context* ctx)
{
    HANDLE hPipe = ctx->hNamedPipe;
    CloseHandle(hPipe);
}

#endif //USE_NAMED_PIPE