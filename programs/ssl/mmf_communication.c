#include "mbedtls/error.h"          // MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED
#include "mbedtls/net_sockets.h"    // MBEDTLS_ERR_NET_...
#include "mmf_communication.h"
#include <windows.h>

static PVOID gpView = NULL;

/*
* Read at most 'len' characters
*/
int mbedtls_net_recv_mmf(void* ctx, unsigned char* buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int fd = ((mbedtls_net_context*)ctx)->fd;

    /*if (fd < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);
    */
    //PVOID pView = create_mmf();
    ret = (int)read_mmf(gpView, buf);
    //unmap_mmf(pView);
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
int mbedtls_net_recv_timeout_mmf(void* ctx, unsigned char* buf,
    size_t len, uint32_t timeout)
{
    getchar();
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    struct timeval tv;
    fd_set read_fds;
    int fd = ((mbedtls_net_context*)ctx)->fd;

    /*if (fd < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);*/

    return mbedtls_net_recv_mmf(ctx, buf, len);

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
int mbedtls_net_send_mmf(void* ctx, const unsigned char* buf, size_t len)
{
    getchar();
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int fd = ((mbedtls_net_context*)ctx)->fd;

    /*if (fd < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);*/

    //ret = (int)write(fd, buf, len);

    //PVOID pView = create_mmf();
    write_mmf(gpView, buf, len);
    //unmap_mmf(pView);
    //int left = 0;
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

// Handle of the open memory-mapped file
//static HANDLE s_hFileMap = NULL;

HANDLE create_mmf()
{
    HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
        PAGE_READWRITE, 0, 4 * 1024, TEXT("MMFSharedData"));

    if (hFileMap != NULL) {

        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            printf("Mapping already exists - not created.");

            hFileMap = OpenFileMapping(FILE_MAP_READ | FILE_MAP_WRITE,
                FALSE, TEXT("MMFSharedData"));
            if (hFileMap == NULL) {
                printf("Can't open file mapping.");
                return NULL;
            }
        }

        // File mapping created successfully.
        return hFileMap;
        
        /*PVOID pView = MapViewOfFile(s_hFileMap,
            FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

        if (pView != NULL) {
            printf("view of file mapped.");

            return pView;*/

            // Put edit text into the MMF.
            /*Edit_GetText(GetDlgItem(hwnd, IDC_DATA),
                (PTSTR)pView, 4 * 1024);
        else {
            printf("Can't map view of file.");
        }*/
    }
    else {
        printf("Can't create file mapping.");
    }
    return NULL;
}

PVOID map_mmf(HANDLE hFileMap)
{
    // Map a view of the file into the address space.
    gpView = MapViewOfFile(hFileMap,
        FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    if (gpView != NULL) {
        printf("view of file mapped.");
    }
    else {
        printf("Can't map view of file.");
    }
    return gpView;
}

void unmap_mmf(PVOID pView)
{
    if (gpView)
    {
        // Protect the MMF storage by unmapping it.
        UnmapViewOfFile(gpView);
    }
}

void write_mmf(PVOID pView, void* buf, int nbytes)
{
    unsigned int* ptr = (unsigned int*)pView;
    *ptr = nbytes;
    pView = ptr + 1;
    memcpy(pView, buf, nbytes);
}

int read_mmf(PVOID pView, void* buf)
{
    unsigned int* ptr = (unsigned int*)pView;
    unsigned int nbytes = *ptr;
    pView = ptr + 1;
    memcpy(buf, pView, nbytes);
    return nbytes;
}

void close_mmf(HANDLE hFileMap)
{
    CloseHandle(hFileMap);
}
