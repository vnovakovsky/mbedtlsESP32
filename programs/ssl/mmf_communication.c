#include "mbedtls/error.h"          // MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED
#include "mbedtls/net_sockets.h"    // MBEDTLS_ERR_NET_...
#include "mmf_communication.h"
#include <windows.h>

#include <stdio.h>

static PVOID gpView = NULL;

static HANDLE ghConnectedEvent = NULL;
static HANDLE ghSignalAboutEvent = NULL;
static HANDLE ghWaitForEvent = NULL;

void hexDump(char* desc, void* addr, int len);

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
    ret = (int)read_mmf(gpView, buf);
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
    //getchar();
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int fd = ((mbedtls_net_context*)ctx)->fd;

    /*if (fd < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);*/

    //ret = (int)write(fd, buf, len);
    write_mmf(gpView, buf, len);
    
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


static const char * kConnectedEvent = "ConnectedEvent";
static const char * kWrittenByServerEvent = "WrittenByServerEvent";
static const char * kWrittenByClientEvent = "WrittenByClientEvent";

void create_event_mmf(enum PointOfView pointOfView)
{
    ghConnectedEvent = CreateEventA(
        NULL,               // default security attributes
        TRUE,               // manual-reset event
        FALSE,              // initial state is nonsignaled
        kConnectedEvent     // object name
    );

    if (ghSignalAboutEvent == NULL)
    {
        if (pointOfView == PointOfView_Server)
        {
            ghSignalAboutEvent = CreateEventA(
                NULL,               // default security attributes
                FALSE,              // manual-reset event
                FALSE,              // initial state is nonsignaled
                kWrittenByServerEvent  // object name
            );
            if (ghSignalAboutEvent == NULL)
            {
                printf("WrittenByServerEvent CreateEvent failed (%d)\n", GetLastError());
                return;
            }
        }
        else if (pointOfView == PointOfView_Client)
        {
            ghSignalAboutEvent = CreateEventA(
                NULL,               // default security attributes
                FALSE,               // manual-reset event
                FALSE,              // initial state is nonsignaled
                kWrittenByClientEvent  // object name
            );
            if (ghSignalAboutEvent == NULL)
            {
                printf("WrittenByClientEvent CreateEvent failed (%d)\n", GetLastError());
                return;
            }
        }
        else
        {
            printf("unexpected point of view (%d)\n", pointOfView);
            return;
        }
    }
    
    ///////////////////////

    if (ghWaitForEvent == NULL)
    {
        if (pointOfView == PointOfView_Server)
        {
            ghWaitForEvent = CreateEventA(
                NULL,               // default security attributes
                FALSE,               // manual-reset event
                FALSE,              // initial state is nonsignaled
                kWrittenByClientEvent  // object name
            );
            if (ghWaitForEvent == NULL)
            {
                printf("WrittenByClientEvent CreateEvent failed (%d)\n", GetLastError());
                return;
            }
        }
        else if (pointOfView == PointOfView_Client)
        {
            ghWaitForEvent = CreateEventA(
                NULL,               // default security attributes
                FALSE,               // manual-reset event
                FALSE,              // initial state is nonsignaled
                kWrittenByServerEvent  // object name
            );
            if (ghWaitForEvent == NULL)
            {
                printf("WrittenByServerEvent CreateEvent failed (%d)\n", GetLastError());
                return;
            }
        }
        else
        {
            printf("unexpected point of view (%d)\n", pointOfView);
            return;
        }
    }
}


void accept_connection_mmf()
{
    printf(">>>>> acceptConnection() waiting for client connection...");

    DWORD dwWaitResult = WaitForSingleObject(
        ghConnectedEvent, // event handle
        INFINITE);    // indefinite wait

    switch (dwWaitResult)
    {
        // Event object was signaled

    case WAIT_OBJECT_0:
        //
        // TODO: Read from the shared buffer
        //
        printf(">>>>> accept_connection_mmf(): client connected\n");
        
        break;

        // An error occurred
    default:
        printf("Wait error (%d)\n", GetLastError());
        return 0;
    }
}


void connect_mmf()
{
    if (!SetEvent(ghConnectedEvent))
    {
        printf("SetEvent failed (%d)\n", GetLastError());
        return;
    }
    printf("!!!!!!!!!!! SetEvent ghConnectedEvent - connecting...\n");
}


void close_connection_mmf()
{
    if (!ResetEvent(ghConnectedEvent))
    {
        printf("ResetEvent failed (%d)\n", GetLastError());
        return;
    }
    if (!ResetEvent(ghSignalAboutEvent))
    {
        printf("ResetEvent failed (%d)\n", GetLastError());
        return;
    }
    if (!ResetEvent(ghWaitForEvent))
    {
        printf("ResetEvent failed (%d)\n", GetLastError());
        return;
    }
    printf("!!!!!!!!!!! ResetEvent ghConnectedEvent - connection is closed\n");
}


HANDLE create_mmf()
{
    HANDLE hFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
        PAGE_READWRITE, 0, 100 * 1024, TEXT("MMFSharedData"));

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
        UnmapViewOfFile(gpView);
    }
}


void write_mmf(PVOID pView, void* buf, int nbytes)
{
    unsigned int* ptr = (unsigned int*)pView;
    *ptr = nbytes;
    ptr++;
    memcpy(ptr, buf, nbytes);
    hexDump("write_mmf: pView", pView, nbytes + sizeof(unsigned int));
    hexDump("write_mmf: buf", ptr, nbytes);
    if (!SetEvent(ghSignalAboutEvent))
    {
        printf("SetEvent failed (%d)\n", GetLastError());
        return;
    }
    printf("!!!!!!!!!!! SetEvent ghSignalAboutEvent\n");
}

int read_mmf(PVOID pView, void* buf)
{
    printf(">>>>> READ_mmf waiting on ghWaitForEvent...");

    DWORD dwWaitResult = WaitForSingleObject(
        ghWaitForEvent, // event handle
        INFINITE);    // indefinite wait

    switch (dwWaitResult)
    {
        // Event object was signaled

    case WAIT_OBJECT_0:
        //
        // TODO: Read from the shared buffer
        //
        printf(">>>>> READ_mmf reading...\n");
        //getchar();
        
        unsigned int* ptr = (unsigned int*)pView;
        unsigned int nbytes = *ptr;
        //pView = ptr + 1;
        ptr++;
        memcpy(buf, ptr, nbytes);
        hexDump("read_mmf: pView", pView, nbytes + sizeof(unsigned int));
        hexDump("read_mmf: buf", ptr, nbytes);
        return nbytes;
        break;

        // An error occurred
    default:
        printf("Wait error (%d)\n", GetLastError());
        return 0;
    }
}


void close_mmf(HANDLE hFileMap)
{
    CloseHandle(hFileMap);
    CloseHandle(ghSignalAboutEvent);
    CloseHandle(ghWaitForEvent);
}


void hexDump(char* desc, void* addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char* pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        }
        else {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}
