#include "mbedtls/error.h"          // MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED
#include "mbedtls/net_sockets.h"    // MBEDTLS_ERR_NET_...
//#define USE_SHARED_MEMORY

#include "mmf_communication.h"
#include <windows.h>

#include <assert.h>
#include <stdio.h>
#include "channel.h"

#ifdef USE_SHARED_MEMORY

int channel_init(mbedtls_net_context* pContext)
{
    init_mmf(pContext)
}


int channel_connect(mbedtls_net_context* pContext, channel_address_t dummy)
{
    if (connect_mmf(pContext))
        return 0;
    return -1;
}


int channel_setup(mbedtls_net_context* pContext, channel_address_t address)
{
    assert(create_event_mmf(pContext, PointOfView_Server));
    assert(create_mmf(pContext));
    return 0;
}


int channel_accept(mbedtls_net_context* pContext)
{
    if (accept_connection_mmf(pContext))
    {
        return 0;
    }
    return -1;
}


int channel_close(mbedtls_net_context* pContext)
{
    if (close_connection_mmf)
    {
        return 0;
    }
    return -1;
}

int channel_free(mbedtls_net_context* pContext)
{
    free_mmf(pContext);
}

static int read_mmf(mbedtls_net_context* pContext, void* buf);
static BOOL write_mmf(mbedtls_net_context* pContext, const unsigned char* buf, int nbytes);
void hexDump(char* desc, void* addr, int len);

/*
* Read at most 'len' characters
*/
int mbedtls_net_recv_mmf(void* ctx, unsigned char* buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_net_context* pContext = (mbedtls_net_context*)ctx;

    if (pContext->pView < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);

    ret = (int)read_mmf(pContext, buf);

    if (ret < 0)
    {
        return(MBEDTLS_ERR_NET_RECV_FAILED);
    }
    return(ret);
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout_mmf(void* ctx, unsigned char* buf,
    size_t len, uint32_t timeout)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    return mbedtls_net_recv_mmf(ctx, buf, len);
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send_mmf(void* ctx, const unsigned char* buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_net_context* pContext = (mbedtls_net_context*)ctx;

    if (pContext->pView < 0)
        return(MBEDTLS_ERR_NET_INVALID_CONTEXT);

    if (!write_mmf(pContext, buf, len))
    {
        return(MBEDTLS_ERR_NET_SEND_FAILED);
    }
    
    return len;
}


static const char * kConnectedEvent = "ConnectedEvent";
static const char * kWrittenByServerEvent = "WrittenByServerEvent";
static const char * kWrittenByClientEvent = "WrittenByClientEvent";

void init_mmf(mbedtls_net_context* pContext)
{
    pContext->hFileMap          = NULL;
    pContext->pView             = NULL;
    pContext->hConnectedEvent   = NULL;
    pContext->hSignalAboutEvent = NULL;
    pContext->hWaitForEvent     = NULL;
}

BOOL create_event_mmf(mbedtls_net_context* pContext, enum PointOfView pointOfView)
{
    pContext->hConnectedEvent = CreateEventA(
        NULL,               // default security attributes
        TRUE,               // manual-reset event
        FALSE,              // initial state is nonsignaled
        kConnectedEvent     // object name
    );

    if (pContext->hSignalAboutEvent == NULL)
    {
        if (pointOfView == PointOfView_Server)
        {
            pContext->hSignalAboutEvent = CreateEventA(
                NULL,               // default security attributes
                FALSE,              // manual-reset event
                FALSE,              // initial state is nonsignaled
                kWrittenByServerEvent  // object name
            );
            if (pContext->hSignalAboutEvent == NULL)
            {
                printf("WrittenByServerEvent CreateEvent failed (%d)\n", GetLastError());
                return FALSE;
            }
        }
        else if (pointOfView == PointOfView_Client)
        {
            pContext->hSignalAboutEvent = CreateEventA(
                NULL,               // default security attributes
                FALSE,               // manual-reset event
                FALSE,              // initial state is nonsignaled
                kWrittenByClientEvent  // object name
            );
            if (pContext->hSignalAboutEvent == NULL)
            {
                printf("WrittenByClientEvent CreateEvent failed (%d)\n", GetLastError());
                return FALSE;
            }
        }
        else
        {
            printf("unexpected point of view (%d)\n", pointOfView);
            return FALSE;
        }
    }
    
    ///////////////////////

    if (pContext->hWaitForEvent == NULL)
    {
        if (pointOfView == PointOfView_Server)
        {
            pContext->hWaitForEvent = CreateEventA(
                NULL,               // default security attributes
                FALSE,               // manual-reset event
                FALSE,              // initial state is nonsignaled
                kWrittenByClientEvent  // object name
            );
            if (pContext->hWaitForEvent == NULL)
            {
                printf("WrittenByClientEvent CreateEvent failed (%d)\n", GetLastError());
                return FALSE;
            }
        }
        else if (pointOfView == PointOfView_Client)
        {
            pContext->hWaitForEvent = CreateEventA(
                NULL,               // default security attributes
                FALSE,               // manual-reset event
                FALSE,              // initial state is nonsignaled
                kWrittenByServerEvent  // object name
            );
            if (pContext->hWaitForEvent == NULL)
            {
                printf("WrittenByServerEvent CreateEvent failed (%d)\n", GetLastError());
                return FALSE;
            }
        }
        else
        {
            printf("unexpected point of view (%d)\n", pointOfView);
            return FALSE;
        }
    }
    return TRUE;
}


BOOL accept_connection_mmf(mbedtls_net_context* pContext)
{
    printf(">>>>> acceptConnection() waiting for client connection...");

    DWORD dwWaitResult = WaitForSingleObject(
        pContext->hConnectedEvent, // event handle
        INFINITE);    // indefinite wait

    switch (dwWaitResult)
    {
        // Event object was signaled

    case WAIT_OBJECT_0:
        //
        // TODO: Read from the shared buffer
        //
        printf(">>>>> accept_connection_mmf(): client connected\n");
        
        return TRUE;

        // An error occurred
    default:
        printf("Wait error (%d)\n", GetLastError());
        return FALSE;
    }
}


BOOL connect_mmf(mbedtls_net_context* pContext)
{
    assert(create_event_mmf(pContext, PointOfView_Client));
    assert(create_mmf(pContext));

    if (!SetEvent(pContext->hConnectedEvent))
    {
        printf("SetEvent failed (%d)\n", GetLastError());
        return FALSE;
    }
    printf("!!!!!!!!!!! SetEvent ghConnectedEvent - connecting...\n");
    return TRUE;
}


BOOL close_connection_mmf(mbedtls_net_context* pContext)
{
    if (!ResetEvent(pContext->hConnectedEvent))
    {
        printf("ResetEvent failed (%d)\n", GetLastError());
        return FALSE;
    }
    if (!ResetEvent(pContext->hSignalAboutEvent))
    {
        printf("ResetEvent failed (%d)\n", GetLastError());
        return FALSE;
    }
    if (!ResetEvent(pContext->hWaitForEvent))
    {
        printf("ResetEvent failed (%d)\n", GetLastError());
        return FALSE;
    }
    printf("!!!!!!!!!!! ResetEvent ghConnectedEvent - connection is closed\n");
    return TRUE;
}


BOOL create_mmf(mbedtls_net_context* pContext)
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
                return FALSE;
            }
        }
        pContext->hFileMap = hFileMap;
        PVOID pView = MapViewOfFile(hFileMap,
            FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

        if (pView != NULL) {
            printf("view of file mapped.");
            pContext->pView = pView;
        }
        else {
            printf("Can't map view of file.");
            return FALSE;
        }
        // File mapping created successfully.
        return TRUE;
    }
    else {
        printf("Can't create file mapping.");
        return FALSE;
    }
    return TRUE;
}


static BOOL write_mmf(mbedtls_net_context* pContext, const unsigned char* buf, int nbytes)
{
    unsigned int* ptr = (unsigned int*)pContext->pView;
    *ptr = nbytes;
    ptr++;
    memcpy(ptr, buf, nbytes);
    hexDump("write_mmf: pView", pContext->pView, nbytes + sizeof(unsigned int));
    hexDump("write_mmf: buf", ptr, nbytes);
    if (!SetEvent(pContext->hSignalAboutEvent))
    {
        printf("SetEvent failed (%d)\n", GetLastError());
        return FALSE;
    }
    printf("!!!!!!!!!!! SetEvent ghSignalAboutEvent\n");
    return TRUE;
}

static int read_mmf(mbedtls_net_context* pContext, void* buf)
{
    printf(">>>>> READ_mmf waiting on ghWaitForEvent...");

    DWORD dwWaitResult = WaitForSingleObject(
        pContext->hWaitForEvent, // event handle
        INFINITE);    // indefinite wait

    switch (dwWaitResult)
    {
        // Event object was signaled

    case WAIT_OBJECT_0:
        //
        // TODO: Read from the shared buffer
        //
        printf(">>>>> READ_mmf reading...\n");
        
        unsigned int* ptr = (unsigned int*)pContext->pView;
        unsigned int nbytes = *ptr;
        //pView = ptr + 1;
        ptr++;
        memcpy(buf, ptr, nbytes);
        hexDump("read_mmf: pView", pContext->pView, nbytes + sizeof(unsigned int));
        hexDump("read_mmf: buf", ptr, nbytes);
        return nbytes;
        break;

        // An error occurred
    default:
        printf("Wait error (%d)\n", GetLastError());
        return 0;
    }
}


void free_mmf(mbedtls_net_context* pContext)
{
    if (pContext->pView)
    {
        UnmapViewOfFile(pContext->pView);
    }
    CloseHandle(pContext->hFileMap);
    CloseHandle(pContext->hSignalAboutEvent);
    CloseHandle(pContext->hWaitForEvent);
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

#endif // USE_SHARED_MEMORY