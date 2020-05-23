//#define USE_NET_SOCKETS
#include "channel.h"

#ifdef USE_NET_SOCKETS

int channel_init(mbedtls_net_context* pContext)
{
    mbedtls_net_init(pContext);
}


int channel_connect(mbedtls_net_context* pContext, channel_address_t address)
{
    return mbedtls_net_connect(pContext, address.bind_ip, address.port, address.proto);
}


int channel_setup(mbedtls_net_context* pContext, channel_address_t address)
{
    return mbedtls_net_bind(pContext, address.bind_ip, address.port, address.proto);
}


int channel_accept(mbedtls_net_context* pContextListen, mbedtls_net_context* pContextClient, channel_address_t address)
{
    return mbedtls_net_accept(pContextListen, pContextClient,
        address.client_ip, address.buf_size, address.ip_len);
}

int channel_close(mbedtls_net_context* pContext);

int channel_free(mbedtls_net_context* pContext)
{
    mbedtls_net_free(pContext);
}

#endif // USE_NET_SOCKETS