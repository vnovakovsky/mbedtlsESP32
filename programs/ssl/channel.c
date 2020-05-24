#include "channel.h"
#include "mbedtls/net_sockets.h"

#ifdef USE_NET_SOCKETS

// implementation of channel interface for sockets.

int channel_init(struct mbedtls_net_context* pContext)
{
    mbedtls_net_init(pContext);
    return 0;
}


int channel_connect(struct mbedtls_net_context* pContext, channel_address_t address)
{
    return mbedtls_net_connect(pContext, address.bind_ip, address.port, address.proto);
}


int channel_setup(struct mbedtls_net_context* pContext, channel_address_t address)
{
    return mbedtls_net_bind(pContext, address.bind_ip, address.port, address.proto);
}


int channel_accept(struct mbedtls_net_context* pContextListen, struct mbedtls_net_context* pContextClient, channel_address_t address)
{
    return mbedtls_net_accept(pContextListen, pContextClient,
        address.client_ip, address.buf_size, address.ip_len);
}

int channel_close(struct mbedtls_net_context* pContext);

int channel_free(struct mbedtls_net_context* pContext)
{
    mbedtls_net_free(pContext);
    return 0;
}

#endif // USE_NET_SOCKETS