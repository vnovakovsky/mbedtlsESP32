#include "mbedtls/config.h"
#include "mbedtls/net_sockets.h"

typedef int channel_callback_t(mbedtls_net_context* pContext);
#define USE_NET_SOCKETS
typedef struct tag_channel_address
{
#if defined(USE_NET_SOCKETS)
	const char* bind_ip;
	const char* port;
	int			proto;

	void*	client_ip;
	size_t	buf_size;
	size_t* ip_len;
#elif defined(USE_SHARED_MEMORY)
	
#elif defined(USE_NAMED_PIPE)
	const char* pipe_name;
#endif
}
channel_address_t, * pchannel_address_t;

typedef struct tag_channel
{
	channel_callback_t* channel_init;
	channel_callback_t* channel_connect;
	channel_callback_t* channel_setup;
	channel_callback_t* channel_accept;
	channel_callback_t* channel_close;
	channel_callback_t* channel_free;
} 
channel_t, * pchannel_t;

int channel_init	(mbedtls_net_context* pContext);
int channel_connect	(mbedtls_net_context* pContext, channel_address_t address);
int channel_setup	(mbedtls_net_context* pContext, channel_address_t address);
int channel_accept	(mbedtls_net_context* pContextListen, mbedtls_net_context* pContextClient, channel_address_t address);
int channel_close	(mbedtls_net_context* pContext);
int channel_free	(mbedtls_net_context* pContext);