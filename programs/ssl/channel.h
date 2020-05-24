#include "mbedtls/config.h"

struct mbedtls_net_context; // forward declaration from mbedtls/net_sockets.h

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
	int dummy;
#elif defined(USE_NAMED_PIPE)
	const char* pipe_name;
#endif
}
channel_address_t;

// interface each messaging system should implement

int channel_init	(struct mbedtls_net_context* pContext);
int channel_connect	(struct mbedtls_net_context* pContext, channel_address_t address);
int channel_setup	(struct mbedtls_net_context* pContext, channel_address_t address);
int channel_accept	(struct mbedtls_net_context* pContextListen, struct mbedtls_net_context* pContextClient, channel_address_t address);
int channel_close	(struct mbedtls_net_context* pContext);
int channel_free	(struct mbedtls_net_context* pContext);