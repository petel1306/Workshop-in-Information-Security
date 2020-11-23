/*
In this module the packet filtering is done.
*/

#include "filter.h"
#include "parser.h"
#include "ruler.h"
#include "logger.h"

/**
 * We perform here the packet filtering for each packet passing through the firewall
 */
static unsigned int fw_filtering(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    packet_t *packet = parse_packet(skb, state);
}