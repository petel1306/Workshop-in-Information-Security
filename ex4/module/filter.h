#ifndef _FILTER_H_
#define _FILTER_H_

#include "fw.h"

unsigned int fw_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int fw_faker(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif