#ifndef _FILTER_H_
#define _FILTER_H_

#include "fw.h"

static unsigned int fw_filtering(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif