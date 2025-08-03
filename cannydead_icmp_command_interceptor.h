// filepath: /Users/olkeksandrkrasila/EDUCATION/rootkit-icmp/cannydead_icmp_command_interceptor.h
#pragma once

unsigned int icmp_command_interceptor(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state);