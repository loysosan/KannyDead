#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "cannydead_ftrace_helper.h"

#define CANNYDEAD_FH_MAX_HOOKS 32

struct cannydead_fh_hook {
    const char *name;
    void *hook_func;
    void **orig_func;
    unsigned long address;
    struct ftrace_ops ops;
    int installed;
};

static struct cannydead_fh_hook cannydead_fh_hooks[CANNYDEAD_FH_MAX_HOOKS];
static int cannydead_fh_hook_count = 0;

static void notrace cannydead_fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                              struct ftrace_ops *ops, struct pt_regs *regs)
{
#if defined(CONFIG_X86_64)
    struct cannydead_fh_hook *hook = container_of(ops, struct cannydead_fh_hook, ops);
    regs->ip = (unsigned long)hook->hook_func;
#else
    #error Only x86_64 is supported
#endif
}

int fh_install_hook(const char *name, void *hook_func, void **orig_func)
{
    unsigned long addr;
    struct cannydead_fh_hook *hook;

    if (cannydead_fh_hook_count >= CANNYDEAD_FH_MAX_HOOKS)
        return -ENOMEM;

    addr = kallsyms_lookup_name(name);
    if (!addr)
        return -ENOENT;

    hook = &cannydead_fh_hooks[cannydead_fh_hook_count++];
    hook->name = name;
    hook->hook_func = hook_func;
    hook->orig_func = orig_func;
    hook->address = addr;
    hook->installed = 0;

    if (orig_func)
        *orig_func = (void *)addr;

    hook->ops.func = cannydead_fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;

    if (ftrace_set_filter_ip(&hook->ops, addr, 0, 0))
        return -EINVAL;

    if (register_ftrace_function(&hook->ops))
        return -EINVAL;

    hook->installed = 1;
    return 0;
}

int fh_remove_hook(const char *name)
{
    int i;
    for (i = 0; i < cannydead_fh_hook_count; i++) {
        struct cannydead_fh_hook *hook = &cannydead_fh_hooks[i];
        if (hook->installed && strcmp(hook->name, name) == 0) {
            unregister_ftrace_function(&hook->ops);
            ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
            hook->installed = 0;
            return 0;
        }
    }
    return -ENOENT;
}