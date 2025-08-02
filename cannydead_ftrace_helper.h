#pragma once

int fh_install_hook(const char *name, void *hook_func, void **orig_func);
int fh_remove_hook(const char *name);