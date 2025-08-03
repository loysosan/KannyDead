KERNELDIR:=/lib/modules/$(shell uname -r)/build

obj-m = cannydead.o
cannydead-objs = cannydead_main.o

all: cannydead.ko

cannydead.ko: cannydead_main.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
