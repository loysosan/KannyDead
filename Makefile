KERNELDIR:=/lib/modules/$(shell uname -r)/build

obj-m = kenny.o
kenny-objs = kenny_main.o

all: kenny.ko

kenny.ko: kenny_main.c
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
