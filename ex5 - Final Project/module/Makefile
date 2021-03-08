obj-m := firewall.o
firewall-objs := fw.o parser.o ruler.o logger.o tracker.o proxy.o filter.o hw5secws.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
