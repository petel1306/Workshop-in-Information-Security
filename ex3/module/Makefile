obj-m := firewall.o
firewall-objs := fw.o parser.o ruler.o logger.o filter.o hw3secws.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
