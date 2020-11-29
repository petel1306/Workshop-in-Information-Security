cd /home/fw/project/ex3/module
sudo rmmod firewall
make clean
make
sudo insmod ./firewall.ko
cd ../user
make clean
make
cd ..