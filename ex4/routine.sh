dmesg -c
clear
cd /home/fw/project
chmod -R 777 ex4
cd ./ex4
echo "Starts routine:"
cd ./module
sudo rmmod firewall
make clean
make
sudo insmod ./firewall.ko
cd ../user
make clean
make
cd ..
sudo chmod o+rw /dev/fw_log
sudo chmod -R o+rw /sys/class/fw
./load_rules.sh
./show_rules.sh