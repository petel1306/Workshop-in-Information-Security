dmesg -c
echo 1 > /proc/sys/net/ipv4/ip_forward
clear
cd ..
echo "Starts routine:"
cd ./module
sudo rmmod firewall
make clean
make all
sudo insmod ./firewall.ko
cd ../user
make clean
make
cd ../scripts
# sudo chmod o+rw /dev/fw_log
# sudo chmod -R o+rw /sys/class/fw
./load_rules.sh
./show_rules.sh
