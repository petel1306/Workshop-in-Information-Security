clear
cd /home/fw/project
chmod -R 777 ex3
cd ./ex3
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
./load_rules.sh
./show_rules.sh
