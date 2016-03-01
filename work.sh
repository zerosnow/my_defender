rmmod test
rm /dev/myDevice
insmod test.ko
mknod /dev/myDevice c 250 0
gcc client.c -o client `pkg-config --cflags --libs gtk+-2.0`
./client 
