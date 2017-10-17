# Cryptodev-Paravirtualized-Driver

# Disclaimer
This is the result of an assignment given during the course of the os 
lab at ece ntua. The assignment was based on skeleton code provided by professors.

# Description
This paravirtualized driver allows a VM, running on qemu-kvm, to access the physical cryptodev. The frontend is character device that communicates with the backend using virtuqueues. Requests to that character device are forwarded to the backend, where they are completed. The backend implements a new qemu device, where the request from the guest, are resolved by using the native cryptodev device.

# Installation

This driver has been developed for, and tested against the cryptodev-linux-1.9 available through http://nwl.cc/pub/cryptodev-linux/cryptodev-linux-1.9.tar.gz, and qemu-2.0.0 available http://wiki.qemu-project.org/download/qemu-2.0.0.tar.bz2

In order to install the cryptodev in the host machine run the following commands
```
$ wget http://nwl.cc/pub/cryptodev-linux/cryptodev-linux-1.9.tar.gz
$ gunzip cryptodev-linux-1.9.tar.gz
$ tar -xvf cryptodev-linux-1.9.tar
$ cd cryptodev-linux-1.9
$ make
$ sudo insmod cryptodev.ko
```

For the qemu source code 
```
$ wget http://wiki.qemu-project.org/download/qemu-2.0.0.tar.bz2
$ tar -xjvf qemu-2.0.0.tar.bz2
```
Now download the sources from this repository and navigate to the directory containing the sources and run 
```
$ ./setup_sources.sh /path/to/qemu/source
```
When inside the qemu source directory run
```
$ ./configure --prefix=/path/to/build/dir --target-list=x86_64-softmmu
$ make 
$ make install
```
Now start a VM using qemu-kvm and attach a virtio-crypto-pci device. The command should look like this
```
$ qemu-system-x86_64 -drive file=disk_image -device virtio-crypto-pci 
```
The only thing left is to install the character device module on the guest machine. Copy the guest directory of the repository to the guest os and make it your working directory. 
```
$ make
$ sudo ./crypto_dev_nodes.sh
$ sudo insmod virtio_crypto.ko
```
