#!/bin/bash

KERNEL=linux-4.15

# go to user home directory
cd ~

# Step 1: install packages required for kernel compilation
sudo apt update
sudo apt install -y build-essential libncurses5-dev libssl-dev flex libelf-dev bc bison gcc make xz-utils

# Step 2: download kernel source
wget https://cdn.kernel.org/pub/linux/kernel/v4.x/${KERNEL}.tar.xz

# Step 3: extract kernel source
tar xvf ${KERNEL}.tar.xz

# Step 4: enter kernel source directory
cd ${KERNEL}

# git (Only use it for initialisation) + you need to do some git init
touch .scmversion
git init
git add .
git commit -m "first commit"

# Step 5: prepare a config file for kernel compilation
# Step 5.1: download basement of the config file
wget --no-check-certificate https://people.montefiore.uliege.be/gain/courses/info0940/asset/linux-4.15-32bit-config
# Step 5.2: rename the file to ".config". (config file must be named ".config" in the kernel source directory)
mv linux-4.15-32bit-config .config
# Step 5.3: adjust the config for the current version of kernel
make olddefconfig

# Step 6: kernel and modules compilation
make ARCH=i386 bzImage -j$(nproc)
make ARCH=i386 modules -j$(nproc)

# Step 7: kernel installation
# Step 7.1: install kernel modules
sudo make modules_install
# Step 7.2: install kernel itself
sudo make install

sudo update-grub
# -- kernel compilation and installation are completed! --

echo "Done. Please reboot for booting with the new kernel."