#!/bin/bash
#

echo "Cloning libitns from git.."
cd ~
git clone https://github.com/mfontanini/libtins.git


echo "Installing requirements (libpcap, libssl, cmake, g++)"

sudo apt install libpcap-dev libssl-dev cmake -y
sudo apt install g++ -y


echo "Compiling libtins.."

cd ~/libtins
mkdir -p build
cd build
cmake ../ -DLIBTINS_ENABLE_CXX11=1
make

sudo make install


echo "Updating ldconfig cache.."
sudo ldconfig


echo "Cloning attack repo.."
cd ~
pwd
git clone https://git.breakpointingbad.com/beau/VeepExploit.git
