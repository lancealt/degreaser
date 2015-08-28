degreaser
=========

A tool for detecting network tarpits.

## To Install
Notes on install from a blank system (CentOS 7 used).

### Dependencies:
    c++ (CentOS used gcc-c++),
    autoconf, 
    libtool,
    libpcap,
    libpcap-dev,
    libcrafter*,
    libcperm* (optional, needed if you want to scan randomly),
    libncurses-dev (optional, but needed for progress output),
    libcap-ng (not needed, currently)

*Note: install via git

 
### 1. Install libcperm (via git, permutation library):
    git clone https://github.com/lancealt/libcperm.git
    (cd libcperm; ./autogen.sh; ./configure; make; make install)
### 2. Install libcrafter (via git):
    git clone https://github.com/pellegre/libcrafter.git
    (cd libcrafter; ./autogen.sh; ./configure; make; make install)
### 3. Install degreaser (via git):
    git clone https://github.com/lancealt/degreaser.git
    (cd degreaser; ./autogen.sh; ./configure; make; make install)
### 4. Create the necessary links and cache to the most recent shared libraries
    sudo ldconfig
    (for CentOS7: add line '/usr/local/lib' to file /etc/ld.so.conf; then command: 'ldconfig -v')
### 5. to run, example useage: 
    sudo ./degreaser -d eth0 205.155.65.20/29 70.90.166.0/24 74.84.25.0/24 199.212.224.0/21

### 6. trouble shooting try:
    ldd -d degreaser


