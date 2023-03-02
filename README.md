<div align="center">
<img  src ="img/logo.svg"  alt="Keysas"  width=300px/>
</div>

# Keysas - USB virus cleaning station (WIP)

Warning: This is only a work in progress for now.

# Main features
- Retrieve files from USB (via keysas-io) or over the network
- Perform multiple checks
    - Run anti-virus check (ClamAV)
    - Run Yara rules
    - Run extensions and size checks

## Keysas-core architecture

<div align="center">
<img  src ="img/keysas-core-architecture.png"  alt="keysas-core architecture"  width=900px/>
</div>

Files are passed between daemons as file descriptors and using abstract sockets.

## Installation

On Debian stable:
```
echo "deb http://deb.debian.org/debian bullseye-backports main contrib non-free" > /etc/apt/sources.list.d/backports.list
apt-get update -yq
apt -qy -t bullseye-backports install libyara-dev libyara9
apt-get install -y wget make lsb-release software-properties-common libseccomp-dev clamav-daemon clamav-freshclam pkg-config git bash libudev-dev
bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly -y
git clone --depth=1 https://github.com/r3dlight/keysas && cd keysas
make help
make build
make install
```
## User documentation

User documentation can be found here : [https://keysas.fr](https://keysas.fr)

