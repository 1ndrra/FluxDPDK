#!/bin/bash

# Rebinds the specified PCI address to vfio-pci
if [ -z "$1" ]; then    
echo "Usage: $0 <PCI_ADDRESS> (e.g., $0 0000:01:00.0)"    
exit 1
fi

sudo modprobe vfio-pci
sudo dpdk-devbind.py -b vfio-pci $1
sudo dpdk-devbind.py -s