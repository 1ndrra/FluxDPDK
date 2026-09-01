#!/bin/bash

# Allocates 2GB of 2MB hugepages (1024 pages). Adjust as needed.

echo "Setting up hugepages..."
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
grep Huge /proc/meminfo