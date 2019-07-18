#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

echo "Restarting LXC containers of deployment"
while read ctname; do
    echo "Stopping $ctname..."
    lxc-stop --name $ctname || true
done <CONTAINERS

while read ctname; do
    echo "Starting $ctname..."
    lxc-start --name $ctname || true
done <CONTAINERS
