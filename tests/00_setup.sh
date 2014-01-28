#!/bin/bash

sudo apt-get install python-setuptools

if [ -f '/etc/apt.d/sources.list.d/juju-stable-precise.list' ]; then
	sudo add-apt-repository ppa:juju/stable
fi

sudo apt-get install amulet python3 python3-requests python3-pymongo juju-core charm-tools 
