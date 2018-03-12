#!/bin/sh
sudo iptables -A INPUT -p tcp --dport 48881 -j DROP
