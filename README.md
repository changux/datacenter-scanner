# Datacenter Scanner

This can be used to scan datacenters for physical and virtual machines

## Usage

You will have to install python-nmap and paramiko. There are lots of tutorials for this elsewhere, and it really depends on your env. 

Create subnets.config and fill it with the subnets you want to scan

`python3 scan.py`

Then just put in your credentials.  It will try to use your keys first if you have them.
