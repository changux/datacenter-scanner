# Datacenter Scanner

This can be used to scan datacenters for physical and virtual machines

## Usage

You will have to install python-nmap and paramiko. There are lots of tutorials for this elsewhere, and it really depends on your env. 

Create config and fill it with the subnets you want to scan.  Here is a base:

```
sites:
  - name: Site1
    subnets:
    - 192.168.0.0/24
    - 10.1.0.0/24
  - name: Site2
    subnets:
    - 10.2.0.0/24
```

Then run the scan:

`python3 scan.py`

Then just put in your credentials.  It will try to use your keys first if you have them.
