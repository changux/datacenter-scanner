# Datacenter Scanner

This can be used to scan datacenters for physical and virtual machines

## Usage

You will have to install python-nmap.  A tarball can be found here: https://bitbucket.org/xael/python-nmap/downloads/

Create subnets.config and fill it with the subnets you want to scan

`virtualenv virtualenv-scanner`

`source virtualenv-scanner/bin/activate`

`pip install -r requirements.txt`

`python3 scan.py`

Then just put in your credentials.  It will try to use your keys first if you have them.
