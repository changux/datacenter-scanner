# Datacenter Scanner

This can be used to scan datacenters for physical and virtual machines

## Usage

Create subnets.config and fill it with the subnets you want to scan

`virtualenv virtualenv-scanner`

`source virtualenv-scanner/bin/activate`

`pip install -r requirements.txt`

`python3 scan.py`

Then just put in your credentials.  It will try to use your keys first if you have them.
