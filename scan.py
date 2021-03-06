#!/usr/bin/env python3

import base64
import paramiko
import nmap
import getpass
import os
import socket
import sys
import traceback
import json
import socket
import time
import logging
import yaml

# Paramiko client configuration
UseGSSAPI = paramiko.GSS_AUTH_AVAILABLE             # enable "gssapi-with-mic" authentication, if supported by your python installation
DoGSSAPIKeyExchange = paramiko.GSS_AUTH_AVAILABLE   # enable "gssapi-kex" key exchange, if supported by your python installation
# UseGSSAPI = False
# DoGSSAPIKeyExchange = False

def main():
    """
    Utilizes all the below functions to scan a list of IPs
    """
    LOG.info("Starting the scan program")

    # Get username and password
    username, password = get_user()

    scan_list = get_subnets()
 
    print("We are scanning.  Please see scan.log for more info....")
    LOG.debug("CIDR list is: {0}".format(scan_list))

    # We want physical boxen, we will keep them here
    all_machines = [None]
    physical_machines = [None]
    
    # Send the commands
    hosts = get_hosts(scan_list)
    hosts = sorted(hosts, key=lambda item: socket.inet_aton(item))
    LOG.info("Found {0} Hosts".format(len(hosts)))

    for host in hosts:
        info = get_data(host, username, password)
        if info is not None:
            all_machines.append(info)
            physical_machines = collect_physical_machines(info, physical_machines)

    # Create a file of physical machines and all machines
    LOG.debug(json.dumps(physical_machines, indent=4, sort_keys=True))
    LOG.debug(json.dumps(all_machines, indent=4, sort_keys=True))
    with open("phsyical_machines.json", 'w') as outfile:
        json.dump(physical_machines, outfile)
    with open("all_machines.json", 'w') as outfile:
        json.dump(all_machines, outfile)

    # Create a file of netbox devices
    netbox_devices = []
    for machine in physical_machines:
        netbox = build_netbox_device(machine['name'], 'unknown', 'Dell', machine['model'], 'Inventory', 'Fortrust',machine['service_tag'], machine['service_tag'])
        if netbox:
            netbox_devices.append(netbox)
    with open("netbox_devices.json", 'w') as outfile:
        json.dump(netbox_devices, outfile)

    LOG.info("Found {0} physical machines.".format(len(physical_machines)))
    LOG.info("Built {0} netbox devices.".format(len(netbox_devices)))


def get_subnets():
    """
    Scans the config file for subnets in the different sites.  Compiles them all into one big list
    """
    config_file = 'config.yaml'
    if os.path.exists(config_file):
        config = yaml.load(open(config_file, "r"))
        subnets = []
        for site in config['sites']:
            for subnet in site['subnets']:
                subnets.append(subnet)
        LOG.debug("Subnets compiled: {0}".format(subnets))
        return subnets
    else:
        LOG.error("{0} needs to exist!".format(config_file))
        print("Please create a config file at {0}".format(config_file))
        sys.exit(1)


def build_netbox_device (name, device_role, manufacturer, model_name, status, site, serial, asset_tag):
    """
    Builds a JSON object that we can submit to netbox
    """
    if name and device_role and manufacturer and model_name and status and site and serial and asset_tag:
        device = { 'device_role': device_role, 'manufacturer': manufacturer, 'model_name': model_name, 'status': status, 'site': site , 'serial': serial, 'asset_tag': asset_tag, 'name': name}
        return device
    else:
        return None


def collect_physical_machines(json_data, physical_boxen):
    """Takes a json machine object and checks to see if it's a physical machine"""

    if json_data["is_virtual"] == "false":
        try:
            if json_data not in physcial_boxen.items():
                physical_boxen.append(json_data)
        except NameError:
            physical_boxen = [json_data]

    return physical_boxen


def get_hosts(cidrs):
    """
    Does an nmap scan of the specified cidrs.  It's just a ping scan.  Returns a list of hosts.
    """
    try:
        nm = nmap.PortScanner()         # instantiate nmap.PortScanner object
    except nmap.PortScannerError:
        LOG.error('Nmap not found', sys.exc_info()[0])
        sys.exit(1)
    except:
        LOG.error("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)
    
    port = 22
    nmap_args='-n -p {} --open -sV -A '.format(port)
    hosts_list = []
    for cidr in cidrs:
        LOG.info("Scanning {0}....".format(cidr))
        LOG.debug(json.dumps(nm.scan(hosts=cidr, arguments=nmap_args), indent=4, sort_keys=True))
        cidr_hosts = [(x, nm[x]['tcp'][port]['state'], nm[x]['tcp'][port]['product'], nm[x]['tcp'][port]['version']) for x in nm.all_hosts()]
        for host, status, product, version in cidr_hosts:
            LOG.debug("{0:15} {2} version {3}".format(host,status, product, version))
            if status == "open":
                hosts_list.append(host)
    return hosts_list


def get_user():
    """
    Gets a username and password to SSH with
    """
    user = ''
    if user == '':
        default_user = getpass.getuser()
        user = input('Username [%s]: ' % default_user)
        if len(user) == 0:
            user = default_user
    if not UseGSSAPI and not DoGSSAPIKeyExchange:
        password = getpass.getpass('Password for %s: ' % (user))
    return(user, password)


def get_data(endpoint, username, password):
    """
    Gets basic data from the specified endpoint.  Needs an ssh username and pass.
    Returns a JSON dict of the form:
    {
        "ipaddress": "",
        "is_virtual": "",
        "model": "",
        "name": "",
        "service_tag": ""
    }
    """
    ssh_port=22
    # The command to get the data
    command = '''
echo "{"
echo '"name":' '"'"$(hostname)"'"',
echo '"service_tag":' '"'"$(/opt/dell/srvadmin/sbin/omreport chassis info | grep Service\ Tag | awk '{print $5}')"'"',
echo '"model":' '"'"$(/opt/dell/srvadmin/sbin/omreport chassis info | grep Model | awk '{print $4 " " $5}')"'"',
echo '"ipaddress":' '"'"$(facter ipaddress)"'"',
echo '"is_virtual":' '"'"$(facter is_virtual)"'"'
echo "}"
'''

    # now, connect and use paramiko Client to negotiate SSH2 across the connection
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        LOG.info('Connecting to {0}'.format(endpoint))
        if not UseGSSAPI and not DoGSSAPIKeyExchange:
            LOG.debug("Basic key auth")
            client.connect(endpoint, ssh_port, username, password, timeout=2)
        else:
            try:
                LOG.debug("gssapikeyexchane")
                client.connect(endpoint, ssh_port, username, gss_auth=UseGSSAPI,
                               gss_kex=DoGSSAPIKeyExchange, timeout=2)
            except Exception:
                LOG.debug("password auth")
                client.connect(endpoint, ssh_port, username, password, timeout=2)

        stdin, stdout, stderr = client.exec_command(command)

        timeout = 5 
        endtime = time.time() + timeout
        while not stdout.channel.eof_received:
            time.sleep(1)
            if time.time() > endtime:
                stdout.channel.close()
                break
        raw = stdout.read()
        if raw:
            decoded = raw.decode("utf-8")
            try:
                json_output = json.loads(decoded)
                LOG.info("Success!")
                client.close()
                return json_output
            except json.decoder.JSONDecodeError:
                LOG.error("Cannot decode output as JSON from {0}".format(endpoint))
                LOG.error("Bad Output: {0}".format(decoded))
                client.close()
                return None
            except Exception as e:
                LOG.error(e)
                return None
        else:
            return None

    except paramiko.ssh_exception.AuthenticationException as e:
        LOG.warning('Bad Auth')
        pass
    except paramiko.ssh_exception.BadHostKeyException as e:
        LOG.warning('Bad Host Key')
        pass
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        LOG.warning(e)
        pass
    except paramiko.ssh_exception.SSHException as e:
        LOG.warning(e)
        pass
    except ConnectionResetError as e:
        LOG.warning("Connection Reset Error")
        pass
    except Exception as e:
        LOG.error('*** Caught exception: %s: %s' % (e.__class__, e))
        traceback.print_exc()
        try:
            client.close()
        except:
            pass
        sys.exit(1)

if __name__ == "__main__":
    logging.basicConfig(filename='scan.log', format="%(asctime)s %(levelname)7s  %(funcName)s %(message)s")
    LOG = logging.getLogger("datacenter_scanner")
    LOG.setLevel(logging.DEBUG)
    
    main()
