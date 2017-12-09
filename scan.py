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

# Paramiko client configuration
UseGSSAPI = paramiko.GSS_AUTH_AVAILABLE             # enable "gssapi-with-mic" authentication, if supported by your python installation
DoGSSAPIKeyExchange = paramiko.GSS_AUTH_AVAILABLE   # enable "gssapi-kex" key exchange, if supported by your python installation
# UseGSSAPI = False
# DoGSSAPIKeyExchange = False
PORT=22

def main():
    """
    Utilizes all the below functions to scan a list of IPs
    """

    # Get username and password
    username, password = get_user()

    # List of CIDRs to scan
    scan_list = ['192.168.6.0/24']

    # We want physical boxen, we will keep them here
    physical_machines = []

    # Send the commands
    hosts = get_hosts(scan_list)
    hosts = sorted(hosts, key=lambda item: socket.inet_aton(item))
    LOG.info("Found {0} Hosts".format(len(hosts)))

    for host in hosts:
        info = get_data(host, username, password)
        if info is not None:
            physical_machines = collect_physical_machines(info, physical_machines)

    print(json.dumps(physical_machines, indent=4, sort_keys=True))
    LOG.info("Found {0} physical machines.".format(len(physical_machines)))


def build_netbox_device (device_role, manufacturer, model_name, status, site):
    """
    Builds a JSON object that we can submit to netbox
    """

    device = { 'device_role': device_role, 'manufacturer': manufacturer, 'model_name': model_name, 'status': status, 'site': site }
    return json.loads(device)


def collect_physical_machines(json_data, physical_boxen):
    """Takes a json machine object and checks to see if it's a physical machine"""

    if json_data["is_virtual"] == "false":
        try:
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

    hosts_list = []
    for cidr in cidrs:
        LOG.info("Scanning {0}....".format(cidr))
        LOG.debug(nm.scan(hosts=cidr, arguments='-n -p 22 --open -sV -A'))
        cidr_hosts = [(x, nm[x]['tcp'][22]['state']) for x in nm.all_hosts()]
        for host, status in cidr_hosts:
            LOG.deug("Host: {0} is {1}".format(host,status))
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

    # The command to get the data
    command = '''
echo "{"
echo '"name":' '"'"$(hostname)"'"',
echo '"service_tag":' '"'"$(omreport chassis info | grep Service\ Tag | awk '{print $5}')"'"',
echo '"model":' '"'"$(omreport chassis info | grep Model | awk '{print $4 " " $5}')"'"',
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
            LOG.info("Basic key auth")
            client.connect(endpoint, PORT, username, password, timeout=2)
        else:
            try:
                LOG.info("gssapikeyexchane")
                client.connect(endpoint, PORT, username, gss_auth=UseGSSAPI,
                               gss_kex=DoGSSAPIKeyExchange, timeout=2)
            except Exception:
                LOG.info("password auth")
                client.connect(endpoint, PORT, username, password, timeout=2)

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
            json_output = json.loads(decoded)
            client.close()
            LOG.info("Success!")
            return json_output
        else:
            return None

    except paramiko.ssh_exception.AuthenticationException as e:
        LOG.info('Bad Auth')
        pass
    except paramiko.ssh_exception.BadHostKeyException as e:
        LOG.info('Bad Host Key')
        pass
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        LOG.error(e)
        pass
    except paramiko.ssh_exception.SSHException as e:
        LOG.error(e)
        pass
    except ConnectionResetError as e:
        LOG.error("Connection Reset Error")
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
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    LOG = logging.getLogger("datacenter_scanner")
    LOG.setLevel(logging.INFO)
    main()
    main()
