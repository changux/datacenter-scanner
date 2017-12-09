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

# Paramiko client configuration
UseGSSAPI = paramiko.GSS_AUTH_AVAILABLE             # enable "gssapi-with-mic" authentication, if supported by your python installation
DoGSSAPIKeyExchange = paramiko.GSS_AUTH_AVAILABLE   # enable "gssapi-kex" key exchange, if supported by your python installation
# UseGSSAPI = False
# DoGSSAPIKeyExchange = False
PORT=22

def main():

    # Get username and password
    username, password = get_user()

    # List of CIDRs to scan
    scan_list = ['192.168.6.1-253']

    # We want physical boxen
    physical_machines = []

    # Send the commands
    hosts = get_hosts(scan_list)
    hosts = sorted(hosts.items(), key=lambda item: socket.inet_aton(item[0]))
    print(hosts)
    print("Found {0} Hosts".format(len(hosts)))
    
    for host in hosts:
        info = get_data(host, username, password)
        if info is not None:
            physical_machines = collect_physical_machines(info, physical_machines)

    print(json.dumps(physical_machines, indent=4, sort_keys=True))


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
        print('Nmap not found', sys.exc_info()[0])
        sys.exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

    hosts_list = []
    for cidr in cidrs:
        print("Scanning {0}....".format(cidr))
        print(nm.scan(hosts=cidr, arguments='-n -p 22 --open -sV'))
        cidr_hosts = [(x, nm[x]['tcp'][22]['state']) for x in nm.all_hosts()]
        print(cidr_hosts)
        for host, status in cidr_hosts:
            #print("Host: {0} is {1}".format(host,status))
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


def agent_auth(transport, username):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent.
    """

    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        return

    for key in agent_keys:
        print('Trying ssh-agent key %s' % hexlify(key.get_fingerprint()))
        try:
            transport.auth_publickey(username, key)
            print('... success!')
            return
        except paramiko.SSHException:
            print('... nope.')


def get_data(endpoint, username, password):
    """
    Gets basic data from the specified endpoint.  Needs an ssh username and pass.
    Returns a JSON dict of the form:
    {
        "asset_tag": "",
        "ipaddress": "",
        "is_virtual": "",
        "model": "",
        "name": "",
        "serial": ""
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
        print('Connecting to {0}'.format(endpoint))
        if not UseGSSAPI and not DoGSSAPIKeyExchange:
            client.connect(endpoint, PORT, username, password, timeout=3)
        else:
            try:
                client.connect(endpoint, PORT, username, gss_auth=UseGSSAPI,
                               gss_kex=DoGSSAPIKeyExchange, timeout=3)
            except Exception:
                # traceback.print_exc()
                password = getpass.getpass('Password for %s@%s: ' % (username, endpoint))
                client.connect(endpoint, PORT, username, password, timeout=3)

        stdin, stdout, stderr = client.exec_command(command)
        raw = stdout.read()
        if raw:
            decoded = raw.decode("utf-8")
            json_output = json.loads(decoded)
            client.close()
            print("Successfully gathered data")
            return json_output
        else:
            return None

    except paramiko.ssh_exception.AuthenticationException as e:
        print('Could not auth with {0}'.format(endpoint))
        pass
    except paramiko.ssh_exception.BadHostKeyException as e:
        print('Bad host key exception on {0}'.format(endpoint))
        pass
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(e)
        pass
    except paramiko.ssh_exception.SSHException as e:
        print(e)
        pass
    except Exception as e:
        print('*** Caught exception: %s: %s' % (e.__class__, e))
        traceback.print_exc()
        try:
            client.close()
        except:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
