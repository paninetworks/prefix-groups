#!/usr/bin/env python3

import json
import struct
import socket
import traceback

CONF                 = None
PREFIX_GROUPS_LOOKUP = {}
PREFIX_GROUPS_LIST   = []
PREFIX_BITS          = 0
ENDPOINT_DBS         = {}
ENDPOINT_LOOKUP      = {}

class MyException(Exception):
    pass


class PrefixGroup(object):
    """
    Prefix group object. Currently only holds prefix value, may have more in
    the future.

    """
    def __init__(self, prefix):
        self.prefix = prefix

class EndpointDB(object):
    """
    Maintains information of all endpoints for a given network.

    """
    def __init__(self, name, cidr):
        endpoint_bits        = 32-int(cidr.split("/")[1])
        smallest_ip_num      = ip2int(cidr.split("/")[0])
        largest_ip_num       = smallest_ip_num + 2**endpoint_bits-1

        self.name            = name
        self.cidr            = cidr
        self.endpoint_bits   = endpoint_bits
        self.num_free        = 2**endpoint_bits
        self.smallest_ip_num = smallest_ip_num
        self.largest_ip_num  = largest_ip_num
        self.endpoints       = []


def read_config(fname):
    """
    Read config file, which has to be in JSON format.

    """
    global CONF

    with open(fname, "r") as f:
        CONF = json.loads(f.read())

def create_prefix_groups():
    """
    Creates information about prefix groups, if configured to do so.

    """
    global PREFIX_GROUPS_LOOKUP, PREFIX_GROUPS_LIST, PREFIX_BITS

    PREFIX_GROUPS_LOOKUP = {}
    PREFIX_GROUPS_LIST   = []

    # Calculate the prefix value for each group
    for prefix_value, prefix_group_hosts in enumerate(CONF['prefix_groups']):
        pg = PrefixGroup(prefix_value)
        PREFIX_GROUPS_LIST.append(pg)
        for host in prefix_group_hosts:
            PREFIX_GROUPS_LOOKUP[host] = pg
            print("... topology prefix for host '%s': %d" %
                                    (host, prefix_value))

    # Store how many bits should be used for the prefix
    if CONF['topology_prefixes']:
        PREFIX_BITS = int.bit_length(prefix_value)
        print("... need %d bits for topology prefix." % PREFIX_BITS)

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def create_endpoint_dbs():
    """
    Create the DBs for endpoints (per network).

    """
    global ENDPOINT_DBS

    ENDPOINT_DBS = {}

    for net_info in CONF['networks']:
        net_name = net_info['name']
        net_cidr = net_info['cidr']
        net_cidr_base, net_cidr_mask_str = net_cidr.split("/")
        net_cidr_mask = int(net_cidr_mask_str)
        # Each prefix group gets its own network, which is a chunk of this
        # network here. The name is derived from the original net_name + the
        # prefix index. The CIDR is a carved up portion of the original CIDR.

        # The new netmask is calculated from the mask of the network CIDR plus
        # the number of bits we need for the prefix groups.
        if CONF['topology_prefixes']:
            mask = net_cidr_mask + PREFIX_BITS
            print("... carving up '%s' (CIDR: %s)" % (net_name, net_cidr))
            for pg in PREFIX_GROUPS_LIST:
                name = "%s+%d" % (net_name, pg.prefix)
                cidr = "%s/%d" % (
                        int2ip(ip2int(net_cidr_base) + (pg.prefix << 32-mask)),
                        mask)
                print("... ... %s : %s" % (name, cidr))
                ENDPOINT_DBS[name] = EndpointDB(name, cidr)
        else:
            ENDPOINT_DBS[net_name] = EndpointDB(net_name, net_cidr)


def _get_netdb(net_name, host_ip, prefix=None):
    """
    Specify either host or prefix, but not both!

    """
    if host_ip:
        if host_ip not in PREFIX_GROUPS_LOOKUP:
            raise MyException("@@@ ERROR! Unknown host '%s'." % host_ip)
        pg = PREFIX_GROUPS_LOOKUP[host_ip]
        prefix = pg.prefix
    if CONF['topology_prefixes']:
        full_net_name = "%s+%d" % (net_name, prefix)
    else:
        full_net_name = net_name
    if full_net_name not in ENDPOINT_DBS:
        raise MyException("@@@ ERROR! Unknown network name '%s'." % net_name)
    return ENDPOINT_DBS[full_net_name]

def allocate_ip(net_name, host):
    netdb = _get_netdb(net_name, host)
    if netdb.num_free > 0:
        for i in range(netdb.smallest_ip_num, netdb.largest_ip_num+1):
            if i not in netdb.endpoints:
                netdb.endpoints.append(i)
                netdb.num_free -= 1
                ip = int2ip(i)
                print("Allocated address '%s'. "
                      "Free addresses remaining on net '%s': %d" %
                      (ip, net_name, netdb.num_free))
                ENDPOINT_LOOKUP[ip] = netdb
                return
    raise MyException("@@@ ERROR! No available IP "
                      "address for net '%s'." % net_name)

def delete_ip(ip):
    if ip not in ENDPOINT_LOOKUP:
        raise MyException("@@@ ERROR! Don't know IP '%s'." % ip)
    netdb = ENDPOINT_LOOKUP[ip]
    ipnum = ip2int(ip)
    if ipnum not in netdb.endpoints:
        raise MyException("@@@ ERROR! IP '%s' not allocated in network '%s'." %
                          (ip, netdb.name))
    netdb.endpoints.remove(ipnum)
    netdb.num_free += 1
    del ENDPOINT_LOOKUP[ip]

def list_ips(net_name):
    eps = []
    try:
        if CONF['topology_prefixes']:
            for pg in PREFIX_GROUPS_LIST:
                netdb = _get_netdb(net_name, None, pg.prefix)
                eps.extend(netdb.endpoints)
        else:
            netdb = _get_netdb(net_name, None, None)
            eps = netdb.endpoints
        print([ int2ip(a) for a in eps])
    except Exception as e:
        print(e)


def show_networks(summary=False):
    if not CONF['topology_prefixes']:
        # If we don't use prefix bits then we never need to summarize
        summary = False
    fstring = "%-15s   %-20s   %-16s   %-16s   %-10s   %-10s"
    headline = fstring % ("Name", "CIDR", "Smallest IP", "Largest IP",
                          "Allocated", "Free")
    print(headline)
    print("-"*len(headline))
    if summary:
        net_names = [ n['name'] for n in CONF["networks"] ]
        cidrs     = dict([ (n['name'], n['cidr']) for n in CONF["networks"] ])
    else:
        net_names = ENDPOINT_DBS.keys()
    net_names = sorted(net_names)
    for name in net_names:
        if summary:
            num_allocated = 0
            num_free      = 0
            cidr          = cidrs[name]
            smallest_ip   = None
            largest_ip    = None
            for pg in PREFIX_GROUPS_LIST:
                nn = "%s+%d" % (name, pg.prefix)
                d = ENDPOINT_DBS[nn]
                num_allocated += len(d.endpoints)
                num_free      += d.num_free
                if not smallest_ip:
                    smallest_ip = int2ip(d.smallest_ip_num)
                largest_ip = int2ip(d.largest_ip_num)

            print(fstring % (
                  name, cidr, smallest_ip, largest_ip,
                  num_allocated, num_free))


        else:
            d = ENDPOINT_DBS[name]
            print(fstring % (
                  d.name, d.cidr, int2ip(d.smallest_ip_num),
                  int2ip(d.largest_ip_num), len(d.endpoints),
                  d.num_free))

def cli():
    """
    Parses commands to create/delete/list endpoints.

    """
    help_str = """Enter command:
    Examples:
        - add <net-name> <host-ip>
        - del <endpoint-ip>
        - list <net-name>
        - nets
        - quit
        - help
    """
    print(help_str)
    while True:
        try:
            raw_line = input("> ")
            elems = raw_line.split()
            if not elems:
                continue
            cmd = elems[0]
            if cmd in ["help", "h", "?"]:
                print(help_str)
            elif cmd in ["quit", "q"]:
                break
            elif cmd == "add":
                allocate_ip(*elems[1:])
            elif cmd == "del":
                delete_ip(*elems[1:])
            elif cmd == "list":
                list_ips(*elems[1:])
            elif cmd == "nets":
                show_networks(*elems[1:], summary=True)
            elif cmd == "nets+":
                show_networks(*elems[1:], summary=False)
            else:
                raise MyException("@@@ ERROR! Unknown command '%s'." % cmd)
        except TypeError as e:
            print(traceback.print_exc(e))
            print("@@@ Malformed command line!")
            print(help_str)
        except MyException as e:
            print(str(e))

    print("\n*** Exit ***\n")


if __name__ == "__main__":
    read_config("confwiz.conf")
    create_prefix_groups()
    create_endpoint_dbs()
    cli()


