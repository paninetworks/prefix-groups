#!/usr/bin/env python3

import json
import struct
import socket
import traceback

CONF                  = None
PREFIX_GROUPS_BY_HOST = {}
PREFIX_GROUPS_BY_NAME = {}
HOSTS_BY_PREFIX_GROUP = {}
ENDPOINT_LOOKUP       = {}    # Find prefix-groups by allocated IP address


class MyException(Exception):
    pass


class PrefixGroup(object):
    """
    Prefix group object. Currently only holds prefix value, may have more in
    the future.

    """
    def __init__(self, net_name, name, parent_cidr,
                 prefix_value, prefix_bits, prefix_shift):
        self.net_name     = net_name        # Name of network this groups is in
        self.name         = name            # Something like "0+3+2"
        self.prefix_value = prefix_value    # Value stored in prefix bits
        self.prefix_bits  = prefix_bits     # How many bits for the prefix
        self.prefix_shift = prefix_shift    # How far to shift to the left

        # Calculate this groups CIDR prefix based on parent CIDR
        parent_cidr_ip   = ip2int(parent_cidr.split("/")[0])
        parent_cidr_bits = int(parent_cidr.split("/")[1])
        cidr_ip          = parent_cidr_ip + (prefix_value << prefix_shift)
        self.cidr        = "%s/%d" % (int2ip(cidr_ip),
                                      parent_cidr_bits + prefix_bits)

        # Some values for the maintenance of endpoint lists
        self.endpoint_bits   = 32-int(self.cidr.split("/")[1])
        self.smallest_ip_num = ip2int(self.cidr.split("/")[0])
        self.largest_ip_num  = self.smallest_ip_num + 2**self.endpoint_bits-1
        self.smallest_ip     = int2ip(self.smallest_ip_num)
        self.largest_ip      = int2ip(self.largest_ip_num)
        self.num_free        = 2**self.endpoint_bits
        self.endpoints       = []

        print("Created group '%s': CIDR: %s, PV: %d, PB: %d, PS: %d" %
              (self.name, self.cidr, self.prefix_value,
               self.prefix_bits, self.prefix_shift))

    def __repr__(self):
        return "Group '%s': %s" % (self.name, self.cidr)

    def allocate_address(self):
        """
        Return the next available IP address in this prefix group.

        """
        if self.num_free > 0:
            for i in range(self.smallest_ip_num, self.largest_ip_num+1):
                if i not in self.endpoints:
                    self.endpoints.append(i)
                    self.num_free -= 1
                    ip = int2ip(i)
                    print("Allocated address '%s'. "
                          "Free addresses remaining at this location: %d" %
                          (ip, self.num_free))
                    return ip
        raise MyException("@@@ ERROR! No IP address available at the "
                          "chosen location.")

    def delete_address(self, ip):
        """
        De-allocate the specified IP address.

        """
        numeric_ip = ip2int(ip)
        if numeric_ip not in self.endpoints:
            raise MyException("@@@ IP address '%s' cannot be found." % ip)

        self.endpoints.remove(numeric_ip)
        self.num_free += 1


def read_config(fname):
    """
    Read config file, which has to be in JSON format.

    """
    global CONF

    with open(fname, "r") as f:
        CONF = json.loads(f.read())


def traverse_prefix_groups(net_name,
                           parent_cidr, groups, parent_name, prefix_value,
                           start_bit, num_prefix_bits):
    """
    Groups are defined as arrays of hosts or arrays of groups. We need to
    find the maximum number of groups on each level to calculate how many
    bits are needed for a group prefix on that level.

    For example, this is a highly-nested, but valid prefix group definition
    (each letter would be the IP address of a host):

                                 Group Name     Group Prefix   Num endpoints
        [
            [ A, B, C ],         # group 0      10.0/10        4194304
            [ D ],               # group 1      10.64/10       4194304
            [                    # group 2      10.128/10
              [ E, F ],          # group 2.0    10.128/11      2097152
              [ G, H ]           # group 2.1    10.160/11      2097152
            ],
            [                    # group 3      10.192/10
              [ I, J, K ],       # group 3.0    10.192/12      1048576
              [                  # group 3.1    10.208/12
                [ N, O, P, Q ],  # group 3.1.0  10.208/13       524288
                [ R, S ],        # group 3.1.1  10.216/13       524288
              ],
              [ T ]              # group 3.2    10.224/12      1048576
            ]
        ]

    Prefix bits for the above mentioned groups. Note that no routes need to be
    set for groups, which only contain other groups, since their entire address
    space will be covered by lower-level (longer prefix) groups.

        00-- ----       10.0/10
        01-- ----       10.64/10
        10-- ----       10.128/10    (no route set)
        100- ----       10.128/11
        101- ----       10.160/11
        11-- ----       10.192/10    (no route set)
        1100 ----       10.192/12
        1101 ----       10.208/12    (no route set)
        1101 0---       10.208/13
        1101 1---       10.216/13
        1110 ----       10.224/12

    This function creates prefix-group definitions for each group, as well as a
    reverse lookup, to quickly identify the correct prefix-group based on a
    host IP.

    """
    if prefix_value is not None:
        # No prefix value is set at the very start. We don't need a group
        # structure at the top level, so only do this if we have a prefix value
        # passed in already.
        if parent_name:
            my_group_name = "%s+%d" % (parent_name, prefix_value)
        else:
            my_group_name = str(prefix_value)

        pg = PrefixGroup(
                net_name      = net_name,
                name          = my_group_name,
                parent_cidr   = parent_cidr,
                prefix_value  = prefix_value,
                prefix_bits   = num_prefix_bits,
                prefix_shift  = 32-start_bit-num_prefix_bits
             )
        pcidr = pg.cidr
        pname = my_group_name
    else:
        # At the very start, no group created. These values here will be the
        # network address range. Also, no group name, yet.
        pg    = None
        pcidr = parent_cidr
        pname = parent_name


    # Now iterate over the elements to see if there are any lists in them. We
    # first need to count them to calculate how many bits are needed in the
    # prefix for them.
    num_lists_in_list = sum(1 for g in groups if type(g) is list)
    if num_lists_in_list == 0:
        # Special case: If there are NO groups then we don't need bits to
        # encode any further groups at this level.
        new_prefix_bits = 0
    elif num_lists_in_list == len(groups) == 1:
        # Special case: If there is just a single group filling this entire
        # group here then we don't need any bits at this level either.
        new_prefix_bits = 0
    elif num_lists_in_list < len(groups):
        # Special case: Hosts and groups share the same level. This is not
        # allowed! If you want hosts here, just put them in their own
        # one-element groups.
        raise MyException(
                "@@@ ERROR! Cannot have hosts and groups at the same level!")
    else:
        # Normal case: How many bits are needed to encode the various group
        # prefixes.
        new_prefix_bits = int.bit_length(num_lists_in_list-1)

    # ... now we can go and examine each of those groups
    new_group_prefix_start_bit = start_bit + num_prefix_bits
    new_group_prefix_value     = 0
    for group_or_host in groups:
        if type(group_or_host) is list:
            traverse_prefix_groups(net_name, pcidr, group_or_host, pname,
                                   new_group_prefix_value,
                                   new_group_prefix_start_bit,
                                   new_prefix_bits)
            new_group_prefix_value += 1
        else:
            # Create lookup to find a host's group
            PREFIX_GROUPS_BY_HOST[net_name][group_or_host] = pg
            # Create lookup to find all the hosts in a prefix group
            if not pg.cidr in HOSTS_BY_PREFIX_GROUP:
                HOSTS_BY_PREFIX_GROUP[pg.cidr] = [ group_or_host ]
            else:
                HOSTS_BY_PREFIX_GROUP[pg.cidr].append(group_or_host)
            """
            # Create lookup to find a prefix-group by name. We do this here,
            # since we only want to create entries for groups that have hosts
            # associated with them.
            if pg.name not in PREFIX_GROUPS_BY_NAME:
                PREFIX_GROUPS_BY_NAME[net_name][pg.name] = pg
            """
    if num_lists_in_list > 0:
        # We are in a group that defines sub-groups. If we didn't fill the
        # entire address space of the groups with the sub groups then we will
        # implicitly discover those cases and create empty groups to fill the
        # address space. Example: A group has 3 sub groups explicitly defined.
        # Obviously, we will have to have 2 bits to encode 3, but we actually
        # can encode 4 groups. User didn't define a 4th group, so we create a
        # fourth, empty group and add it. That way, if the list of networks is
        # shown, the user can see those empty groups. They can see where there
        # is "still space" in the prefix groups.
        while new_group_prefix_value <= (2**new_prefix_bits)-1:
            traverse_prefix_groups(net_name, pcidr, [], pname,
                                   new_group_prefix_value,
                                   new_group_prefix_start_bit,
                                   new_prefix_bits)
            new_group_prefix_value += 1

    # Create the reference to the new group, but only if it's a pure prefix
    # group ("only has hosts", since those don't introduce any new prefix
    # bits). By only creating references to those, the other intermittent
    # groups we have created will disappear, since they don't have a reference
    # any more. This is ok, we don't need them, since no IP is ever assigned to
    # those.
    # Note that empty groups (either explicitly specified in the config, or
    # automatically discovered) will be referenced here, since empty groups
    # also don't introduce a new prefix level.
    if pg and pg.name not in PREFIX_GROUPS_BY_NAME and \
                new_prefix_bits == 0:
        PREFIX_GROUPS_BY_NAME[net_name][pg.name] = pg

def _get_net_info(net_name):
    for net_info in CONF['networks']:
        if net_info['name'] == net_name:
            return net_info
    raise MyException("@@@ ERROR! Did not find network '%s'." % net_name)


def create_prefix_groups_from_topology():
    """
    Creates information about prefix groups from the supplied topology info.

    """
    global PREFIX_GROUPS_LIST

    # Multiple topologies can be specified. A "topology" consists of a
    # topology-map of hosts, as well as a list of one or more 'networks' which
    # connect those hosts.
    for topology in CONF['topologies']:
        networks = topology['networks']
        topo_map = topology['map']
        for net_name in networks:
            net_info = _get_net_info(net_name)
            net_cidr = net_info['cidr']
            net_len  = int(net_cidr.split("/")[1])
            PREFIX_GROUPS_BY_HOST[net_name] = {}
            PREFIX_GROUPS_BY_NAME[net_name] = {}
            traverse_prefix_groups(net_name, net_cidr, topo_map,
                                   net_name, None, net_len, 0)

            # PREFIX_GROUPS_BY_HOST[net_name] will now have been filled in
            group_names = sorted(set(
               [ gn.name for gn in PREFIX_GROUPS_BY_HOST[net_name].values() ]))
            for gn in group_names:
                buf = "Group '%s': " % gn
                for host, group in PREFIX_GROUPS_BY_HOST[net_name].items():
                    if group.name == gn:
                        buf += "%s " % host
                print(buf)
    return


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def _get_prefix_group(net_name, host_ip, prefix=None):
    """
    Specify either host or prefix, but not both!

    """
    if net_name not in PREFIX_GROUPS_BY_HOST:  # first index is net name
        raise MyException("@@@ ERROR! Unknown network name '%s'." % net_name)

    if not host_ip or host_ip not in PREFIX_GROUPS_BY_HOST[net_name]:
        raise MyException("@@@ ERROR! Unknown host '%s' in network '%s'." %
                          (host_ip, net_name))

    pg = PREFIX_GROUPS_BY_HOST[net_name][host_ip]

    return pg


def allocate_ip(net_name, host):
    pg = _get_prefix_group(net_name, host)
    ip = pg.allocate_address()
    ENDPOINT_LOOKUP[ip] = pg
    return ip


def delete_ip(ip):
    if ip not in ENDPOINT_LOOKUP:
        raise MyException("@@@ ERROR! Don't know IP '%s'." % ip)
    pg = ENDPOINT_LOOKUP[ip]
    pg.delete_address(ip)
    del ENDPOINT_LOOKUP[ip]


def list_ips(net_name):
    eps = []
    try:
        for pg in PREFIX_GROUPS_BY_NAME[net_name].values():
            eps.extend(pg.endpoints)
        print([ int2ip(a) for a in eps ])
    except Exception as e:
        print(e)


def show_networks(selected_net_name=None, summary=False, show_hosts=False):
    if selected_net_name:
        # Don't need the net info here, just want to check that the network
        # exists.
        _get_net_info(selected_net_name)

    fstring = "%-15s   %-20s   %-16s   %-16s   %-10s   %-10s"
    fill_args = [ "Name", "CIDR", "Smallest IP", "Largest IP",
                  "Allocated", "Free" ]
    if show_hosts:
        fstring += " %-20s"
        fill_args.append("Hosts")
    headline = fstring % tuple(fill_args)
    print(headline)
    print("-"*len(headline))

    for net in CONF['networks']:
        net_name = net['name']
        if net_name not in PREFIX_GROUPS_BY_NAME or \
                selected_net_name and net_name != selected_net_name:
            continue
        pgnames = sorted([ name for name
                           in PREFIX_GROUPS_BY_NAME[net_name].keys() ])
        if summary:
            smallest_ip = 0
            largest_ip  = 0
            allocated   = 0
            free        = 0
        for pgname in pgnames:
            pg = PREFIX_GROUPS_BY_NAME[net_name][pgname]
            if summary:
                if not smallest_ip or pg.smallest_ip_num < smallest_ip:
                    smallest_ip = pg.smallest_ip_num
                if not largest_ip or pg.largest_ip_num > largest_ip:
                    largest_ip = pg.largest_ip_num
                free      += pg.num_free
                allocated += len(pg.endpoints)
            else:
                fill_args = [ pg.name, pg.cidr, pg.smallest_ip, pg.largest_ip,
                              len(pg.endpoints), pg.num_free ]
                if show_hosts:
                    host_list = HOSTS_BY_PREFIX_GROUP.get(pg.cidr, "---")
                    fill_args.append(host_list)
                print(fstring % tuple(fill_args))


        if summary:
            print(fstring % (
                  net_name, net['cidr'], int2ip(smallest_ip),
                  int2ip(largest_ip), allocated, free))
    return


def show_hosts(summary=False):
    """
    Shows information about the hosts in the cluster.

    """
    # Not all hosts may be connected to all networks. We get a full list of all
    # hosts by accumulating all those that are connected to any network.
    # We also use the first loop to start assembling the header for the output.
    fstring   = "%-15s   "
    fill_args = [ "Host" ]
    all_hosts = set()
    for net in CONF['networks']:
        net_name = net['name']
        if net_name in PREFIX_GROUPS_BY_HOST:
            fstring += "%-20s    "
            fill_args.append(net_name)
            all_hosts.update(PREFIX_GROUPS_BY_HOST[net_name].keys())
    sorted_hosts = sorted(all_hosts)

    buf = fstring % tuple(fill_args)
    print(buf)
    print("-"*len(buf))

    for host in sorted_hosts:
        fill_args = [ host ]
        for net in CONF['networks']:
            net_name = net['name']
            if net_name in PREFIX_GROUPS_BY_HOST:
                pg = PREFIX_GROUPS_BY_HOST[net_name].get(host)
                if pg:
                    fill_args.append(pg.cidr)
                else:
                    fill_args.append("---")
        print(fstring % tuple(fill_args))


def cli():
    """
    Parses commands to create/delete/list endpoints.

    """
    help_str = """Enter command:
    Examples:
        - add <net-name> <host-ip>
        - del <endpoint-ip>
        - list <net-name>
        - nets [<net-name]  (use nets+ and nets++ for more details)
        - hosts
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
            elif cmd == "nets++":
                show_networks(*elems[1:], summary=False, show_hosts=True)
            elif cmd == "hosts":
                show_hosts(*elems[1:], summary=True)
            elif cmd == "hosts+":
                show_hosts(*elems[1:], summary=True)
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
    create_prefix_groups_from_topology()
    cli()


