#!/usr/bin/env python

# First boot configuration for Gandi IaaS virtual machine

try:
    import json
except ImportError:
    import simplejson as json

if not hasattr(json, 'dumps'):
    json.dumps = json.write
    json.loads = json.read

import grp
import os
import posix
import pwd
import subprocess
import sys
import getopt
import errno
import random
import re
from socket import inet_pton, AF_INET


this_os_names = [os.uname()[0]]
if os.path.isdir('/etc/sysconfig/'):
    this_os_names.append('Redhat')
if os.path.exists('/etc/debian_version'):
    this_os_names.append('Debian')
if os.path.exists('/etc/arch-release'):
    this_os_names.append('ArchLinux')
if os.path.exists('/etc/SuSE-release'):
    this_os_names.append('openSUSE')


default_file = '/etc/default/gandi'
if not os.path.exists(default_file):
    default_file = '/etc/sysconfig/gandi'

if this_os_names[0] == "FreeBSD":
    default_file = '/etc/rc.conf.d/gandi'

_fndict = {}


def debug(fn):
    import time

    def _timed_fn(*args):
        t0 = time.time()
        try:
            return fn(*args)
        finally:
            print '%s took %s' % (fn, time.time() - t0)
    return _timed_fn


def _notimp(*args):
    return 'not implemented'


def ifon(*args):
    def _ifon(fn):
        for name in this_os_names:
            if name in args:
                _fndict[fn.__name__] = debug(fn)
        return _fndict.get(fn.__name__, _notimp)
    return _ifon


def _admin_group():
    for group in grp.getgrall():
        if group.gr_name in ('wheel', 'admin', 'users'):
            return group.gr_name


# User functions
@ifon('SunOS', 'Linux')
def add_user(user):
    return subprocess.Popen(
        ['useradd', '-m', user, '-g', _admin_group(), '-s', '/bin/bash']
    ).wait()


@ifon('FreeBSD')
def add_user(user):
    return subprocess.Popen(
        ['pw', 'adduser', user, '-G', _admin_group(), '-m']
    ).wait()


# Password functions
@ifon('Linux')
def set_password(user, passwd):
    entries = file('/etc/shadow').readlines()
    new_entries = []
    for entry in entries:
        if entry.startswith('%s:' % user):
            (user, encpw, end) = entry.split(':', 2)
            new_entries.append(':'.join((user, passwd, end)))
        else:
            new_entries.append(entry)
    file('/etc/shadow', 'w').write(''.join(new_entries))


@ifon('FreeBSD')
def set_password(user, passwd):
    return subprocess.Popen(
        ['chpass', '-p', passwd, user]
    ).wait()


# Ssh functions
def add_ssh_key(user, key):
    uinfo = pwd.getpwnam(user)
    authfile = uinfo.pw_dir + '/.ssh/authorized_keys'

    if os.path.exists('%s/.ssh/authorized_keys' % uinfo.pw_dir):
        all_keys = file(authfile).readlines()
        if '%s\n' % key in all_keys:
            return

    o_umask = os.umask(077)
    os.setegid(uinfo.pw_gid)
    os.seteuid(uinfo.pw_uid)
    try:
        os.makedirs(uinfo.pw_dir + '/.ssh', 0700)
    except OSError, err:
        if err.errno != errno.EEXIST:
            raise

    try:
        file(authfile, 'a').write('%s\n' % key)
    finally:
        os.seteuid(0)
        os.setegid(0)
        os.umask(o_umask)


# Network functions
def _netmask4(cidr):
    try:
        bits = int(cidr.split('/')[1])
        net_bits = (2 ** (bits) - 1) << 32 - bits
        return '.'.join(str((net_bits & (255 << 8 * x)) >> 8 * x)
                        for x in range(3, -1, -1))
    except:
        # fallback
        return '255.255.255.0'


def _netbits4(cidr):
    try:
        return cidr.split('/')[1]
    except:
        # fallback
        return '24'


@ifon('Linux', 'FreeBSD', 'SunOS')
def resolver_setup(nameservers):
    """Writes resolv.conf file.

    Uses 3 IPv6 nameservers (if available) for IPv6 only VM.
    Uses 2 IPv4 and 1 IPv6 nameservers otherwise.
    """
    ipv4_ns = [ns for ns in nameservers if valid_ipv4(ns)]
    ipv6_ns = [ns for ns in nameservers if not valid_ipv4(ns)]
    valid_ns = []
    if is_ipv6_only():
        # Using shuffle instead of sample to avoid error if ipv6_ns have less
        # than 3 elements
        random.shuffle(ipv6_ns)
        valid_ns = ipv6_ns[:3]
    else:
        random.shuffle(ipv4_ns)
        valid_ns = ipv4_ns[:2]
        if ipv6_ns:
            valid_ns.append(random.choice(ipv6_ns))

    with open('/etc/resolv.conf', 'w') as f:
        f.write('\n'.join("nameserver %s" % x for x in valid_ns))
        f.write('\noptions timeout:1 attempts:3 rotate\n')


def ip_family(ip):
    import socket
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return 4
    except socket.error:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return 6
    except socket.error:
        return -1


def enumerate_ips(vif_list, family=4):
    for num, vif in enumerate(vif_list):
        ret = {}
        for pna in vif.get('pna', []):
            if not family or ip_family(pna['pna_address']) == family:
                ret['address'] = pna['pna_address']
                if 'pvn' in pna:
                    ret['network'] = pna['pvn']['pvn_network']
                    if pna['pvn'].get('pvn_gateway'):
                        ret['gateway'] = pna['pvn']['pvn_gateway']
                else:
                    ret['network'] = pna['pbn']['pbn_network']
                    if pna['pbn'].get('pbn_gateway'):
                        ret['gateway'] = pna['pbn']['pbn_gateway']
                yield num, ret


def network_disable_dhcp(vif_list, default_file):
    """ As virtual interfaces are setup with information in the JSON config
        no need to use DHCP after boot.
    """
    entries = file(default_file).readlines()
    new_entries = []
    for entry in entries:
        if entry.startswith('CONFIG_NODHCP'):
            new_entries.append('CONFIG_NODHCP="%s"\n' % " ".join(i for i
                               in vif_list))
        else:
            new_entries.append(entry)
    file(default_file, 'w').write(''.join(new_entries))


def network_setup_check(default_file):
    """ Check if the system admin wants to have the network auto-configured.
    """
    for entry in file(default_file).readlines():
        if entry.startswith('CONFIG_NETWORK=0') or \
           entry.startswith('CONFIG_NETWORK = 0'):
            return False
    return True


def nameserver_setup_check(default_file):
    """ Check if the system admin wants to have the nameservers
    of Gandi or let their own.
    """
    for entry in file(default_file).readlines():
        if entry.startswith('CONFIG_NAMESERVER=0') or \
           entry.startswith('CONFIG_NAMESERVER = 0'):
            return False
    return True


@ifon('Debian')
def network_setup(hostname, vif_list):
    eth_list = []
    f = file('/etc/network/interfaces', 'w')
    f.write('auto lo\niface lo inet loopback\n')
    for num, vif in enumerate_ips(vif_list):
        f.write('auto eth%d\niface eth%d inet static\n'
                '\taddress %s\n'
                '\tnetmask %s\n' % (num,
                                    num,
                                    vif['address'],
                                    _netmask4(vif['network'])
                                    )
                )
        if num == 0:
            if vif.get('gateway'):
                f.write('\tgateway %s\n' % vif['gateway'])
            add_host(hostname, vif['address'])
        if vif['address']:
            eth_list.append('eth%s' % num)

    network_disable_dhcp(eth_list, default_file)
    hostname_setup(conf['vm_hostname'])


@ifon('Redhat')
def network_setup(hostname, vif_list):
    eth_list = []
    netw = file('/etc/sysconfig/network', 'w')
    netw.write('NETWORKING=y\n'
               'NETWORKING_IPV6=y\n'
               'HOSTNAME=%s\n' % hostname)

    for num, vif in enumerate_ips(vif_list):
        file('/etc/sysconfig/network-scripts/ifcfg-eth%d' % num,
             'w').write('DEVICE=eth%d\n'
                        'IPADDR=%s\n'
                        'NETMASK=%s\n' % (num, vif['address'],
                                          _netmask4(vif['network']))
                        )
        if num == 0:
            if vif.get('gateway'):
                netw.write('GATEWAY=%s\n' % vif.get('gateway'))
                netw.write('GATEWAYDEV=eth%d\n' % num)
            add_host(hostname, vif['address'])
        if vif['address']:
            eth_list.append('eth%s' % num)

    subprocess.Popen(['/bin/hostname', hostname]).wait()
    network_disable_dhcp(eth_list, '/etc/sysconfig/gandi')


@ifon('openSUSE')
def network_setup(hostname, vif_list):
    eth_list = []
    for num, vif in enumerate_ips(vif_list):
        file('/etc/sysconfig/network/ifcfg-eth%d' % num,
             'w').write('DEVICE=eth%d\n'
                        'IPADDR=%s\n'
                        'NETMASK=%s\n'
                        'STARTMODE=auto\n'
                        'BOOTPROTO=static\n'
                        'USERCONTROL=yes\n' % (num, vif['address'],
                                               _netmask4(vif['network']))
                        )
        if num == 0:
            if vif.get('gateway'):
                defaultroute = "default %s 0.0.0.0 eth0\n" % vif.get('gateway')
                file('/etc/sysconfig/network/routes', 'w').write(defaultroute)
            add_host(hostname, vif['address'])
        if vif['address']:
            eth_list.append('eth%s' % num)

    # specific OpenSUSE hostname setup
    file('/etc/HOSTNAME', 'w').write('%s\n' % conf['vm_hostname'])
    subprocess.Popen(['/bin/hostname', hostname]).wait()

    network_disable_dhcp(eth_list, '/etc/sysconfig/gandi')


@ifon('ArchLinux')
def network_setup(hostname, vif_list):
    eth_list = []
    for num, vif in enumerate_ips(vif_list):
        cfile = file('/etc/conf.d/network@eth%d' % num, 'w')
        cfile.write('address=%s\n'
                    'netmask=%s\n'
                    'broadcast=%s\n' % (vif['address'],
                                        _netbits4(vif['network']),
                                        vif['gateway'][:-1] + '5')
                    )

        if num == 0:
            cfile.write('gateway=%s\n' % vif['gateway'])
            add_host(hostname, vif['address'])

        if vif['address']:
            eth_list.append('eth%s' % num)

    network_disable_dhcp(eth_list, default_file)
    hostname_setup(conf['vm_hostname'])


@ifon('FreeBSD')
def network_setup(hostname, vif_list):
    """Setup network for FreeBSD:
       Do all configurations a directory /etc/rc.conf.d/network
       Add one file per vif containing the configuration
       Configure the gateway in /etc/rc.conf.d/routing
   """
    eth_list = []
    if not os.path.exists('/etc/rc.conf.d/network'):
        os.mkdir('/etc/rc.conf.d/network')
    elif not os.path.isdir('/etc/rc.conf.d/network'):
        os.unlink('/etc/rc.conf.d/network')
        os.mkdir('/etc/rc.conf.d/network')
    for num, vif in enumerate_ips(vif_list):
        cfile = file('/etc/rc.conf.d/network/vtnet%d' % num, 'w')
        cfile.write(
            'ifconfig_vtnet%d="inet %s netmask %s"\n' % (num,
                                                         vif['address'],
                                                         _netmask4(
                                                             vif['network']
                                                             )))
        eth_list.append('vtnet%s' % num)
        if num == 0:
            if vif.get('gateway'):
                cfile = file('/etc/rc.conf.d/routing', 'w')
                cfile.write('defaultrouter=%s\n' % vif['gateway'])
            add_host(hostname, vif['address'])
    for num, vif in enumerate_ips(vif_list, family=6):
        mode = 'w'
        if 'vtnet%d' % num in eth_list:
            mode = 'a'
        cfile = file('/etc/rc.conf.d/network/vtnet%d' % num, mode)
        cfile.write('ifconfig_vtnet%d_ipv6="inet6 accept_rtadv"\n' % num)
    cfile = file('/etc/rc.conf.d/rtsold', 'w')
    cfile.write('rtsold_enable="YES"')

    hostname_setup(conf['vm_hostname'])


@ifon('Debian')
def network_enable(vif_list):
    """ Activate network interface after configuration.
    """
    subprocess.Popen(['/sbin/modprobe', 'ipv6']).wait()
    for num, vif in enumerate_ips(vif_list):
        subprocess.Popen(['/sbin/ifup', 'eth%d' % num]).wait()
    subprocess.Popen(['/sbin/ip', 'link', 'set', 'dev',
                      'eth0', 'up']).wait()
    subprocess.Popen(['/usr/sbin/service', 'ssh', 'restart']).wait()


@ifon('Redhat', 'openSUSE')
def network_enable(vif_list):
    """ Activate network interface after configuration.
    """
    subprocess.Popen(['/sbin/modprobe', 'ipv6']).wait()
    for num, vif in enumerate_ips(vif_list):
        subprocess.Popen(['/sbin/ifup', 'eth%d' % num]).wait()
    subprocess.Popen(['/sbin/ip', 'link', 'set', 'dev',
                      'eth0', 'up']).wait()
    subprocess.Popen(['/usr/sbin/service', 'sshd', 'restart']).wait()


@ifon('ArchLinux')
def network_enable(vif_list):
    """
    Activate network interface after configuration.
    Archlinux uses netctl profiles.
    Enable profile then for link to systemd.
    """
    subprocess.Popen(['/usr/bin/modprobe', 'ipv6']).wait()
    for num, vif in enumerate_ips(vif_list):
        subprocess.Popen(['/usr/bin/systemctl', 'enable',
                          'network@eth%d' % num]).wait()
        subprocess.Popen(['/usr/bin/systemctl', 'start',
                          'network@eth%d' % num]).wait()
    subprocess.Popen(['/usr/bin/ip', 'link', 'set', 'dev',
                      'eth0', 'up']).wait()
    subprocess.Popen(['/usr/bin/systemctl', 'restart', 'sshd']).wait()


@ifon('FreeBSD')
def network_enable(vif_list):
    """ Activate network interface after configuration.
    """
    subprocess.Popen(['/usr/sbin/service', 'netif', 'restart']).wait()
    subprocess.Popen(['/usr/sbin/service', 'routing', 'restart']).wait()
    subprocess.Popen(['/usr/sbin/service', 'rtsold', 'restart']).wait()


@ifon('Linux')
def get_number_cpu():
    """
    Get the number of virtual CPU of the machine
    """
    try:
        return open('/proc/cpuinfo').read().count('processor\t:')
    except IOError:
        pass


@ifon('FreeBSD')
def get_number_cpu():
    """
    Get the number of virtual CPU of the machine
    """
    try:
        sysctl = subprocess.Popen(['sysctl', '-n', 'hw.ncpu'],
                                  stdout=subprocess.PIPE)
        return int(sysctl.communicate()[0])
    except (OSError, ValueError):
        pass


def network_virtio(vif_list):
    """
    Enable multiqueue for vif in virtio mode
    """
    nb_proc = get_number_cpu()
    if nb_proc > 8:
        nb_proc = 8
    for num, vif in enumerate_ips(vif_list):
        if nb_proc > 1:
            cmd = ['ethtool', '-L', 'eth%d' % num, 'combined', str(nb_proc)]
            subprocess.Popen(cmd).wait()


@ifon('Linux')
def hostname_setup(hostname):
    """Hostname and mailname configuration process mainly for Debian/Ubuntu
       and ArchLinux distribution. CentOS/RedHat is using hostname
       configuration in the ip config file.
    """
    for entry in file(default_file).readlines():
        if entry.startswith('CONFIG_HOSTNAME=1') or \
           entry.startswith('CONFIG_HOSTNAME = 1'):
            for elt in 'hostname', 'mailname':
                file('/etc/%s' % elt, 'w').write('%s\n' % hostname)
            subprocess.Popen(['/bin/hostname', hostname]).wait()


@ifon('FreeBSD')
def hostname_setup(hostname):
    """Hostname configuration for FreeBSD
       Here we prefer /etc/rc.conf.d/hostname over /etc/rc.conf
    """
    for entry in file(default_file).readlines():
        if entry.startswith('CONFIG_HOSTNAME=1') or \
           entry.startswith('CONFIG_HOSTNAME = 1'):
            hfile = file('/etc/rc.conf.d/hostname', 'w')
            hfile.write("hostname=\"%s\"\n" % hostname)
            subprocess.Popen(['/bin/hostname', hostname]).wait()
            subprocess.Popen(['service', 'hostname', 'restart']).wait()


def add_host(hostname, addr):
    """ Add hostname/IP couple in /etc/hosts file for local name resolution
        by running application.
    """
    file('/etc/hosts', 'a').write('%s\t%s\n' % (addr, hostname,))


@ifon('Linux')
def create_module_dir():
    """
    If kernel library module directory is not present, create it.
    """
    try:
        os.mkdir('/lib/modules', 0755)
    except OSError:
        pass


@ifon('FreeBSD', 'SunOS')
def create_module_dir():
    """ Nothing to do. """
    pass


def is_ipv6_only():
    """ if no network interface has IPv4 configuration """
    vifs = conf.get('vif', {})
    for vif in vifs:
        for elt in vif['pna']:
            # we also need to know if the IP address is an IPv6 and we check
            # with both subnet of Gandi (another dirty detection)
            netw = elt['pbn']['pbn_network'].split('/')[0]
            if valid_ipv4(elt['pbn']['pbn_gateway']) and \
               valid_ipv4(netw):
                return False
    return True


def valid_ipv4(addr):
    """ is this addr an IPv4 or IPV6 ? """
    try:
        inet_pton(AF_INET, addr)
    except socket.error:
        return False
    return True


if __name__ == '__main__':
    conf = json.load(file('%s/config' % os.path.dirname(sys.argv[0])))
    extra = conf.get('vm_conf', {})

    opts, args = getopt.getopt(sys.argv[1:], 'p', ["postboot"])
    for o, a in opts:
        if o in ("-p", "--postboot"):
            script = '/gandi/script'
            if os.path.exists(script):
                if extra.get('script_args'):
                    script = '{} {}'.format(script, extra['script_args'])
                subprocess.Popen(script, shell=True).wait()
            if extra.get('run'):
                subprocess.Popen(['sh', '-c', extra['run']]).wait()
            sys.exit(0)

    create_module_dir()

    if nameserver_setup_check(default_file):
        nameservers = conf.get('nameservers', [])
        resolver_setup(nameservers)

    if network_setup_check(default_file):
        network_setup(conf['vm_hostname'], conf['vif'])
        network_enable(conf['vif'])
    try:
        if os.path.exists('/sys/module/virtio_net'):
            network_virtio(conf['vif'])
    except OSError:
        pass

    if extra:
        user_list = ['root']
        if extra.get('user'):
            add_user(extra['user'])
            user_list.append(extra['user'])

        for user in user_list:
            if extra.get('password'):
                set_password(user, extra['password'])
            if extra.get('ssh_key'):
                add_ssh_key(user, extra['ssh_key'])
