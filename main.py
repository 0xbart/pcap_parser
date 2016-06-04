#* coding: UTF-8 *
#/usr/bin/python

import os
import sys
import json
import dpkt
import time
import socket
import urllib
import argparse

from IPy import IP as IP_checker


array = {
    'src': {},
    'dst': {}
}


def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)


def get_src_dst_ip(pcap):
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # First, get all IP sources
        try:
            if ip_to_str(ip.src) != '0.0.0.0':
                array['src'][ip_to_str(ip.src)]['count'] += 1
        except KeyError:
            if ip_to_str(ip.src) != '0.0.0.0':
                array['src'][ip_to_str(ip.src)] = {}
                array['src'][ip_to_str(ip.src)]['count'] = 1

        # Second, get all IP destinations
        try:
            if ip_to_str(ip.dst) != '0.0.0.0':
                array['dst'][ip_to_str(ip.dst)]['count'] += 1
        except KeyError:
            if ip_to_str(ip.dst) != '0.0.0.0':
                array['dst'][ip_to_str(ip.dst)] = {}
                array['dst'][ip_to_str(ip.dst)]['count'] = 1


def get_ip_geo():
    for src_ip in array['src']:
        if IP_checker(src_ip).iptype() == 'PRIVATE':
            break

        # Example url: http://ip-api.com/json/IP_IP_IP_IP
        url = 'http://ip-api.com/json/{ip}'.format(ip=src_ip)
        response = urllib.urlopen(url)
        data = json.loads(response.read())

        for key in data:
            array['src'][src_ip][key] = {}
            array['src'][src_ip][key] = data[key]

    for dst_ip in array['dst']:
        if IP_checker(dst_ip).iptype() == 'PRIVATE':
            break

        # Example url: http://ip-api.com/json/IP_IP_IP_IP
        url = 'http://ip-api.com/json/{ip}'.format(ip=dst_ip)
        response = urllib.urlopen(url)
        data = json.loads(response.read())

        for key in data:
            array['dst'][dst_ip][key] = {}
            array['dst'][dst_ip][key] = data[key]


def dump_array_to_json():
    try:
        f = open('dump.json', 'w')
        f.write(json.dumps(array, indent=4, sort_keys=True))
        f.close()
    except Exception as e:
        print 'Dump to json failed! Reason: {error}'.format(error=str(e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Full path to PCAP file.")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print "Given file doesn't exist."
        sys.exit()

    with open(args.file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        get_src_dst_ip(pcap)

    get_ip_geo()
    dump_array_to_json()
