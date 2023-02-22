import argparse
import datetime
import os
import socket
import struct
import sys

import dpkt


def print_packet(ts, src_ip, dst_ip, src_port, dst_port, protocol):
    # Convert timestamp to a readable format
    ts_str = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')

    # Print packet information in a readable format
    print(f"{ts_str} {src_ip}:{src_port} > {dst_ip}:{dst_port} {protocol}")


def parse_packet(packet):
    try:
        eth = dpkt.ethernet.Ethernet(packet)

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = "TCP"
                print_packet(ip.ts, src_ip, dst_ip, src_port, dst_port, protocol)

            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                src_port = udp.sport
                dst_port = udp.dport
                protocol = "UDP"
                print_packet(ip.ts, src_ip, dst_ip, src_port, dst_port, protocol)

    except Exception as e:
        print(f"Error parsing packet: {e}")


def sniff_live(interface):
    try:
        # Create a new raw socket and bind it to the specified interface
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))

        print(f"Sniffing on interface {interface}...")

        # Loop through incoming packets and parse each one
        while True:
            packet = sock.recv(2048)
            parse_packet(packet)

    except socket.error as e:
        print(f"Error creating or binding raw socket: {e}")
        sys.exit(1)


def sniff_pcap(pcap_file):
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            print(f"Reading from pcap file {pcap_file}...")

            # Loop through packets in the pcap file and parse each one
            for ts, packet in pcap:
                parse_packet(packet)

    except IOError as e:
        print(f"Error opening or reading pcap file: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="A packet sniffer for live network traffic or pcap files")
    parser.add_argument('-i', '--interface', help="The network interface to sniff (e.g. eth0)")
    parser.add_argument('-f', '--file', help="The pcap file to read packets from")
    args = parser.parse_args()

    if not args.interface and not args.file:
        parser.error("Please specify either an interface or a pcap file")

    if args.interface and args.file:
        parser.error("Please specify only one of interface or file")

    if args.interface:
        sniff_live(args.interface)

    if args.file:
        sniff_pcap(args.file)


if __name__ == '__main__':
    main()
