import os
import sys
import argparse
import binascii
import math
import pathlib

from beautifultable import BeautifulTable
from scapy.utils import PcapReader, rdpcap
from scapy.layers.l2 import Ether, Dot1Q

CURDIR = os.path.dirname(os.path.abspath(__file__))

# Traffic class specifications
tclass = {}
tclass["High"] = { "vid" : 257, "prio" : 6 }
tclass["Low"] = { "vid" : 258, "prio" : 5 }
tclass["Rtc"] = { "vid" : 0, "prio" : 4 }
tclass_cycle_time = 0.001

# Packets analysis statistics
# Inter-packet gap
ipg_stats = {}
ipg_stats["High"] = { "min" : 100000, "ave" : 0, "max" : 0 }
ipg_stats["Low"] = { "min" : 100000, "ave" : 0, "max" : 0 }
ipg_stats["Rtc"] = { "min" : 100000, "ave" : 0, "max" : 0 }

# Packet count in a traffic class batch
batch_count_stats = {}
batch_count_stats["High"] = { "min" : 100000, "ave" : 0, "max" : 0 }
batch_count_stats["Low"] = { "min" : 100000, "ave" : 0, "max" : 0 }
batch_count_stats["Rtc"] = { "min" : 100000, "ave" : 0, "max" : 0 }

# 1st packet time in a traffic class batch
batch_start_stats = {}
batch_start_stats["High"] = { "min" : 100000, "ave" : 0, "max" : 0 }
batch_start_stats["Low"] = { "min" : 100000, "ave" : 0, "max" : 0 }
batch_start_stats["Rtc"] = { "min" : 100000, "ave" : 0, "max" : 0 }

# Last packet time in a traffic class batch
batch_end_stats = {}
batch_end_stats["High"] = { "min" : 100000, "ave" : 0, "max" : 0 }
batch_end_stats["Low"] = { "min" : 100000, "ave" : 0, "max" : 0 }
batch_end_stats["Rtc"] = { "min" : 100000, "ave" : 0, "max" : 0 }

# Packet size in a traffic class batch
batch_pkt_len = {}
batch_pkt_len["High"] = []
batch_pkt_len["Low"] = []
batch_pkt_len["Rtc"] = []

tclass_stats = {}
tclass_stats["High"] = {"TClass" : "High", "cycles" : 0,
                        "pkt_len" : batch_pkt_len["High"],
                        "ipg" : ipg_stats["High"],
                        "batch_count" : batch_count_stats["High"],
                        "batch_start" : batch_start_stats["High"],
                        "batch_end" : batch_end_stats["High"]}
tclass_stats["Low"] = {"TClass" : "Low", "cycles" : 0,
                        "pkt_len" : batch_pkt_len["Low"],
                        "ipg" : ipg_stats["Low"],
                        "batch_count" : batch_count_stats["Low"],
                        "batch_start" : batch_start_stats["Low"],
                        "batch_end" : batch_end_stats["Low"]}
tclass_stats["Rtc"] = {"TClass" : "Rtc", "cycles" : 0,
                        "pkt_len" : batch_pkt_len["Rtc"],
                        "ipg" : ipg_stats["Rtc"],
                        "batch_count" : batch_count_stats["Rtc"],
                        "batch_start" : batch_start_stats["Rtc"],
                        "batch_end" : batch_end_stats["Rtc"]}

other_pkt_count = 0
other_pkt_list = []
tclass_start_cycle = 0

def create_main_table():
    # IPG column
    ipgTable = BeautifulTable()
    ipgTable.rows.append(["min", "ave", "max"])
    ipgTable.columns.width = [14, 14, 14]
    ipgTable.border.left = ''
    ipgTable.border.right = ''
    ipgTable.border.top = ''
    ipgTable.border.bottom = ''

    # Batch Count
    bcTable = BeautifulTable()
    bcTable.rows.append(["min", "ave", "max"])
    bcTable.columns.width = [5, 6, 5]
    bcTable.border.left = ''
    bcTable.border.right = ''
    bcTable.border.top = ''
    bcTable.border.bottom = ''
    # Batch Start
    bsTable = BeautifulTable()
    bsTable.rows.append(["min", "ave", "max"])
    bsTable.columns.width = [14, 14, 14]
    bsTable.border.left = ''
    bsTable.border.right = ''
    bsTable.border.top = ''
    bsTable.border.bottom = ''
    # Batch End
    beTable = BeautifulTable()
    beTable.rows.append(["min", "ave", "max"])
    beTable.columns.width = [14, 14, 14]
    beTable.border.left = ''
    beTable.border.right = ''
    beTable.border.top = ''
    beTable.border.bottom = ''

    # Main table
    mainTable = BeautifulTable(maxwidth=200)
    mainTable.columns.header = [ "Traffic Class",
                                 "Cycles",
                                 "Pkt Len",
                                 "Batch Count",
                                 "Batch Start",
                                 "IPG",
                                 "Batch End" ]
    mainTable.rows.append(["Cycle Time (s)", tclass_cycle_time, "",
                            bcTable, bsTable, ipgTable, beTable])

    return mainTable

def populate_stats(tclass, table):
    # Result
    stats = tclass_stats[tclass]
    resultIPGTable = BeautifulTable(precision=9)
    resultIPGTable.rows.append([stats["ipg"]["min"],
                                stats["ipg"]["ave"],
                                stats["ipg"]["max"]])
    resultIPGTable.columns.width = [14, 14, 14]
    resultIPGTable.border.left = ''
    resultIPGTable.border.right = ''
    resultIPGTable.border.top = ''
    resultIPGTable.border.bottom = ''

    resultBCTable = BeautifulTable(precision=1)
    resultBCTable.rows.append([stats["batch_count"]["min"],
                               stats["batch_count"]["ave"],
                               stats["batch_count"]["max"] ])
    resultBCTable.columns.width = [5, 6, 5]
    resultBCTable.border.left = ''
    resultBCTable.border.right = ''
    resultBCTable.border.top = ''
    resultBCTable.border.bottom = ''

    resultBSTable = BeautifulTable(precision=9)
    resultBSTable.rows.append([ stats["batch_start"]["min"],
                                stats["batch_start"]["ave"],
                                stats["batch_start"]["max"]])
    resultBSTable.columns.width = [14, 14, 14]
    resultBSTable.border.left = ''
    resultBSTable.border.right = ''
    resultBSTable.border.top = ''
    resultBSTable.border.bottom = ''

    resultBETable = BeautifulTable(precision=9)
    resultBETable.rows.append([stats["batch_end"]["min"],
                               stats["batch_end"]["ave"],
                               stats["batch_end"]["max"]])
    resultBETable.columns.width = [14, 14, 14]
    resultBETable.border.left = ''
    resultBETable.border.right = ''
    resultBETable.border.top = ''
    resultBETable.border.bottom = ''
    table.rows.append([stats["TClass"],
                       stats["cycles"],
                       stats["pkt_len"],
                       resultBCTable,
                       resultBSTable,
                       resultIPGTable,
                       resultBETable])

def create_pkt_time_table():
    table = BeautifulTable(maxwidth=200)
    table.columns.header = [ "Traffic Class", "Packet Length", "Overhead", "Byte Time(ns)", "Packet Time"]
    table.columns.width = [20, 20, 14, 20, 20]
    return table

def populate_pkt_time_stat(tclass, table):
    stats = tclass_stats[tclass]
    # For 1Gbps, 1-byte takes 8ns to transfer
    byte_ns = 8
    line_rate = float(byte_ns * math.pow(10, -9))
    # Ethernet has minimum of 8B preamble, 12B gaps and 4B FCS
    overhead = 8 + 12 + 4
    pkt_times = [ round((len + overhead) * line_rate, 9) for len in stats["pkt_len"] ]
    table.rows.append([stats["TClass"],
                       stats["pkt_len"],
                       overhead,
                       byte_ns,
                       pkt_times])

def show_tclass_stats_summary():
    mainTable = create_main_table()
    populate_stats("High", mainTable)
    populate_stats("Low", mainTable)
    populate_stats("Rtc", mainTable)
    print(mainTable)
    print("Non VLAN packet skipped = ", other_pkt_count)
    print("Non VLAN packet index = ", other_pkt_list, "\n")

    pktTimeTable = create_pkt_time_table()
    populate_pkt_time_stat("High", pktTimeTable)
    populate_pkt_time_stat("Low", pktTimeTable)
    populate_pkt_time_stat("Rtc", pktTimeTable)
    print(pktTimeTable)

def get_tclass(payload):
    left=10
    right=17
    if payload[left:right] == b'TsnHigh':
        return "High"
    if payload[left:right] == b'TsnLowP':
        return "Low"
    if payload[left:right] == b'RtcPayl':
        return "Rtc"
    return "Unknown"

def print_payload(payload, bytes):
    left = 0
    right = 8
    loop = int(bytes / 16) + 1
    for i in range(loop):
        print(' '*8, i, ' :', binascii.hexlify(payload[left:right]),
                              binascii.hexlify(payload[left+8:right+8]))
        left += 16
        right += 16

def print_pkt_summary(i, pkt):
    eth_pkt = pkt[Ether]
    if pkt.type == 0x8100:
        # vlan_pkt.fields['prio'|'id'|'vlan'|'type']
        vlan_pkt = pkt[Dot1Q]

        print("%-9d %s : len=%d : %s -> %s [%s] (vid=%d prio=%d type=%s) tclass=%s" %
              (i, pkt.time, len(pkt.load) + 14 + 4,
               eth_pkt.fields['dst'], eth_pkt.fields['src'],
               hex(pkt.type),
               vlan_pkt.fields['vlan'],
               vlan_pkt.fields['prio'],
               hex(vlan_pkt.fields['type']), get_tclass(pkt.load)))
    else:
        print("%-9d %s : len=%d : %s -> %s [%s]" %
              (i, pkt.time, len(pkt.load) + 14,
               eth_pkt.fields['dst'], eth_pkt.fields['src'],
               hex(pkt.type)))

def cal_min_ave_max(stat, val):
    if stat["min"] > val:
        stat["min"] = val
    if stat["max"] < val:
        stat["max"] = val
    if stat["ave"] != 0:
        stat["ave"] = (stat["ave"] + val) / 2
    else:
        stat["ave"] = val
    # Round to 9-digit decimal points to cover nano-sec
    stat["ave"] = round(stat["ave"], 9)

def cal_tclass_start_cycle(pkt_time, tclass_cycle_time):
    start_cycle_time_sec = str(pkt_time).split(".")[0]
    start_cycle_time_decimals = pkt_time - start_cycle_time_sec
    multp = int(start_cycle_time_decimals / tclass_cycle_time)
    return float(start_cycle_time_sec) + multp * tclass_cycle_time

def analyze_tclass(tclass_name, tclass_start_cycle, cur_batch_proc, cur_batch_count, cur_batch_pkt_time, cur_cycle_time, pkt):
    if cur_batch_proc != tclass_name:
        if cur_batch_proc != "Unknown":
            # Calculate the batch_count from previous tclass
            cal_min_ave_max(tclass_stats[cur_batch_proc]["batch_count"], cur_batch_count)
            # Calculate the last packet time
            cur_batch_end = round(cur_batch_pkt_time - cur_cycle_time, 9)
            cal_min_ave_max(tclass_stats[cur_batch_proc]["batch_end"], cur_batch_end)

        cur_batch_proc = tclass_name
        cur_batch_count = 1
        cur_batch_pkt_time = pkt.time

        cur_cycle_time = tclass_start_cycle + (tclass_cycle_time * tclass_stats[cur_batch_proc]["cycles"])
        # Calculate the 1st packet time
        cur_batch_start = round(cur_batch_pkt_time - cur_cycle_time, 9)
        cal_min_ave_max(tclass_stats[cur_batch_proc]["batch_start"], cur_batch_start)

        tclass_stats[tclass_name]["cycles"] += 1
    else:
        cur_batch_count += 1
        cur_batch_pkt_ipg = pkt.time - cur_batch_pkt_time
        cal_min_ave_max(tclass_stats[cur_batch_proc]["ipg"], cur_batch_pkt_ipg)
        cur_batch_pkt_time = pkt.time

    pkt_len = len(pkt.load) + 14 + 4
    if tclass_stats[cur_batch_proc]["pkt_len"].count(pkt_len) == 0:
        tclass_stats[cur_batch_proc]["pkt_len"].append(pkt_len)

    return (cur_batch_proc, cur_batch_count, cur_batch_pkt_time, cur_cycle_time)

def pcap_parsing(pcapng_file, left=0, right=100, analyze_pkt=False, show_pkt=False, show_payload=False):
    if right < left:
        print('Error: end < begin!')
        sys.exit(1)

    pfile = open(pcapng_file, "rb")
    r = PcapReader(pfile)

    cur_batch_proc = "Unknown"
    cur_batch_count = 0
    cur_batch_pkt_time = 0
    cur_cycle_time = 0
    global other_pkt_count

    # To match Wireshark sequence id
    i = 1

    while i < right:
        # We only interested on the samples from left to before right
        if i < left:
            i += 1
            r.next()
            continue

        if i >= right:
            break

        try:
            pkt = r.next()
        except StopIteration:
            print("No more samples at right =", right)
            break

        # Calculate the start of traffic cycles
        if i == left:
            tclass_start_cycle = cal_tclass_start_cycle(pkt.time, tclass_cycle_time)

        if show_pkt is True:
            print_pkt_summary(i, pkt)
            if show_payload is True:
                print_payload(pkt.load, len(pkt.load))

        if analyze_pkt is True:
            if pkt.type != 0x8100:
                other_pkt_count += 1
                other_pkt_list.append(i)
                i += 1
                continue

            vlan_pkt = pkt[Dot1Q]
            pkt_tclass = get_tclass(pkt.load)

            if (pkt_tclass != "Unknown" and
                vlan_pkt.fields['vlan'] == tclass[pkt_tclass]["vid"] and
                vlan_pkt.fields['prio'] == tclass[pkt_tclass]["prio"]):
                (cur_batch_proc,
                cur_batch_count,
                cur_batch_pkt_time,
                cur_cycle_time) = analyze_tclass(pkt_tclass, tclass_start_cycle,
                                                cur_batch_proc, cur_batch_count,
                                                cur_batch_pkt_time, cur_cycle_time, pkt)

        i += 1
    # End of for Loop

    # To calculate the last batch
    if analyze_pkt is True:
        if cur_batch_proc != "Unknown":
            # Calculate the batch_count from previous tclass
            cal_min_ave_max(tclass_stats[cur_batch_proc]["batch_count"], cur_batch_count)

            # Calculate the last packet time
            cur_batch_end = round(cur_batch_pkt_time - cur_cycle_time, 9)
            cal_min_ave_max(tclass_stats[cur_batch_proc]["batch_end"], cur_batch_end)

        show_tclass_stats_summary()

def main():
    global tclass_cycle_time
    parser = argparse.ArgumentParser(description='To analyze cyclic packet delivery performance')
    parser.add_argument('-f', '--file', help="Specify pcapng file", default="./sample.pcapng", required=True)
    parser.add_argument('-s', '--show', help="Show packets", action="store_true", default=False)
    parser.add_argument('-p', '--payload-show', help="Show packet payload", action="store_true", default=False)
    parser.add_argument('-a', '--analyze', help="Analyze packets", action="store_true", default=False)
    parser.add_argument('-l', '--left', help="Begin of packet analysis", type=int, required=False, default=1)
    parser.add_argument('-r', '--right', help="End of packet analysis (not inclusive)", type=int, required=False, default=1)
    parser.add_argument('-c', '--cycle-time', help="Cycle time (second). Default 0.001s", type=float, required=False, default=0.001)
    args =parser.parse_args()

    pcapfile = os.path.join(CURDIR + '/' + args.file)

    if args.analyze is False and args.show is False and args.payload_show is False:
        args.show = True
        args.payload_show = True
        args.analyze = True

    if args.payload_show is True:
        args.show = True

    tclass_cycle_time = args.cycle_time

    pcap_parsing(pcapfile, args.left, args.right, args.analyze, args.show, args.payload_show)

if __name__ == "__main__":
    main()
