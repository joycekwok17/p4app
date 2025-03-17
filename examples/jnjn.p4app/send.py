#!/usr/bin/python

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from scapy.all import sniff, sendp
from scapy.all import *
from scapy.all import Packet
from scapy.all import ShortField, IntField, LongField, BitField

import networkx as nx

import sys


TYPE_QTRP = 0x8FFF

dest="00:00:00:00:00:02"
interface="eth0"

class QTRP(Packet):
    name = "QTRP"
    fields_desc = [
        IntField("fld01_uint32", 0),
        IntField("fld02_uint32", 0),
        IntField("fld03_uint32", 0),
        ShortField("fld04_uint16", 0),
        IntField("fld05_uint32", 0),
        IntField("fld06_uint32", 0),   # Group attribute 
        ShortField("fld07_uint16", 0),  # table name field
        ShortField("fld08_uint16", 0),  # Hash key of group attribute
        ShortField("fld09_uint16", 0),
        ShortField("fld10_uint16", 0),
        ShortField("fld11_uint16", 0),
    ]


bind_layers(Ether, QTRP, type=TYPE_QTRP)

# def read_topo():
#     nb_hosts = 0
#     nb_switches = 0
#     links = []
#     with open("topo.txt", "r") as f:
#         line = f.readline()[:-1]
#         w, nb_switches = line.split()
#         assert(w == "switches")
#         line = f.readline()[:-1]
#         w, nb_hosts = line.split()
#         assert(w == "hosts")
#         for line in f:
#             if not f: break
#             a, b = line.split()
#             links.append( (a, b) )
#     return int(nb_hosts), int(nb_switches), links

def main():
    # if len(sys.argv) != 3:
    #     print "Usage: send.py [this_host] [target_host]"
    #     print "For example: send.py h1 h2"
    #     sys.exit(1)

    # src, dst = sys.argv[1:]

    # nb_hosts, nb_switches, links = read_topo()

    # port_map = {}

    # for a, b in links:
    #     if a not in port_map:
    #         port_map[a] = {}
    #     if b not in port_map:
    #         port_map[b] = {}

    #     assert(b not in port_map[a])
    #     assert(a not in port_map[b])
    #     port_map[a][b] = len(port_map[a]) + 1
    #     port_map[b][a] = len(port_map[b]) + 1


    # G = nx.Graph()
    # for a, b in links:
    #     G.add_edge(a, b)

    # shortest_paths = nx.shortest_path(G)
    # shortest_path = shortest_paths[src][dst]

    # print "path is:", shortest_path

    # port_list = []
    # first = shortest_path[1]
    # for h in shortest_path[2:]:
    #     port_list.append(port_map[first][h])
    #     first = h

    # print "port list is:", port_list

    # port_str = ""
    # for p in port_list:
    #     port_str += chr(p)

    # while(1):
    #     msg = raw_input("What do you want to send: ")

    #     # finding the route
    #     first = None

    #     p = SrcRoute(num_valid = len(port_list)) / port_str / msg


    #  Build phase (fld07 == 1) - include and drop
    p = Ether(dst=dest) / QTRP(fld01_uint32=3,fld02_uint32=0,fld03_uint32=0,fld04_uint16=0,fld05_uint32=0,fld06_uint32=0,fld07_uint16=1,fld08_uint16=0,
        fld09_uint16=0,fld10_uint16=0,fld11_uint16=0)
    sendp(p, iface=interface)

    #  Build phase (fld07 == 1) - include and drop
    p = Ether(dst=dest) / QTRP(fld01_uint32=4,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=4,fld07_uint16=1,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Build phase (fld07 == 1) - include and drop. This key 6 does not show in any other table. Should not appear in the final output.
    p = Ether(dst=dest) / QTRP(fld01_uint32=6,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=6,fld07_uint16=1,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Build phase (fld07 == 1) - include and drop:  highest uint16 key value
    p = Ether(dst=dest) / QTRP(fld01_uint32=65535,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=65535,fld07_uint16=1,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Build phase (fld07 == 1) - include in the next table due to collision with key 4 and drop
    p = Ether(dst=dest) / QTRP(fld01_uint32=65540,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=65540,fld07_uint16=1,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)
    # print msg


    #  Probe phase (fld07 == 2) - emit found key. Build phase of next join, drop.
    p = Ether(dst=dest) / QTRP(fld01_uint32=3,fld02_uint32=0,fld03_uint32=0,fld04_uint16=0,fld05_uint32=0,fld06_uint32=0,fld07_uint16=2,fld08_uint16=0,
        fld09_uint16=0,fld10_uint16=0,fld11_uint16=0)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - emit found key. Build phase of next join, drop.
    p = Ether(dst=dest) / QTRP(fld01_uint32=3,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=3,fld07_uint16=2,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - emit found key. Build phase of next join, drop.
    p = Ether(dst=dest) / QTRP(fld01_uint32=4,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=4,fld07_uint16=2,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase - drop key not found 
    p = Ether(dst=dest) / QTRP(fld01_uint32=5,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=5,fld07_uint16=2,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - emit found key highest value. Build phase of next join, drop.
    p = Ether(dst=dest) / QTRP(fld01_uint32=65535,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=65535,fld07_uint16=2,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase - drop key not found 
    p = Ether(dst=dest) / QTRP(fld01_uint32=65536,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=65536,fld07_uint16=2,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - emit found key after collision with key 4. Build phase of next join, drop.
    p = Ether(dst=dest) / QTRP(fld01_uint32=65540,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=65540,fld07_uint16=2,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    ######## Table R (fld07 = 3) - 8 records
    #### fld01, ..., fld02, fld03, fld07
    ####   1  , ...,   1  ,   1  ,  3    drop
    ####   2  , ...,   1  ,   1  ,  3    drop
    ####   3  , ...,   1  ,   1  ,  3    match
    ####   4  , ...,   1  ,   1  ,  3    match
    ####   5  , ...,   1  ,   1  ,  3    drop
    #### 65535, ...,   1  ,   1  ,  3    match
    #### 65536, ...,   1  ,   1  ,  3    drop
    #### 65540, ...,   1  ,   1  ,  3    match
    #############################

    #  Probe phase (fld07 == 2) - drop key not found 
    p = Ether(dst=dest) / QTRP(fld01_uint32=1,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=1,fld07_uint16=3,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - drop key not found
    p = Ether(dst=dest) / QTRP(fld01_uint32=2,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=2,fld07_uint16=3,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - emit found key 
    p = Ether(dst=dest) / QTRP(fld01_uint32=3,fld02_uint32=0,fld03_uint32=0,fld04_uint16=0,fld05_uint32=0,fld06_uint32=0,fld07_uint16=3,fld08_uint16=0,
        fld09_uint16=0,fld10_uint16=0,fld11_uint16=0)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - emit found key 
    p = Ether(dst=dest) / QTRP(fld01_uint32=4,fld02_uint32=0,fld03_uint32=0,fld04_uint16=0,fld05_uint32=0,fld06_uint32=4,fld07_uint16=3,fld08_uint16=0,
        fld09_uint16=0,fld10_uint16=0,fld11_uint16=0)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - drop key not found 
    p = Ether(dst=dest) / QTRP(fld01_uint32=5,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=5,fld07_uint16=3,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - emit found key 
    p = Ether(dst=dest) / QTRP(fld01_uint32=65535,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=65535,fld07_uint16=3,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

    #  Probe phase (fld07 == 2) - drop key not found
    p = Ether(dst=dest) / QTRP(fld01_uint32=65536,fld02_uint32=1,fld03_uint32=1,fld04_uint16=3,fld05_uint32=0,fld06_uint32=65536,fld07_uint16=3,fld08_uint16=0,
        fld09_uint16=1,fld10_uint16=0,fld11_uint16=1)
    sendp(p, iface=interface)

if __name__ == '__main__':
    main()
