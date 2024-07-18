#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct


# Testdata
data1 = b'\x10.\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00Pandaria\x00192.168.11.30:8085\x00\x00\x00\x00\x00\x01\x01\x01\x10\x00'
data2 = b'\x10U\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00Pandaria\x00192.168.11.30:8085\x00\x00\x00\x00\x00\x01\x01\x01\x00\x00\x00Pandaria2\x00192.168.11.30:8085\x00\x00\x00\x00\x00\x00\x01\x02\x10\x00'

def realm_unpack(data):
    REALM_LIST = 0x10
    cmd = "Unknown"

    # Extract parts
    realmlist_type = data[0]      
    size_field = data[1:3]  
    RealmListSizeBuffer = data[3:8] 
    pkt_data = data[8:] 


    print(realmlist_type)
    print(size_field)
    print(RealmListSizeBuffer)

    if REALM_LIST == data[0]:
        cmd = "Realmist"

    

    realmsize = int(size_field.hex(), 16) 
    num_realms = int(RealmListSizeBuffer.hex(), 16)

    print(f'cmd: {cmd}')
    print(f'Realm sizes: {realmsize - num_realms}')
    print(f'Num of realms {num_realms}')
    print(f'Realmdata: {pkt_data}')

realm_unpack(data1)
realm_unpack(data2)