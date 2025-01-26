#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.Logger import Logger
from utils.crypto.arc4_crypto import Arc4CryptoHandler
from utils.opcodes.WorldOpcodes import *

K = 'fe7d6dac6789c756db917e9b3856833bf3c629d60f4ff3ec58963b222f7aa90d324fe20f72a2e47c'


header_hex = '1fba4136'
Logger.info(f'Original: {header_hex}')

arc4 = Arc4CryptoHandler()
arc4.init_arc4(K)

data = bytes.fromhex(header_hex)
decrypted_header = arc4.encrypt_send(data)
header = arc4.unpack_data(decrypted_header)

opname = WorldOpcodes.getServerOpCodeName(header.cmd)

Logger.info(f'Decrypted header data: CMD: {header.cmd}, size: {header.size} opcode: {opname}')

header = arc4.pack_data(header.cmd, header.size)
Logger.info(f'Repacked header data: {header.hex()}')

arc4.init_arc4(K)
header = arc4.encrypt_send(header)

Logger.info(f'Encrypted: {header.hex()}')