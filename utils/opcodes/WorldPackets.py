from dataclasses import dataclass
import struct
import os
import random
from typing import List, Dict


@dataclass
class AuthChallengePacket:
    uint16_zero: int
    encryption_data: bytes
    flag: int
    m_seed: int

    @staticmethod
    def generate() -> "AuthChallengePacket":
        """
        Genererar ett autentiseringspaket med korrekt struktur.
        """
        uint16_zero = 0  # Första två bytes (uint16(0))
        encryption_data = os.urandom(32)  # 32 bytes slumpmässig krypteringsdata
        flag = 1  # Sista byte före seed (uint8(1))
        m_seed = random.randint(0, 0xFFFFFFFF)  # Slumpmässig uint32

        return AuthChallengePacket(uint16_zero, encryption_data, flag, m_seed)

    def encode(self) -> bytes:
        """
        Kodar detta AuthChallengePacket till ett binärt paket.
        """
        packet = struct.pack('<H', self.uint16_zero)  # uint16(0)
        packet += self.encryption_data  # 32 bytes krypteringsdata
        packet += struct.pack('<B', self.flag)  # uint8(1)
        packet += struct.pack('<I', self.m_seed)  # uint32 seed
        return packet

    @staticmethod
    def decode(packet: bytes) -> "AuthChallengePacket":
        """
        Dekodar ett binärt paket till ett AuthChallengePacket.
        """
        if len(packet) != 39:
            raise ValueError(f"Invalid packet size: {len(packet)}. Expected 39 bytes.")

        offset = 0

        # Dekoda uint16(0)
        uint16_zero = struct.unpack_from('<H', packet, offset)[0]
        offset += 2

        # Dekoda 32 bytes krypteringsdata
        encryption_data = packet[offset:offset + 32]
        offset += 32

        # Dekoda uint8(1)
        flag = struct.unpack_from('<B', packet, offset)[0]
        offset += 1

        # Dekoda uint32 seed
        m_seed = struct.unpack_from('<I', packet, offset)[0]

        return AuthChallengePacket(uint16_zero, encryption_data, flag, m_seed)


@dataclass
class AuthResponsePacket:
    code: int  # ResponseCodes (uint8)
    queued: bool  # Queued status (bit)
    queue_pos: int  # Queue position (uint32)
    realm_name_store: Dict[int, str]  # Realm ID och namn
    races: List[tuple]  # Race expansions [(expansion_id, race_id), ...]
    classes: List[tuple]  # Class expansions [(expansion_id, class_id), ...]
    active_expansion: int  # Active expansion (uint8)
    server_expansion: int  # Server expansion (uint8)

    def encode(self) -> bytes:
        """
        Kodar paketet till ett binärt format.
        """
        packet = b""

        # Skriv `AUTH_OK` status och flaggor
        packet += struct.pack('?', self.code == 0)  # AUTH_OK flagga (bool)

        if self.code == 0:  # AUTH_OK
            packet += struct.pack('<H', len(self.realm_name_store))  # Antal realms

            for realm_id, realm_name in self.realm_name_store.items():
                normalized_name = realm_name.replace(" ", "")
                packet += struct.pack('<B', len(realm_name))  # Längd på realm_name
                packet += struct.pack('<B', len(normalized_name))  # Längd på normalized_name
                packet += struct.pack('?', realm_id == list(self.realm_name_store.keys())[0])  # Home realm flagga

            packet += struct.pack('<H', len(self.classes))  # Antal klasser
            packet += struct.pack('<H', 0)  # Okänd bitmask
            packet += struct.pack('?', False)  # Okänd bit

            packet += struct.pack('<H', len(self.races))  # Antal raser
            packet += struct.pack('?', False)  # Okänd bit

        # Queued flagga
        packet += struct.pack('?', self.queued)

        if self.queued:
            packet += struct.pack('?', True)
            packet += struct.pack('<I', self.queue_pos)

        if self.code == 0:  # AUTH_OK
            for realm_id, realm_name in self.realm_name_store.items():
                normalized_name = realm_name.replace(" ", "")
                packet += struct.pack('<I', realm_id)  # Realm ID
                packet += realm_name.encode() + b'\x00'  # Realm Name
                packet += normalized_name.encode() + b'\x00'  # Normalized Name

            for race in self.races:
                packet += struct.pack('<BB', race[1], race[0])  # Race ID och expansion ID

            for cls in self.classes:
                packet += struct.pack('<BB', cls[1], cls[0])  # Class ID och expansion ID

            packet += struct.pack('<I', 0)  # Okänd data
            packet += struct.pack('<B', self.active_expansion)  # Active expansion
            packet += struct.pack('<I', 0)  # Okänd data
            packet += struct.pack('<I', 0)  # Gossip warning box
            packet += struct.pack('<B', self.server_expansion)  # Server expansion
            packet += struct.pack('<I', 0)  # Okänd data
            packet += struct.pack('<I', 0)  # Okänd data
            packet += struct.pack('<I', 0)  # Okänd data

        packet += struct.pack('<B', self.code)  # Response code

        return packet

    @staticmethod
    def decode(packet: bytes) -> "AuthResponsePacket":
        """
        Dekodar ett binärt paket till ett AuthResponsePacket objekt.
        """
        offset = 0

        # Läs AUTH_OK flagga
        auth_ok = struct.unpack_from('?', packet, offset)[0]
        offset += 1

        realm_name_store = {}
        if auth_ok:
            num_realms = struct.unpack_from('<H', packet, offset)[0]
            offset += 2

            for _ in range(num_realms):
                realm_name_length = struct.unpack_from('<B', packet, offset)[0]
                offset += 1
                normalized_length = struct.unpack_from('<B', packet, offset)[0]
                offset += 1
                home_realm = struct.unpack_from('?', packet, offset)[0]
                offset += 1

                realm_id = struct.unpack_from('<I', packet, offset)[0]
                offset += 4

                realm_name = packet[offset:offset + realm_name_length].decode()
                offset += realm_name_length

                normalized_name = packet[offset:offset + normalized_length].decode()
                offset += normalized_length

                realm_name_store[realm_id] = realm_name

        return AuthResponsePacket(
            code=auth_ok,
            queued=False,
            queue_pos=0,
            realm_name_store=realm_name_store,
            races=[],
            classes=[],
            active_expansion=0,
            server_expansion=0
        )
