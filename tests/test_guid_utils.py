#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from server.modules.game.guid import (
    GuidHelper,
    HighGuid,
    PlayerGuid,
    CreatureGuid,
    GameObjectGuid,
    MoTransportGuid,
)


class TestGuidUtils(unittest.TestCase):
    def test_make_and_decode_roundtrip(self):
        guid = GuidHelper.make(HighGuid.PLAYER, 0x1234, 0x89ABCDEF)
        decoded = GuidHelper.decode(guid)
        self.assertEqual(decoded.high, HighGuid.PLAYER)
        self.assertEqual(decoded.realm, 0x1234)
        self.assertEqual(decoded.low, 0x89ABCDEF)

    def test_le_bytes_roundtrip(self):
        guid = GuidHelper.make(HighGuid.UNIT, 0x0001, 0x00000002)
        data = GuidHelper.to_le_bytes(guid)
        self.assertEqual(GuidHelper.from_le_bytes(data), guid)
        with self.assertRaises(ValueError):
            GuidHelper.from_le_bytes(b"short")

    def test_pack_and_unpack_roundtrip(self):
        guid = GuidHelper.make(HighGuid.GAMEOBJECT, 0x00AB, 0x00CD00EF)
        packed = GuidHelper.pack(guid)
        self.assertEqual(GuidHelper.unpack(packed), guid)
        with self.assertRaises(ValueError):
            GuidHelper.unpack(b"")  # empty
        with self.assertRaises(ValueError):
            GuidHelper.unpack(bytes([0xFF, 0x01]))  # mask claims more bytes than provided

    def test_typed_helpers(self):
        player = PlayerGuid.from_db_guid(2, 1)
        creature = CreatureGuid.from_spawn_guid(3, 1)
        gameobject = GameObjectGuid.from_spawn_guid(4, 1)
        self.assertEqual(GuidHelper.decode(player).high, HighGuid.PLAYER)
        self.assertEqual(GuidHelper.decode(creature).high, HighGuid.UNIT)
        self.assertEqual(GuidHelper.decode(gameobject).high, HighGuid.GAMEOBJECT)

    def test_mo_transport_guid_uses_skyfire_highguid_shape(self):
        transport = MoTransportGuid.from_spawn_guid(6)
        self.assertEqual(transport, 0x1FC0000000000006)
        self.assertEqual(GuidHelper.to_le_bytes(transport)[7], 0x1F)
        self.assertEqual(GuidHelper.to_le_bytes(transport)[6], 0xC0)


if __name__ == "__main__":
    unittest.main()
