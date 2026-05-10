from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.interpretation.utils import dsl_decode


def test_update_object_encodes_structured_mask_and_u32_fields():
    payload = EncoderHandler.encode_packet(
        "SMSG_UPDATE_OBJECT",
        {
            "map_id": 1,
            "update_count": 1,
            "updates": [
                {
                    "update_type": 0,
                    "guid": 7,
                    "mask_blocks": 3,
                    "mask": {
                        "set_bits": [8, 10],
                        "block_count": 3,
                    },
                    "fields": {
                        "u32": [123, 456],
                    },
                    "dynamic_mask_blocks": 0,
                }
            ],
        },
    )

    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert decoded["map_id"] == 1
    assert update["guid"] == 7
    assert update["mask"]["set_bits"] == [8, 10]
    assert update["fields"]["u32"] == [123, 456]

