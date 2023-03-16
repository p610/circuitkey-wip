from circuitkey.channel import generate_cid


def test_generate_cid():
    cid = generate_cid()

    assert len(cid) == 4
    assert cid != b"\x00\x00\x00\x00"
    assert cid != b"\xff\xff\xff\xff"
