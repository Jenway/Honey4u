"""Test broadcast mempool functionality"""

import time

from honey.data.broadcast_mempool import BroadcastMempool


def test_mempool_add_and_get():
    """Test basic add and get operations"""
    mempool = BroadcastMempool(max_size=100, expire_rounds=5)

    payload = b"test_data"
    roothash = b"test_hash"
    shards = [b"shard0", b"shard1", b"shard2", b"shard3"]
    proofs = [b"proof0", b"proof1", b"proof2", b"proof3"]
    round_no = 0
    sender_id = 0

    # Add data
    payload_id = mempool.add(payload, roothash, shards, proofs, round_no, sender_id, time.time())

    # Get data
    data = mempool.get(payload_id)
    assert data is not None
    assert data.payload == payload
    assert data.roothash == roothash
    assert data.round_no == round_no
    assert data.sender_id == sender_id


def test_mempool_get_by_hash():
    """Test retrieval by merkle hash"""
    mempool = BroadcastMempool()

    payload = b"test_data"
    roothash = b"test_hash"
    # shards = [b"s0", b"s1", b"s2", b"s3"]
    # proofs = [b"p0", b"p1", b"p2", b"p3"]

    # payload_id = mempool.add(payload, roothash, shards, proofs, 0, 0, time.time())

    # Get by hash
    data = mempool.get_by_hash(roothash)
    assert data is not None
    assert data.payload == payload


def test_mempool_get_by_round_sender():
    """Test retrieval by round and sender"""
    mempool = BroadcastMempool()

    payload = b"test_data"
    # roothash = b"test_hash"
    # shards = [b"s0", b"s1", b"s2", b"s3"]
    # proofs = [b"p0", b"p1", b"p2", b"p3"]
    round_no = 2
    sender_id = 3

    # payload_id = mempool.add(payload, roothash, shards, proofs, round_no, sender_id, time.time())

    # Get by round and sender
    data = mempool.get_by_round_sender(round_no, sender_id)
    assert data is not None
    assert data.payload == payload


def test_mempool_list_round():
    """Test listing all payloads for a round"""
    mempool = BroadcastMempool()

    # Add multiple payloads in same round
    round_no = 1
    for sender in range(4):
        mempool.add(
            f"data_{sender}".encode(),
            f"hash_{sender}".encode(),
            [b"s0", b"s1"],
            [b"p0", b"p1"],
            round_no,
            sender,
            time.time(),
        )

    # List all payloads for round 1
    payloads = mempool.list_round(round_no)
    assert len(payloads) == 4
    assert all(sender in payloads for sender in range(4))


def test_mempool_list_unused():
    """Test finding unused payloads"""
    mempool = BroadcastMempool()

    round_no = 1
    # Add 4 payloads
    for sender in range(4):
        mempool.add(
            f"data_{sender}".encode(),
            f"hash_{sender}".encode(),
            [b"s0", b"s1"],
            [b"p0", b"p1"],
            round_no,
            sender,
            time.time(),
        )

    # Only 2 were selected by ACS
    selected = {0, 1}
    unused = mempool.list_unused(round_no, selected)

    # Should have 2 unused
    assert len(unused) == 2
    unused_senders = {sender for sender, _ in unused}
    assert unused_senders == {2, 3}


def test_mempool_cleanup():
    """Test cleanup of expired entries"""
    mempool = BroadcastMempool(max_size=100, expire_rounds=2)

    # Add payloads from rounds 0, 1, 2, 3
    for round_no in range(4):
        mempool.add(
            f"data_{round_no}".encode(),
            f"hash_{round_no}".encode(),
            [b"s0"],
            [b"p0"],
            round_no,
            0,
            time.time(),
        )

    # Current round is 3, expire_rounds is 2
    # So round 0 should be expired (3 - 2 = 1, and 0 < 1)
    mempool.cleanup(3)

    # Should have entries from rounds 1, 2, 3
    stats = mempool.stats()
    assert len(stats["rounds_covered"]) == 3
    assert 0 not in stats["rounds_covered"]
    assert 1 in stats["rounds_covered"]


def test_mempool_lru_eviction():
    """Test LRU eviction when max_size is exceeded"""
    mempool = BroadcastMempool(max_size=3, expire_rounds=10)

    # Add 4 payloads (max_size is 3)
    ids = []
    for i in range(4):
        pid = mempool.add(
            f"data_{i}".encode(),
            f"hash_{i}".encode(),
            [b"s0"],
            [b"p0"],
            0,
            i,
            time.time(),
        )
        ids.append(pid)

    # First payload should have been evicted
    assert mempool.get(ids[0]) is None
    # Others should still be present
    assert mempool.get(ids[1]) is not None
    assert mempool.get(ids[2]) is not None
    assert mempool.get(ids[3]) is not None


def test_mempool_stats():
    """Test statistics reporting"""
    mempool = BroadcastMempool()

    stats_empty = mempool.stats()
    assert stats_empty["size"] == 0

    # Add some data
    for round_no in range(3):
        for sender in range(2):
            mempool.add(
                f"data_{round_no}_{sender}".encode(),
                f"hash_{round_no}_{sender}".encode(),
                [b"s0"],
                [b"p0"],
                round_no,
                sender,
                time.time(),
            )

    stats = mempool.stats()
    assert stats["size"] == 6
    assert stats["oldest_round"] == 0
    assert stats["newest_round"] == 2
    assert len(stats["rounds_covered"]) == 3
