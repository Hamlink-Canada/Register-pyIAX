import pytest
from rpt_protobuf.dns_update_pb2 import dns_update

from rpt_iax.config import load_settings
from rpt_iax.publisher import Publisher, PublishUnavailable


class Producer:
    def __init__(self, config):
        self.config = config
        self.sent = []
        self.fail = False

    def produce(self, topic, key, value, on_delivery):
        self.sent.append((topic, key, dns_update.FromString(value)))
        on_delivery("failed" if self.fail else None, None)

    def poll(self, timeout):
        pass


def test_nested_publication(monkeypatch, tmp_path):
    monkeypatch.setenv("RPT_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr("rpt_iax.publisher.Producer", Producer)
    publisher = Publisher(load_settings())
    publisher.publish("1234", "192.0.2.1", 4569)
    topic, key, event = publisher.producer.sent[0]
    assert topic == "rpt.registrations" and key == b"1234"
    assert event.node.id == 1234
    assert event.node.ipaddress == "192.0.2.1"
    assert event.node.port == 4569 and event.node.ttl == 180
    assert event.HasField("timestamp")
    publisher.producer.fail = True
    with pytest.raises(PublishUnavailable):
        publisher.publish("1234", "192.0.2.1", 4569)


def test_publisher_uses_durable_kafka_producer_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("RPT_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr("rpt_iax.publisher.Producer", Producer)

    publisher = Publisher(load_settings())

    assert publisher.producer.config["acks"] == "all"
    assert publisher.producer.config["enable.idempotence"] is True
