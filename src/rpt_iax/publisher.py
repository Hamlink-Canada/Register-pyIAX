"""Publish the shared nested DNS update; acknowledge only broker-confirmed writes."""

from ipaddress import IPv4Address

from confluent_kafka import Producer
from rpt_protobuf.dns_update_pb2 import dns_update

from rpt_iax.kafka_config import client_config


class PublishUnavailable(Exception):
    pass


class Publisher:
    def __init__(self, settings):
        self.settings = settings
        config = client_config(settings)
        config.update(
            {
                "message.timeout.ms": int(settings.KAFKA.TIMEOUT * 1000),
                "acks": "all",
                "enable.idempotence": True,
            }
        )
        self.producer = Producer(config)

    def publish(self, node, ip, port):
        entry = dns_update()
        entry.timestamp.GetCurrentTime()
        entry.node.id = int(node)
        entry.node.ipaddress = str(IPv4Address(ip))
        entry.node.port = port
        entry.node.ttl = int(self.settings.LIFETIME)
        entry.node.server = self.settings.SERVER_ID
        from threading import Event

        done = Event()
        errors = []

        def delivered(error, message):
            if error:
                errors.append(True)
            done.set()

        try:
            self.producer.produce(
                self.settings.KAFKA.TOPIC,
                key=str(node).encode(),
                value=entry.SerializeToString(),
                on_delivery=delivered,
            )
            from time import monotonic

            deadline = monotonic() + float(self.settings.KAFKA.TIMEOUT)
            while not done.is_set() and monotonic() < deadline:
                self.producer.poll(min(0.1, max(0, deadline - monotonic())))
            if not done.is_set() or errors:
                raise PublishUnavailable("registration publication failed")
        except Exception:
            raise PublishUnavailable("registration publication failed") from None

    def close(self):
        self.producer.flush(float(self.settings.KAFKA.TIMEOUT))
