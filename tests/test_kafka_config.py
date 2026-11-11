from types import SimpleNamespace

from rpt_iax.kafka_config import client_config


def test_client_config_uses_plain_bootstrap_by_default():
    settings = SimpleNamespace(KAFKA=SimpleNamespace(BOOTSTRAP="localhost:9092", SECURITY_PROTOCOL=""))

    assert client_config(settings) == {"bootstrap.servers": "localhost:9092"}


def test_client_config_adds_tls_scram_options():
    settings = SimpleNamespace(
        KAFKA=SimpleNamespace(
            BOOTSTRAP="kafka:9093",
            SECURITY_PROTOCOL="SASL_SSL",
            SASL_MECHANISM="SCRAM-SHA-512",
            SASL_USERNAME="registration-iax-producer",
            SASL_PASSWORD="test-password",
            SSL_CA_LOCATION="/var/run/kafka/ca.crt",
        )
    )

    assert client_config(settings) == {
        "bootstrap.servers": "kafka:9093",
        "security.protocol": "SASL_SSL",
        "sasl.mechanism": "SCRAM-SHA-512",
        "sasl.username": "registration-iax-producer",
        "sasl.password": "test-password",
        "ssl.ca.location": "/var/run/kafka/ca.crt",
    }
