def client_config(settings):
    config = {"bootstrap.servers": settings.KAFKA.BOOTSTRAP}
    if settings.KAFKA.SECURITY_PROTOCOL:
        config.update(
            {
                "security.protocol": settings.KAFKA.SECURITY_PROTOCOL,
                "sasl.mechanism": settings.KAFKA.SASL_MECHANISM,
                "sasl.username": settings.KAFKA.SASL_USERNAME,
                "sasl.password": settings.KAFKA.SASL_PASSWORD,
                "ssl.ca.location": settings.KAFKA.SSL_CA_LOCATION,
            }
        )
    return config
