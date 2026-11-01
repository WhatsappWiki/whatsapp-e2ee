"""The default test suite cannot open network connections."""

import socket

import pytest


@pytest.fixture(autouse=True)
def offline_network_boundary(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("Offline tests must use an injected transport, not a socket connection")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
