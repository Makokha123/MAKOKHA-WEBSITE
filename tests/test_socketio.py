import pytest
from flask_socketio import SocketIOTestClient

pytestmark = pytest.mark.socketio


def test_socketio_connect_requires_auth(app):
    # Socket.IO test client without login should fail connect handler
    from app import socketio

    client = socketio.test_client(app)
    # Our server returns False in connect for unauthenticated users,
    # which still completes a low-level connect in test client.
    # Verify no personal room events were emitted.
    received = client.get_received()
    # Should not receive 'connection_status' for unauthenticated client
    assert not any(p['name'] == 'connection_status' for p in received)
    client.disconnect()
