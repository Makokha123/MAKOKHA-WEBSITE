from app import generate_csrf_token


def test_csrf_endpoint(client):
    resp = client.get('/api/csrf-token')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'csrf_token' in data
    assert isinstance(data['csrf_token'], str)


def test_timezone_info(client):
    resp = client.get('/api/get-timezone-info')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'timezone' in data
    assert 'current_time' in data
