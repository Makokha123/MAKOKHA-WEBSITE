# wsgi.py
import eventlet
eventlet.monkey_patch()

from app import app, socketio, init_db

# Initialize database before starting the app
with app.app_context():
    init_db()

if __name__ == "__main__":
    socketio.run(app)