# wsgi.py - Production WSGI entry point
import os
import eventlet

# Apply eventlet monkey patch early
eventlet.monkey_patch()

from app import app, socketio, initialize_database

print("🚀 Starting Makokha Medical Centre Production Server...")

# Initialize database
try:
    with app.app_context():
        initialize_database()
    print("✅ Database initialized successfully!")
except Exception as e:
    print(f"⚠️ Database initialization warning: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = '0.0.0.0'
    
    # Check if we're in production
    is_production = os.environ.get('RENDER') or os.environ.get('FLASK_ENV') == 'production'
    
    if is_production:
        print(f"🌐 Production server starting on port {port}")
        print("📡 WebSocket support: Enabled")
        print("⚡ Server: Eventlet")
        
        # Use eventlet's production server
        socketio.run(app, host=host, port=port, debug=False, log_output=True)
    else:
        print(f"🔧 Development server starting on port {port}")
        socketio.run(app, host=host, port=port, debug=True, log_output=True)