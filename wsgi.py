# wsgi.py - Fixed version
import os
import eventlet

# Apply monkey patching first
eventlet.monkey_patch()

print("🔧 Starting Makokha Medical Centre WebSocket Server...")

from app import app, socketio, db

# Initialize database function
def initialize_database():
    """Initialize database tables"""
    try:
        with app.app_context():
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Create admin user if not exists
            from app import User, Patient, Doctor
            admin_user = User.query.filter_by(email='admin@makokha.com').first()
            if not admin_user:
                admin_user = User(
                    email='admin@makokha.com',
                    username='admin',
                    role='admin',
                    timezone='Africa/Nairobi'
                )
                admin_user.set_password('Admin123!')
                db.session.add(admin_user)
                print("✅ Admin user created")
            
            db.session.commit()
            
    except Exception as e:
        print(f"⚠️ Database initialization note: {e}")
        db.session.rollback()

# Initialize database
try:
    initialize_database()
except Exception as e:
    print(f"⚠️ Database initialization: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    host = '0.0.0.0'
    
    print(f"🌐 Production server starting on {host}:{port}")
    print("📡 WebSocket support: ENABLED")
    print("⚡ Server: Eventlet")
    print("🚀 Ready for connections...")
    
    # Start the SocketIO server
    socketio.run(
        app,
        host=host,
        port=port,
        debug=False,
        log_output=True,
        use_reloader=False
    )