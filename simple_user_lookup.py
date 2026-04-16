from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)
DATABASE = 'users.db'


def get_db_connection():
    """Create a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with a users table."""
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
        print("Database initialized: " + DATABASE)


@app.route('/api/users/lookup', methods=['GET'])
def lookup_user():
    """Look up a user by username from query string."""
    username = request.args.get('username')
    
    if not username:
        return jsonify({'error': 'Missing username parameter'}), 400
    
    if len(username) < 1 or len(username) > 80:
        return jsonify({'error': 'Username must be between 1 and 80 characters'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user = cursor.execute(
            'SELECT id, username, email, created_at FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        
        conn.close()
        
        if user:
            return jsonify({
                'found': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'created_at': user['created_at']
                }
            }), 200
        else:
            return jsonify({
                'found': False,
                'error': 'User not found'
            }), 404
    
    except sqlite3.Error as e:
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/users/seed', methods=['POST'])
def seed_users():
    """Add sample users to the database."""
    sample_users = [
        ('alice', 'alice@example.com'),
        ('bob', 'bob@example.com'),
        ('charlie', 'charlie@example.com'),
    ]
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        for username, email in sample_users:
            try:
                cursor.execute(
                    'INSERT INTO users (username, email) VALUES (?, ?)',
                    (username, email)
                )
            except sqlite3.IntegrityError:
                pass
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Sample users added'}), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/users', methods=['GET'])
def list_users():
    """List all users in the database."""
    try:
        conn = get_db_connection()
        users = conn.execute('SELECT id, username, email, created_at FROM users').fetchall()
        conn.close()
        
        return jsonify({
            'count': len(users),
            'users': [dict(user) for user in users]
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
