from flask import Blueprint, request, jsonify
import bcrypt
import mariadb
from database import get_db_connection  # Ensure this works

auth_bp = Blueprint('auth', __name__)

# User Signup
@auth_bp.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password'].encode('utf-8')  # Encode password

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        
        return jsonify({"message": "✅ User registered successfully"}), 201
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# User Login
@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password'].encode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password, user[0].encode('utf-8')):
            return jsonify({"message": "✅ Login successful"}), 200
        else:
            return jsonify({"error": "❌ Invalid credentials"}), 401
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
