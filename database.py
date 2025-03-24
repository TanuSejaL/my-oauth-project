import mysql.connector

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="spam_db"
        )
        if conn.is_connected():
            print("✅ Database connected successfully!")
        return conn
    except mysql.connector.Error as e:
        print(f"❌ Database connection failed: {e}")  # Print exact error
        return None
