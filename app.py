import os
import tensorflow as tf
from flask import Flask, jsonify, request
from api.database import get_db_connection

app = Flask(__name__)

# ✅ Define the correct model path
MODEL_PATH = os.path.join(os.getcwd(), "model", "lstm_model.h5")

# ✅ Check if the model exists before loading
if os.path.exists(MODEL_PATH):
    model = tf.keras.models.load_model(MODEL_PATH)
else:
    model = None  # Prevent crash if model is missing
    print(f"❌ Model file not found: {MODEL_PATH}")

@app.route('/')
def home():
    return jsonify({"message": "🚀 AI Protection API is running!"})

@app.route('/test_db')
def test_db():
    try:
        conn = get_db_connection()
        if conn:
            return jsonify({"message": "✅ Database connection successful"}), 200
        else:
            return jsonify({"error": "❌ Database connection failed."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Show full error

@app.route('/detect_spam', methods=['POST'])
def detect_spam():
    if model is None:
        return jsonify({"error": "❌ AI Model not found. Please check lstm_model.h5"}), 500
    
    try:
        data = request.get_json()
        email_text = data.get("email_text", "")

        if not email_text:
            return jsonify({"error": "❌ No email text provided"}), 400

        # ✅ Process email_text (Example: Tokenization, TF-IDF, etc.)
        # Ensure preprocessing matches training-time steps

        prediction = model.predict([email_text])  # Modify based on your model input
        is_spam = bool(prediction[0] > 0.5)  # Adjust threshold if needed

        return jsonify({"spam": is_spam, "confidence": float(prediction[0])})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
