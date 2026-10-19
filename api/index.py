import io
import os
import random
import hashlib
import hmac
from flask import Flask, request, jsonify, send_file
from captcha.image import ImageCaptcha

app = Flask(__name__)

# Secret key used to sign the captcha cookie
SECRET_KEY = os.environ.get("CAPTCHA_SECRET_KEY", "your_secret_key_here")

# Characters excluding confusing ones like 0, O, I, l
CAPTCHA_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

def create_signature(text: str) -> str:
    """Create an HMAC SHA-256 signature for the given text."""
    normalized = text.strip().upper()
    return hmac.new(SECRET_KEY.encode('utf-8'), normalized.encode('utf-8'), hashlib.sha256).hexdigest()

@app.route('/')
def home():
    """Serve the homepage from the root directory."""
    return send_file('../index.html')

@app.route("/api/captcha", methods=["GET"])
def generate_captcha():
    """Generate a 5-character image captcha."""
    captcha_text = "".join(random.choices(CAPTCHA_CHARS, k=5))
    
    # Configure ImageCaptcha dimensions
    image_generator = ImageCaptcha(width=160, height=60)
    image_data = image_generator.generate(captcha_text)
    
    response = make_response(
        send_file(io.BytesIO(image_data.read()), mimetype='image/png')
    )
    
    # Prevent browser caching so every refresh fetches a new captcha
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    # Set a secure, HTTP-only cookie containing the signature
    response.set_cookie(
        "bseb_captcha_sig",
        create_signature(captcha_text),
        max_age=300,  # Valid for 5 minutes
        httponly=True,
        secure=True,     # Ensure this is True in production (HTTPS)
        samesite="Lax",
    )
    
    return response

@app.route("/api/verify-captcha", methods=["POST"])
def verify_captcha():
    """Verify the user's captcha input against the cookie signature."""
    payload = request.get_json(silent=True)
    user_input = str(payload.get("captcha")).strip().upper() if payload else None
    saved_sig = request.cookies.get("bseb_captcha_sig")
    
    if not user_input or not saved_sig:
        return jsonify({"valid": False}), 400
        
    expected_sig = create_signature(user_input)
    is_valid = hmac.compare_digest(saved_sig, expected_sig)
    
    res = make_response(jsonify({"valid": is_valid}))
    
    if is_valid:
        # Clear cookie after one use so it cannot be reused
        res.delete_cookie("bseb_captcha_sig")
        
    return res

if __name__ == '__main__':
    app.run(debug=True)
    
