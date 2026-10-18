import io
import os
import random
import hashlib
import hmac
from flask import Flask, request, jsonify, send_file, make_response
from captcha.image import ImageCaptcha

app = Flask(__name__)

# Secret key used to sign the captcha cookie on Vercel serverless functions
SECRET_KEY = os.environ.get("CAPTCHA_SECRET", "bseb_student_portal_secret_2026")

# Characters excluding confusing ones like 0/O and 1/I
CAPTCHA_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def create_signature(text: str) -> str:
    """Create an HMAC SHA-256 signature for stateless serverless verification."""
    normalized = text.strip().upper().encode("utf-8")
    return hmac.new(SECRET_KEY.encode("utf-8"), normalized, hashlib.sha256).hexdigest()


@app.route("/api/captcha", methods=["GET"])
def generate_captcha():
    """Generate a 5-character image captcha and store its hash in an HTTP-only cookie."""
    captcha_text = "".join(random.choices(CAPTCHA_CHARS, k=5))

    # Configure ImageCaptcha dimensions
    image_generator = ImageCaptcha(width=220, height=64, font_sizes=(34, 38, 42))
    image_data = image_generator.generate(captcha_text)

    response = make_response(
        send_file(io.BytesIO(image_data.read()), mimetype="image/png")
    )
    # Prevent browser caching so every refresh gives a brand new image
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.set_cookie(
        "bseb_captcha_sig",
        create_signature(captcha_text),
        max_age=300,  # Valid for 5 minutes
        httponly=True,
        samesite="Lax",
    )
    return response


@app.route("/api/verify-captcha", methods=["POST"])
def verify_captcha():
    """Verify the user's captcha input against the signed cookie."""
    payload = request.get_json(silent=True) or {}
    user_input = str(payload.get("captcha", "")).strip().upper()
    saved_sig = request.cookies.get("bseb_captcha_sig", "")

    if not user_input or not saved_sig:
        return jsonify({"valid": False, "message": "Captcha expired or missing"}), 400

    expected_sig = create_signature(user_input)
    is_valid = hmac.compare_digest(saved_sig, expected_sig)

    res = make_response(jsonify({"valid": is_valid}))
    if is_valid:
        # Clear cookie after one use so the same captcha cannot be reused
        res.delete_cookie("bseb_captcha_sig")
    return res