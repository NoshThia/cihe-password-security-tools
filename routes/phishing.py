from flask import Blueprint, render_template, request
from services.phishing_advisor import get_phishing_ai_advice

phishing_bp = Blueprint("phishing", __name__)

@phishing_bp.route("/phishing", methods=["GET", "POST"])
def phishing():
    result = None
    message_text = ""

    if request.method == "POST":
        message_text = request.form.get("message_text", "")
        result = get_phishing_ai_advice(message_text)

    return render_template("phishing.html", result=result, message_text=message_text)