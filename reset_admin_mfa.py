# reset_admin_mfa.py

from app import app
from extensions import db
from models import User

with app.app_context():
    user = User.query.filter_by(username="admin").first()

    if not user:
        print("Admin user not found.")
    else:
        user.mfa_enabled = False
        user.totp_secret = None
        db.session.commit()
        print("Admin MFA reset successfully.")
        print("Now login again and scan the new QR code.")