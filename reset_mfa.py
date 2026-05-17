from app import app
from extensions import db
from models import User

with app.app_context():

    users = User.query.all()

    for user in users:
        user.mfa_enabled = False
        user.totp_secret = None

    db.session.commit()

    print("All MFA secrets reset successfully.")