import os

from flask import Flask, redirect, url_for
from werkzeug.security import generate_password_hash

from config import Config
from extensions import db, login_manager
from models import User, PasswordPolicy
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.analyst import analyst_bp
from routes.user import user_bp

from routes.phishing import phishing_bp

def load_blacklist(file_path):
    blacklist = set()

    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                password = line.strip()
                if password:
                    blacklist.add(password)
    return blacklist


def create_default_data(app):
    with app.app_context():
        db.create_all()

        admin_user = User.query.filter_by(username=app.config["DEFAULT_ADMIN_USERNAME"]).first()
        if not admin_user:
            admin_user = User(
                username=app.config["DEFAULT_ADMIN_USERNAME"],
                email="admin@psms.local",
                password_hash=generate_password_hash(app.config["DEFAULT_ADMIN_PASSWORD"]),
                role="admin",
                mfa_enabled=False,
                is_active=True
            )
            db.session.add(admin_user)
            db.session.commit()

        # ── Default User account ──────────────────────────────────────────
        default_user = User.query.filter_by(username="user1").first()
        if not default_user:
            default_user = User(
                username="user1",
                email="user1@psms.local",
                password_hash=generate_password_hash("User@1234"),
                role="user",
                mfa_enabled=False,
                is_active=True
            )
            db.session.add(default_user)
            db.session.commit()

        # ── Default Analyst account ───────────────────────────────────────
        default_analyst = User.query.filter_by(username="analyst1").first()
        if not default_analyst:
            default_analyst = User(
                username="analyst1",
                email="analyst1@psms.local",
                password_hash=generate_password_hash("Analyst@1234"),
                role="analyst",
                mfa_enabled=False,
                is_active=True
            )
            db.session.add(default_analyst)
            db.session.commit()

        default_policy = PasswordPolicy.query.first()
        if not default_policy:
            default_policy = PasswordPolicy(
                min_length=8,
                require_upper=True,
                require_lower=True,
                require_digit=True,
                require_symbol=True,
                updated_by=admin_user.id
            )
            db.session.add(default_policy)
            db.session.commit()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    app.blacklist_passwords = load_blacklist(app.config["BLACKLIST_FILE"])

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(analyst_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(phishing_bp)
    @app.route("/")
    def index():
        return redirect(url_for("auth.login"))

    create_default_data(app)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)