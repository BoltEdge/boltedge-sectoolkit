"""
BoltEdge SecToolkit â€” Flask App Factory (Complete â€” 101 Tools)
"""
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

from app.config import get_config
from app.utils.formatters import register_error_handlers


db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_override=None):
    app = Flask(__name__)

    if config_override:
        if isinstance(config_override, dict):
            app.config.from_mapping(config_override)
        else:
            app.config.from_object(config_override)
    else:
        app.config.from_object(get_config())

    db.init_app(app)
    limiter.init_app(app)
    CORS(app, origins=app.config.get("CORS_ORIGINS", ["*"]))

    register_error_handlers(app)
    _register_blueprints(app)

    with app.app_context():
        db.create_all()

    return app


def _register_blueprints(app):
    from app.routes.health import health_bp
    app.register_blueprint(health_bp)

    from app.routes.ip_routes import ip_bp
    app.register_blueprint(ip_bp, url_prefix="/api/ip")

    from app.routes.domain_routes import domain_bp
    app.register_blueprint(domain_bp, url_prefix="/api/domain")

    from app.routes.ssl_routes import ssl_bp
    app.register_blueprint(ssl_bp, url_prefix="/api/ssl")

    from app.routes.url_routes import url_bp
    app.register_blueprint(url_bp, url_prefix="/api/url")

    from app.routes.email_routes import email_bp
    app.register_blueprint(email_bp, url_prefix="/api/email")

    from app.routes.hash_routes import hash_bp
    app.register_blueprint(hash_bp, url_prefix="/api/hash")

    from app.routes.encode_routes import encode_bp
    app.register_blueprint(encode_bp, url_prefix="/api/encode")

    from app.routes.network_routes import network_bp
    app.register_blueprint(network_bp, url_prefix="/api/network")

    from app.routes.threat_routes import threat_bp
    app.register_blueprint(threat_bp, url_prefix="/api/threat")

    from app.routes.password_routes import password_bp
    app.register_blueprint(password_bp, url_prefix="/api/password")

    from app.routes.external_routes import external_bp
    app.register_blueprint(external_bp, url_prefix="/api/external")

