"""
Flask blueprints for the PCAP Analyzer HTTP API.

Each blueprint owns a coherent slice of the REST surface; app.py only wires
them and adds Swagger. Helpers and shared state live in routes.common.
"""

from .auth import auth_bp
from .users import users_bp
from .scans import scans_bp
from .alerts import alerts_bp
from .rules import rules_bp
from .admin import admin_bp
from .config import config_bp
from .ui import ui_bp

ALL_BLUEPRINTS = (
    auth_bp,
    users_bp,
    scans_bp,
    alerts_bp,
    rules_bp,
    admin_bp,
    config_bp,
    ui_bp,
)


def register_all(app):
    """Register every blueprint on *app*."""
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)
