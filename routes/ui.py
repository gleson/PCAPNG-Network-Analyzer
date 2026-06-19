"""
HTML page + static asset routes.
"""

from flask import Blueprint, render_template, send_from_directory


ui_bp = Blueprint('ui', __name__)


@ui_bp.route('/')
def index():
    """Main page."""
    return render_template('index.html')


@ui_bp.route('/static/<path:path>')
def send_static(path):
    """Serve files from the static/ directory."""
    return send_from_directory('static', path)
