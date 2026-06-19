"""
Vite asset helper for Jinja templates.

Two modes:
  * Production (default): reads `static/dist/.vite/manifest.json` produced by
    `npm run build` and emits hashed <script>/<link> tags pointing at
    /static/dist/...
  * Development (`VITE_DEV=1` env var): emits tags pointing at the Vite dev
    server (http://localhost:5173/<entry>) so HMR works. The dev server is
    expected to proxy /api back to Flask.

Registered in app.py as the Jinja global `vite_assets`.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict

from markupsafe import Markup


DEFAULT_ENTRY = 'frontend/src/main.js'
MANIFEST_PATH = Path('static/dist/.vite/manifest.json')
DEV_SERVER = os.environ.get('VITE_DEV_URL', 'http://localhost:5173')


def _dev_mode() -> bool:
    return os.environ.get('VITE_DEV') == '1'


def _read_manifest() -> Dict[str, Any]:
    if not MANIFEST_PATH.exists():
        return {}
    try:
        return json.loads(MANIFEST_PATH.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}


def vite_assets(entry: str = DEFAULT_ENTRY) -> Markup:
    """Return the <script>/<link> tags to load the Vite-built bundle."""
    if _dev_mode():
        return Markup(
            f'<script type="module" src="{DEV_SERVER}/@vite/client"></script>\n'
            f'<script type="module" src="{DEV_SERVER}/{entry}"></script>'
        )

    manifest = _read_manifest()
    info = manifest.get(entry)
    if not info:
        return Markup(
            '<!-- Vite manifest missing or entry not found. '
            'Run `npm install && npm run build` to generate static/dist/. -->'
        )

    tags = []
    for css in info.get('css', []):
        tags.append(f'<link rel="stylesheet" href="/static/dist/{css}">')
    tags.append(
        f'<script type="module" src="/static/dist/{info["file"]}"></script>'
    )
    return Markup('\n'.join(tags))
