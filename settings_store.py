"""
Settings file IO, decoupled from the web layer.

Both the Flask app and the Celery workers need to read settings (detector
thresholds, API keys, SMTP creds). Keeping this here — with no Flask import —
lets workers load settings locally instead of having the web process ship the
whole settings dict (secrets included) as a Celery task argument, where it would
sit in the Redis broker. See routes.common, which re-exports these for the
blueprints.
"""
import os
import json

SETTINGS_FILE = os.environ.get('SETTINGS_FILE', 'data/settings.json')
# Committed template used to seed SETTINGS_FILE on a fresh data volume.
# settings.json itself is gitignored / dockerignored because it accrues
# secrets (api_keys, smtp.password) at runtime.
SETTINGS_EXAMPLE_FILE = os.environ.get('SETTINGS_EXAMPLE_FILE',
                                       'data/settings.example.json')


def load_settings():
    try:
        # First run on a fresh data volume: seed settings.json from the
        # committed example so detectors get sane thresholds out of the box.
        if not os.path.exists(SETTINGS_FILE) and os.path.exists(SETTINGS_EXAMPLE_FILE):
            try:
                os.makedirs(os.path.dirname(SETTINGS_FILE) or '.', exist_ok=True)
                with open(SETTINGS_EXAMPLE_FILE, 'r') as src:
                    seed = src.read()
                with open(SETTINGS_FILE, 'w') as dst:
                    dst.write(seed)
            except Exception as e:
                print(f"Could not seed settings from example: {e}")

        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        print(f"Error loading settings: {e}")
        return {}


def save_settings(settings):
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE) or '.', exist_ok=True)
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False


__all__ = [
    'SETTINGS_FILE', 'SETTINGS_EXAMPLE_FILE', 'load_settings', 'save_settings',
]
