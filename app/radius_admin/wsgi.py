"""Gunicorn entry point: gunicorn radius_admin.wsgi:app"""
from . import create_app

app = create_app()
