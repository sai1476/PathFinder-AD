"""
PathFinder AD application factory.
"""

from __future__ import annotations
import os
from flask import Flask


def create_app(test_config=None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "pathfinder-ad-insecure-dev-key"),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB max upload
    )

    if test_config:
        app.config.update(test_config)

    from app.routes import bp
    app.register_blueprint(bp)

    return app
