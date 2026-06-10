"""
Flask application factory + blueprint registration.

After the refactor that split the original 1119-line ``app.py``, this
file only:

  1. configures logging,
  2. creates the Flask app,
  3. wires the global ``@before_request`` security gate + the
     ``@after_request`` honeypot injector,
  4. registers blueprints for /captcha, /admin, honeypots and the
     protected pages,
  5. registers the dynamic catch-all trap routes.

All business logic lives in dedicated modules (``ban_manager``,
``event_publisher``, ``helpers``) or in the blueprints under
``routes/``.
"""
import logging

from flask import Flask


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [web] %(message)s",
)

app = Flask(__name__)


# Hooks + blueprints are imported after ``app`` exists so the local
# imports inside ``register_security_gate`` (which need ban_manager and
# routes.honeypot_routes) resolve cleanly.
from event_publisher import register_security_gate
from routes.admin_routes import bp as admin_bp
from routes.captcha_routes import bp as captcha_bp
from routes.honeypot_routes import (
    bp as honeypot_bp,
    register_inject_after_request,
    register_trap_prefix_routes,
)
from routes.protected_routes import bp as protected_bp


register_security_gate(app)
register_inject_after_request(app)

app.register_blueprint(captcha_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(honeypot_bp)
app.register_blueprint(protected_bp)

register_trap_prefix_routes(app)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
