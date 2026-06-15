"""Factory Flask plus inregistrarea blueprint-urilor."""
import logging

from flask import Flask

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [web] %(message)s",
)

app = Flask(__name__)

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
