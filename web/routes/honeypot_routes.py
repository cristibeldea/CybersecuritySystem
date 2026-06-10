"""
Honeypot subsystem.

Three layers of decoys are injected into every protected HTML response
via the ``@after_request`` hook ``inject_honeypots``:

  1. Traditional invisible links (opacity:0, off-screen, clip-rect).
  2. A hidden form whose field names appear in ``TRAP_FIELD_NAMES``.
  3. 1×1 transparent pixel-links that look like tracking pixels.

A small JS snippet reports any DOM interaction with the traps to
``/hp-trap``. The hidden form posts to ``/hp-form``. Dynamic trap
paths (``/user/<token>``, ``/admin/<token>``, ...) are caught by the
catch-all routes registered through ``register_trap_prefix_routes``.

Any hit on any of these endpoints proves the client is a bot and is
banned for ``BAN_SECONDS_HONEYPOT``.
"""
import logging
import random
import string

from flask import Blueprint, request

from config import BAN_SECONDS_HONEYPOT


log = logging.getLogger("web")
bp = Blueprint("honeypot_routes", __name__)


# Dynamic trap path prefixes — combined with a random token per page
# load to create unique, unpredictable trap URLs.
TRAP_PATH_PREFIXES = [
    "/user/", "/account/", "/api/v2/", "/settings/",
    "/admin/", "/profile/", "/download/", "/export/",
    "/internal/", "/config/", "/session/", "/auth/",
]

# Trap form field names — no real form uses these. Any submission = bot.
TRAP_FIELD_NAMES = {
    "newsletter", "terms_agree", "remember_me",
    "opt_out", "confirm_age", "website_url",
    "fax_number", "middle_name",
}


# ---------------------------------------------------------------------
# Honeypot HTML builder (injected as @after_request)
# ---------------------------------------------------------------------
def _rand_id(n=8):
    """Random CSS-safe id like 'a3f8c1d2'."""
    return random.choice(string.ascii_lowercase) + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=n - 1)
    )


def _rand_token(n=10):
    """Random URL-safe token like 'a3f8c1d2e9'."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _generate_trap_paths(count=4):
    """Generate unique dynamic trap paths for this page load."""
    prefixes = random.sample(TRAP_PATH_PREFIXES, min(count, len(TRAP_PATH_PREFIXES)))
    return [prefix + _rand_token() for prefix in prefixes]


def _build_honeypot_html() -> str:
    """Generate randomised invisible honeypot elements + JS detection script."""
    cls_zero  = _rand_id()
    cls_off   = _rand_id()
    cls_clip  = _rand_id()
    cls_pixel = _rand_id()
    trap_attr = _rand_id()

    trap_paths = _generate_trap_paths(random.randint(3, 5))
    chosen_fields = random.sample(list(TRAP_FIELD_NAMES), random.randint(2, 3))

    field_labels = {
        "newsletter": "Subscribe to newsletter",
        "terms_agree": "I agree to the terms",
        "remember_me": "Remember me",
        "opt_out": "Opt out of tracking",
        "confirm_age": "I am over 18",
        "website_url": "Your website",
        "fax_number": "Fax number",
        "middle_name": "Middle name",
    }

    style = f"""<style>
.{cls_zero}{{opacity:0;position:absolute;z-index:-1;height:0;width:0;overflow:hidden;padding:0;margin:0;border:0;pointer-events:auto}}
.{cls_off}{{position:fixed;left:-9999px;top:-9999px;pointer-events:auto}}
.{cls_clip}{{position:absolute;clip:rect(0,0,0,0);height:1px;width:1px;overflow:hidden;white-space:nowrap;pointer-events:auto}}
.{cls_pixel}{{display:inline-block;width:1px;height:1px;overflow:hidden;color:transparent;background:transparent;border:0;padding:0;margin:0;font-size:0;line-height:0;text-decoration:none;pointer-events:auto;position:relative;z-index:0}}
</style>"""

    traps = []

    # Layer 1: traditional hidden links (2 paths)
    for href in trap_paths[:2]:
        cls = random.choice([cls_zero, cls_off, cls_clip])
        tid = _rand_id()
        traps.append(
            f'<a href="{href}" class="{cls}" id="{tid}" '
            f'data-{trap_attr}="1" tabindex="-1" aria-hidden="true">link</a>'
        )

    # Layer 2: hidden form with trap fields
    form_id = _rand_id()
    form_parts = [f'<form action="/hp-form" method="POST" class="{cls_off}" '
                  f'id="{form_id}" aria-hidden="true">']
    for name in chosen_fields:
        tid = _rand_id()
        label = field_labels.get(name, name.replace("_", " ").title())
        form_parts.append(
            f'<label for="{tid}">{label}</label>'
            f'<input type="checkbox" id="{tid}" name="{name}" '
            f'data-{trap_attr}="1" tabindex="-1">'
        )
    form_parts.append(f'<button type="submit" tabindex="-1" data-{trap_attr}="1">Submit</button>')
    form_parts.append('</form>')
    traps.append("\n".join(form_parts))

    # Layer 3: 1px transparent pixel-links (remaining paths)
    for href in trap_paths[2:]:
        tid = _rand_id()
        traps.append(
            f'<a href="{href}" class="{cls_pixel}" id="{tid}" '
            f'data-{trap_attr}="1" tabindex="-1">&nbsp;</a>'
        )

    random.shuffle(traps)

    # Layer 4: JS detection — bonus for headless browsers
    script = f"""<script>
(function(){{
var ts=document.querySelectorAll('[data-{trap_attr}]');
ts.forEach(function(el){{
["click","mousedown","touchstart","focus","change","pointerdown"].forEach(function(ev){{
el.addEventListener(ev,function(){{
fetch("/hp-trap",{{method:"POST",headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{t:Date.now(),tag:el.tagName,id:el.id}}),credentials:"same-origin"}});
}},{{passive:true,once:true}});
}});
}});
}})();
</script>"""

    return style + "\n".join(traps) + script


# ---------------------------------------------------------------------
# Trap endpoints
# ---------------------------------------------------------------------
@bp.post("/hp-trap")
def honeypot_trap_js():
    """JS-reported interaction with a hidden element."""
    from ban_manager import ban_ip_with_history
    from helpers import get_client_ip
    ip = get_client_ip()
    log.warning("HONEYPOT JS-TRAP ip=%s", ip)
    ban_ip_with_history(ip, BAN_SECONDS_HONEYPOT, reason="honeypot:js_trap")
    return "", 204


@bp.post("/hp-form")
def honeypot_form_trap():
    """A bot submitted the hidden honeypot form."""
    from ban_manager import ban_ip_with_history
    from helpers import get_client_ip
    ip = get_client_ip()
    log.warning("HONEYPOT FORM-TRAP ip=%s fields=%s", ip, list(request.form.keys()))
    ban_ip_with_history(ip, BAN_SECONDS_HONEYPOT, reason="honeypot:form_submit")
    return "", 204


# ---------------------------------------------------------------------
# App-level registrations
# ---------------------------------------------------------------------
def register_trap_prefix_routes(app) -> None:
    """Catch-all routes for the dynamic trap-path prefixes.

    Any request matching ``/user/<token>``, ``/account/<token>`` etc.
    is a bot following a honeypot link → ban.
    """
    from ban_manager import ban_ip_with_history
    from helpers import get_client_ip

    def _make_prefix_handler(prefix):
        def handler(token):
            ip = get_client_ip()
            log.warning("HONEYPOT LINK-TRAP ip=%s path=%s%s", ip, prefix, token)
            ban_ip_with_history(
                ip, BAN_SECONDS_HONEYPOT,
                reason=f"honeypot:trap_link:{prefix}{token}",
            )
            return "<html><body><h1>Page not available</h1></body></html>", 200
        return handler

    for prefix in TRAP_PATH_PREFIXES:
        endpoint = f"trap_prefix_{prefix.strip('/').replace('/', '_')}"
        rule = prefix + "<path:token>"
        app.add_url_rule(
            rule, endpoint=endpoint,
            view_func=_make_prefix_handler(prefix),
            methods=["GET", "POST"],
        )


def register_inject_after_request(app) -> None:
    """Wire the @after_request hook that injects honeypots into HTML pages."""
    @app.after_request
    def inject_honeypots(response):
        if response.content_type and "text/html" not in response.content_type:
            return response
        if request.path.startswith(("/captcha", "/static", "/behavior",
                                    "/hp-trap", "/hp-form", "/admin")):
            return response
        try:
            html = response.get_data(as_text=True)
        except Exception:
            return response

        honeypot = _build_honeypot_html()
        if "</body>" in html:
            html = html.replace("</body>", honeypot + "\n</body>", 1)
        elif "</html>" in html:
            html = html.replace("</html>", honeypot + "\n</html>", 1)
        else:
            html += honeypot

        response.set_data(html)
        response.headers["Content-Length"] = len(response.get_data())
        return response
