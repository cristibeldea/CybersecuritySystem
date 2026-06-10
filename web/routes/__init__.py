"""
Flask blueprints grouping the web service's HTTP endpoints.

Each blueprint module owns a coherent slice of the URL space:

    captcha_routes.py    — /captcha, /captcha/verify, /captcha/reset,
                           /captcha/asset/<nonce>/<token>, /behavior/check
    admin_routes.py      — /admin and /admin/api/*
    honeypot_routes.py   — /hp-trap, /hp-form, the dynamic trap-prefix
                           catch-all and the @after_request HTML injector
    protected_routes.py  — /, /health, /debug-ip (sit behind the captcha)
"""
