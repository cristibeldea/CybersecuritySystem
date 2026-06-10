FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# After the app.py refactor the web service is laid out as:
#   app.py              — Flask factory + blueprint registration
#   config.py           — env vars, Redis client, ban-ladder constants
#   helpers.py          — IP/UA/host extraction, sid, captcha pass verify, admin auth
#   ban_manager.py      — progressive ban ladder + ban_ip_with_history
#   event_publisher.py  — log_ban_event, log_near_miss, @before_request gate
#   routes/             — one blueprint per URL group (captcha, admin, honeypot, protected)
#   captcha/            — behavioural + visual CAPTCHA subsystem
#   request_checker/    — request publisher to the inspector
COPY app.py config.py helpers.py ban_manager.py event_publisher.py ./
COPY routes ./routes
COPY templates ./templates
COPY request_checker ./request_checker
COPY captcha ./captcha

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["gunicorn", "-w", "1", "-k", "gthread", "--threads", "8", "-b", "0.0.0.0:8080", "app:app"]
