FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire inspector source tree:
#   - inspector.py        (main loop)
#   - config.py           (env-var driven configuration)
#   - state.py            (shared Redis client + in-memory caches)
#   - ban.py              (Redis ban primitive)
#   - modules/            (m1_volume, m2_frequency, ..., m6_botnet)
COPY inspector.py config.py state.py ban.py ./
COPY modules ./modules

ENV PYTHONUNBUFFERED=1

CMD ["python", "inspector.py"]
