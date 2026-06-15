FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY inspector.py config.py state.py ban.py ./
COPY modules ./modules

ENV PYTHONUNBUFFERED=1

CMD ["python", "inspector.py"]
