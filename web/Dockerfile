FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates ./templates
COPY request_checker ./request_checker
COPY captcha ./captcha

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["gunicorn", "-w", "1", "-k", "gthread", "--threads", "8", "-b", "0.0.0.0:8080", "app:app"]