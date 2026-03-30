FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY inference.py .
COPY server.py .
COPY openenv.yaml .
COPY custom_emails.txt .
COPY data/ data/

ENV PYTHONPATH=/app
ENV PORT=7860

EXPOSE 7860

CMD ["python", "server.py"]