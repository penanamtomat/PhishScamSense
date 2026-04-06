FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["bentoml", "serve", "src.inference.service:svc", "--host", "0.0.0.0", "--port", "3000"]
