FROM python:3.12-slim
WORKDIR /app
COPY *.py ./
EXPOSE 8080
# Keys arrive via environment only (docker compose env_file / VM .env).
CMD ["python3", "app.py"]
