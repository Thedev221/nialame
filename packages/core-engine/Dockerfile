FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir -e .

EXPOSE 8000

# Lié à 127.0.0.1 par défaut : toute exposition externe doit passer par
# un reverse proxy avec TLS/auth/CORS/rate-limit (voir docs/threat-model.md).
CMD ["uvicorn", "nialame.main:app", "--host", "127.0.0.1", "--port", "8000"]
