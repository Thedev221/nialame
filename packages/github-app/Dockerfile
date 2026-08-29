FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir -e .

EXPOSE 8080

CMD ["uvicorn", "nialame_github_app.main:app", "--host", "0.0.0.0", "--port", "8080"]
