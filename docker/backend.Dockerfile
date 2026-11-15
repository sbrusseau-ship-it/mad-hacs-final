FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && python -m playwright install --with-deps chromium
COPY SecurityApp/*.py ./SecurityApp/
CMD ["uvicorn", "SecurityApp.api:app", "--host", "0.0.0.0", "--port", "8000"]
