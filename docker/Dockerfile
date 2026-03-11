FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN pip install -e .
EXPOSE 5000 9090
CMD ["python", "-m", "flask", "--app", "waf.core.proxy:create_app", "run", "--host", "0.0.0.0", "--port", "5000"]
