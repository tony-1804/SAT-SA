FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py app.html ./
ENV SATSA_HOST=0.0.0.0
EXPOSE 8000
CMD ["sh","-c","[ -f alerts.csv ] || python generate_data.py; python satsa.py >/dev/null && python server.py"]
