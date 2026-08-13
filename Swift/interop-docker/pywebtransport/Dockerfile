FROM python:3.12-slim
RUN pip install --no-cache-dir pywebtransport==0.1.2 aioquic==1.3.0
COPY server.py /srv/server.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/srv/server.py"]
