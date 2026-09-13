# The interop peer with its own logging turned up (WT-135).
#
# The upstream server logs at INFO, and aioquic's HTTP/3 and QUIC state transitions are at DEBUG -- so "what does
# the peer make of our request" had no answer from the peer's side. This is the same server and the same packages
# with one line changed.
FROM python:3.12-slim
RUN pip install --no-cache-dir pywebtransport==0.1.2 aioquic==1.3.0
COPY server.py /srv/server.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/srv/server.py"]
