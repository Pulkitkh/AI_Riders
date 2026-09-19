# PRAHARI live sensor.
#
# The entire detection engine is pure-CPython with no third-party dependency, so
# this image is just Python on Alpine plus the source — a few megabytes, and a
# cold start that is the interpreter, nothing more. That is the property that
# lets it install on an air-gapped appliance.
#
# Live capture needs a raw socket, so run with host networking and NET_RAW:
#
#   docker build -t prahari .
#   docker run --rm --network host --cap-add NET_RAW -p 8000:8000 prahari
#
# then open http://<host>:8000 and start the sensor. Without --network host the
# container taps its own veth (still real capture, but only container traffic).
FROM python:3.12-alpine

WORKDIR /app
COPY prahari/ ./prahari/
COPY sensor/ ./sensor/
COPY web/ ./web/
COPY eval/ ./eval/

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Precompute the replay datasets at build time so the static tabs load instantly.
RUN python -m web.build

EXPOSE 8000
# Default: serve everything and start the live sensor on the primary interface.
# Override the interface with -e IFACE=eth0.
ENV IFACE=eth0 PORT=8000
CMD ["sh", "-c", "python -m web.server --host 0.0.0.0 --port ${PORT} --iface ${IFACE} --live"]
