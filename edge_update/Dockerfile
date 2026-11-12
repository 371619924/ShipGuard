# Authored configuration only; no image was built or executed in this environment.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /work
COPY requirements.txt /work/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m tester
COPY --chown=10001:10001 . /work
USER 10001
CMD ["python", "-m", "edge_update.run_validation", "/tmp/edge-evidence"]
