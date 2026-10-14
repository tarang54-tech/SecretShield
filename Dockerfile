FROM ghcr.io/gitleaks/gitleaks:v8.28.0 AS gitleaks
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 GITLEAKS_PATH=/usr/local/bin/gitleaks
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && groupadd --system secretshield && useradd --system --gid secretshield --create-home secretshield
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY secretshield ./secretshield
COPY .gitleaks.toml ./.gitleaks.toml
COPY migrations ./migrations
COPY scripts/render-start.sh /usr/local/bin/render-start
RUN chmod 755 /usr/local/bin/render-start \
    && mkdir -p /app/instance /tmp/secretshield \
    && chown -R secretshield:secretshield /app /tmp/secretshield
USER secretshield
EXPOSE 5000
CMD ["gunicorn", "--bind=0.0.0.0:5000", "--workers=2", "--timeout=120", "secretshield:create_app()"]
