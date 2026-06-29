FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY src/ src/
COPY scripts/ scripts/
RUN pip install --no-cache-dir .

# Download data and train at build time so the image ships with a ready model.
# (Comment out if you prefer to mount data/artifacts as volumes instead.)
RUN python scripts/download_data.py && python -m netsentinel.train

ENTRYPOINT ["python", "-m", "netsentinel.realtime"]
CMD ["--source", "replay", "--limit", "50"]
