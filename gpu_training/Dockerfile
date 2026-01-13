# ═══════════════════════════════════════════════════════════════════
# Th3 Thirty3 - GPU Training Service (OPTIMIZED)
# TensorFlow with CUDA - Minimal layers
# ═══════════════════════════════════════════════════════════════════

FROM tensorflow/tensorflow:2.15.0-gpu

# Métadonnées
LABEL maintainer="th3-thirty3"
LABEL description="GPU Training Service for Ethical Hacking AI"
LABEL version="2.0"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV TF_CPP_MIN_LOG_LEVEL=1
ENV CUDA_VISIBLE_DEVICES=0
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ───────────────────────────────────────────────────────────────────
# LAYER 1: Tout système + Python deps en UNE SEULE layer
# ───────────────────────────────────────────────────────────────────
COPY requirements.txt ./

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    && pip install --upgrade pip && \
    pip install --ignore-installed -r requirements.txt || \
    pip install --ignore-installed flask flask-cors python-dotenv tqdm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* ~/.cache/pip

# ───────────────────────────────────────────────────────────────────
# LAYER 2: Code source (change souvent)
# ───────────────────────────────────────────────────────────────────
COPY . .

# Créer les répertoires
RUN mkdir -p /app/trained_models /app/datasets /app/logs

EXPOSE 5000 6006

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import tensorflow as tf; print('GPU:', len(tf.config.list_physical_devices('GPU')))"

CMD ["python", "trainer.py"]
