# Th3 Thirty3 - GPU Training Service
# TensorFlow with CUDA for Ethical Hacking AI
FROM tensorflow/tensorflow:2.15.0-gpu

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip first
RUN pip install --upgrade pip

# Install Flask and CORS separately with ignore-installed to avoid conflicts
RUN pip install --ignore-installed flask flask-cors

# Install additional utilities (these should be safe)
RUN pip install python-dotenv tqdm || true

# Copy application code
COPY . .

# Create directories
RUN mkdir -p /app/trained_models /app/datasets /app/logs

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV TF_CPP_MIN_LOG_LEVEL=1
ENV CUDA_VISIBLE_DEVICES=0

# Expose ports
EXPOSE 5000 6006

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import tensorflow as tf; print('GPU:', len(tf.config.list_physical_devices('GPU')))"

# Start the training server
CMD ["python", "trainer.py"]
