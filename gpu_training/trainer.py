"""
Th3 Thirty3 - GPU Training Service
TensorFlow-powered ethical hacking AI trainer
Supports both automatic and on-demand training modes
"""

import os
import json
import logging
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf
import numpy as np
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# GPU Configuration
def configure_gpu():
    """Configure TensorFlow to use GPU with memory growth."""
    gpus = tf.config.list_physical_devices('GPU')
    if gpus:
        try:
            for gpu in gpus:
                tf.config.experimental.set_memory_growth(gpu, True)
            logger.info(f"✅ GPU configured: {len(gpus)} device(s) available")
            for gpu in gpus:
                logger.info(f"   - {gpu.name}")
            return True
        except RuntimeError as e:
            logger.error(f"GPU configuration error: {e}")
            return False
    else:
        logger.warning("⚠️ No GPU detected, running on CPU")
        return False

GPU_AVAILABLE = configure_gpu()

# Training state
class TrainingManager:
    def __init__(self):
        self.active_jobs = {}
        self.job_history = []
        self.auto_training_enabled = os.environ.get('TRAINING_MODE', 'both') in ['auto', 'both']
        self.models_dir = '/app/trained_models'
        self.datasets_dir = '/app/datasets'
        self.ollama_url = os.environ.get('OLLAMA_URL', 'http://host.docker.internal:11434')
        self.server_url = os.environ.get('SERVER_URL', 'http://host.docker.internal:3000')
        
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.datasets_dir, exist_ok=True)
        
        # Start auto-training thread if enabled
        if self.auto_training_enabled:
            self.auto_train_thread = threading.Thread(target=self._auto_training_loop, daemon=True)
            self.auto_train_thread.start()
            logger.info("🔄 Auto-training enabled and started")
    
    def _auto_training_loop(self):
        """Background thread for automatic training."""
        while True:
            try:
                # Run training cycle every 30 minutes
                time.sleep(1800)
                if not self.active_jobs:
                    logger.info("🔄 Starting automatic training cycle...")
                    self.start_training('auto_cycle', 'security', iterations=3)
            except Exception as e:
                logger.error(f"Auto-training error: {e}")
    
    def start_training(self, job_id, category='all', iterations=5, custom_data=None):
        """Start a new training job."""
        if job_id in self.active_jobs:
            return {'success': False, 'error': f'Job {job_id} already running'}
        
        job = {
            'id': job_id,
            'category': category,
            'iterations': iterations,
            'current_iteration': 0,
            'status': 'starting',
            'started_at': datetime.now().isoformat(),
            'metrics': [],
            'custom_data': custom_data
        }
        
        self.active_jobs[job_id] = job
        
        # Start training in background thread
        thread = threading.Thread(
            target=self._run_training,
            args=(job_id, category, iterations, custom_data),
            daemon=True
        )
        thread.start()
        
        return {'success': True, 'job_id': job_id, 'status': 'started'}
    
    def _run_training(self, job_id, category, iterations, custom_data):
        """Execute the training loop."""
        job = self.active_jobs.get(job_id)
        if not job:
            return
        
        try:
            job['status'] = 'running'
            
            # Load or create security training model
            model = self._get_or_create_model(category)
            
            # Training scenarios by category
            scenarios = self._get_training_scenarios(category)
            
            for i in range(iterations):
                job['current_iteration'] = i + 1
                
                # Pick random scenario
                scenario = scenarios[i % len(scenarios)]
                
                # Generate training data using Ollama
                training_result = self._train_on_scenario(model, scenario, category)
                
                job['metrics'].append({
                    'iteration': i + 1,
                    'scenario': scenario[:50],
                    'loss': training_result.get('loss', 0),
                    'accuracy': training_result.get('accuracy', 0),
                    'timestamp': datetime.now().isoformat()
                })
                
                logger.info(f"[{job_id}] Iteration {i+1}/{iterations} - Loss: {training_result.get('loss', 0):.4f}")
                
                # Small delay between iterations
                time.sleep(2)
            
            job['status'] = 'completed'
            job['completed_at'] = datetime.now().isoformat()
            
            # Save model
            model_path = os.path.join(self.models_dir, f'{category}_model')
            model.save(model_path)
            job['model_path'] = model_path
            
            logger.info(f"✅ Training job {job_id} completed successfully")
            
        except Exception as e:
            job['status'] = 'failed'
            job['error'] = str(e)
            logger.error(f"❌ Training job {job_id} failed: {e}")
        
        finally:
            # Move to history
            self.job_history.append(self.active_jobs.pop(job_id, job))
    
    def _get_or_create_model(self, category):
        """Get existing model or create new one."""
        model_path = os.path.join(self.models_dir, f'{category}_model')
        
        if os.path.exists(model_path):
            try:
                return tf.keras.models.load_model(model_path)
            except:
                pass
        
        # Create new security classification model
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(512, activation='relu', input_shape=(768,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(64, activation='softmax')  # 64 security categories
        ])
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def _get_training_scenarios(self, category):
        """Get training scenarios for category."""
        scenarios = {
            'security': [
                "Analyze this code for SQL injection vulnerabilities",
                "Identify XSS attack vectors in this HTML",
                "Detect command injection patterns",
                "Find authentication bypass methods",
                "Analyze network traffic for intrusion signs",
                "Identify privilege escalation paths",
                "Detect malware signatures in binaries",
                "Analyze API for IDOR vulnerabilities",
            ],
            'pentesting': [
                "Generate nmap scan strategy for target",
                "Create Metasploit exploit sequence",
                "Design SQLMap attack parameters",
                "Plan Burp Suite testing workflow",
                "Develop Hydra brute-force configuration",
                "Create custom reverse shell payload",
                "Design persistence mechanism",
                "Plan lateral movement strategy",
            ],
            'osint': [
                "Extract intelligence from WHOIS data",
                "Analyze social media for personal info",
                "Find exposed credentials in breaches",
                "Map organizational structure from LinkedIn",
                "Identify infrastructure from DNS records",
                "Analyze metadata from public documents",
                "Track digital footprint patterns",
                "Correlate data across multiple sources",
            ],
            'defense': [
                "Recommend firewall rules for this threat",
                "Design IDS signatures for attack pattern",
                "Create incident response playbook",
                "Implement zero-trust architecture",
                "Design security monitoring strategy",
                "Harden system configuration",
                "Implement encryption best practices",
                "Design backup and recovery plan",
            ]
        }
        
        if category == 'all':
            all_scenarios = []
            for cat_scenarios in scenarios.values():
                all_scenarios.extend(cat_scenarios)
            return all_scenarios
        
        return scenarios.get(category, scenarios['security'])
    
    def _train_on_scenario(self, model, scenario, category):
        """Train model on a specific scenario."""
        try:
            # Generate training data using embeddings
            # Simulating with random data for now (will be replaced with actual embeddings)
            batch_size = 32
            x_train = np.random.randn(batch_size, 768).astype(np.float32)
            y_train = np.random.randint(0, 64, batch_size).astype(np.int32)
            
            # Single training step
            history = model.fit(
                x_train, y_train,
                epochs=1,
                batch_size=8,
                verbose=0
            )
            
            return {
                'loss': float(history.history['loss'][0]),
                'accuracy': float(history.history['accuracy'][0])
            }
            
        except Exception as e:
            logger.error(f"Training step error: {e}")
            return {'loss': 0, 'accuracy': 0}
    
    def get_job_status(self, job_id):
        """Get status of a specific job."""
        if job_id in self.active_jobs:
            return self.active_jobs[job_id]
        
        for job in self.job_history:
            if job['id'] == job_id:
                return job
        
        return None
    
    def get_all_jobs(self):
        """Get all active and recent jobs."""
        return {
            'active': list(self.active_jobs.values()),
            'history': self.job_history[-10:]
        }
    
    def stop_job(self, job_id):
        """Stop a running job."""
        if job_id in self.active_jobs:
            self.active_jobs[job_id]['status'] = 'stopping'
            return {'success': True, 'message': f'Stopping job {job_id}'}
        return {'success': False, 'error': 'Job not found'}


# Initialize training manager
training_manager = TrainingManager()


# =================================
# API Endpoints
# =================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    gpus = tf.config.list_physical_devices('GPU')
    return jsonify({
        'status': 'healthy',
        'gpu_available': len(gpus) > 0,
        'gpu_count': len(gpus),
        'gpu_details': [gpu.name for gpu in gpus],
        'tensorflow_version': tf.__version__,
        'auto_training': training_manager.auto_training_enabled,
        'active_jobs': len(training_manager.active_jobs)
    })


@app.route('/api/train/start', methods=['POST'])
def start_training():
    """Start a new training job."""
    data = request.get_json() or {}
    
    job_id = data.get('job_id', f'job_{int(time.time())}')
    category = data.get('category', 'security')
    iterations = data.get('iterations', 5)
    custom_data = data.get('custom_data')
    
    result = training_manager.start_training(job_id, category, iterations, custom_data)
    return jsonify(result)


@app.route('/api/train/status/<job_id>', methods=['GET'])
def get_job_status(job_id):
    """Get status of a training job."""
    job = training_manager.get_job_status(job_id)
    if job:
        return jsonify(job)
    return jsonify({'error': 'Job not found'}), 404


@app.route('/api/train/jobs', methods=['GET'])
def get_all_jobs():
    """Get all training jobs."""
    return jsonify(training_manager.get_all_jobs())


@app.route('/api/train/stop/<job_id>', methods=['POST'])
def stop_job(job_id):
    """Stop a training job."""
    result = training_manager.stop_job(job_id)
    return jsonify(result)


@app.route('/api/embeddings', methods=['POST'])
def generate_embeddings():
    """Generate GPU-accelerated embeddings."""
    data = request.get_json() or {}
    texts = data.get('texts', [])
    
    if not texts:
        return jsonify({'error': 'No texts provided'}), 400
    
    try:
        # Use TensorFlow for GPU-accelerated processing
        # This is a placeholder - will integrate with sentence-transformers
        embeddings = []
        for text in texts:
            # Simulate embedding generation (will be replaced with actual model)
            embedding = np.random.randn(768).tolist()
            embeddings.append(embedding)
        
        return jsonify({
            'embeddings': embeddings,
            'model': 'th3-security-embed',
            'gpu_accelerated': GPU_AVAILABLE,
            'count': len(embeddings)
        })
        
    except Exception as e:
        logger.error(f"Embedding error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze/vulnerability', methods=['POST'])
def analyze_vulnerability():
    """Analyze code/config for vulnerabilities using GPU model."""
    data = request.get_json() or {}
    content = data.get('content', '')
    content_type = data.get('type', 'code')
    
    if not content:
        return jsonify({'error': 'No content provided'}), 400
    
    try:
        # Placeholder for actual vulnerability detection model
        analysis = {
            'vulnerabilities': [],
            'risk_score': np.random.uniform(0, 100),
            'recommendations': [],
            'gpu_accelerated': GPU_AVAILABLE
        }
        
        # Simulated vulnerability detection
        vuln_types = ['SQL Injection', 'XSS', 'CSRF', 'Command Injection', 'Path Traversal']
        if len(content) > 100:
            analysis['vulnerabilities'].append({
                'type': np.random.choice(vuln_types),
                'severity': np.random.choice(['low', 'medium', 'high', 'critical']),
                'confidence': np.random.uniform(0.7, 1.0),
                'description': 'Potential vulnerability detected'
            })
        
        return jsonify(analysis)
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/predict/exploit', methods=['POST'])
def predict_exploit():
    """Predict likely exploits for given vulnerability."""
    data = request.get_json() or {}
    vulnerability = data.get('vulnerability', {})
    
    try:
        # Placeholder for exploit prediction model
        predictions = {
            'exploits': [
                {'technique': 'Manual exploitation', 'probability': 0.85},
                {'technique': 'Automated scanner', 'probability': 0.72},
                {'technique': 'Metasploit module', 'probability': 0.65}
            ],
            'gpu_accelerated': GPU_AVAILABLE
        }
        
        return jsonify(predictions)
        
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/gpu/info', methods=['GET'])
def gpu_info():
    """Get detailed GPU information."""
    gpus = tf.config.list_physical_devices('GPU')
    gpu_details = []
    
    for gpu in gpus:
        try:
            details = tf.config.experimental.get_device_details(gpu)
            gpu_details.append({
                'name': gpu.name,
                'type': gpu.device_type,
                'details': details
            })
        except:
            gpu_details.append({'name': gpu.name, 'type': gpu.device_type})
    
    return jsonify({
        'available': len(gpus) > 0,
        'count': len(gpus),
        'devices': gpu_details,
        'tensorflow_version': tf.__version__,
        'cuda_available': tf.test.is_built_with_cuda()
    })


# =================================
# Main Entry Point
# =================================

if __name__ == '__main__':
    logger.info("=" * 50)
    logger.info("🚀 Th3 Thirty3 GPU Training Service Starting...")
    logger.info(f"   TensorFlow Version: {tf.__version__}")
    logger.info(f"   GPU Available: {GPU_AVAILABLE}")
    logger.info(f"   CUDA Built: {tf.test.is_built_with_cuda()}")
    logger.info(f"   Auto-Training: {training_manager.auto_training_enabled}")
    logger.info("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
