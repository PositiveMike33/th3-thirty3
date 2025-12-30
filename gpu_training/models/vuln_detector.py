"""
Th3 Thirty3 - Vulnerability Detection Model
TensorFlow model for identifying security vulnerabilities in code
"""

import os
import json
import numpy as np
import tensorflow as tf
from tensorflow import keras
from typing import List, Dict, Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityDetector:
    """
    GPU-accelerated vulnerability detection model.
    Classifies code snippets into vulnerability categories.
    """
    
    VULNERABILITY_CLASSES = [
        'sql_injection',
        'xss',
        'command_injection',
        'path_traversal',
        'weak_auth',
        'insecure_deserialization',
        'ssrf',
        'xxe',
        'idor',
        'csrf',
        'hardcoded_secrets',
        'buffer_overflow',
        'race_condition',
        'safe'  # No vulnerability
    ]
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or '/app/trained_models/vuln_detector'
        self.model = None
        self.embedding_dim = 768
        self.num_classes = len(self.VULNERABILITY_CLASSES)
        
        # Load or create model
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            self.create_model()
    
    def create_model(self) -> keras.Model:
        """Create the vulnerability detection model."""
        logger.info("Creating new vulnerability detection model...")
        
        self.model = keras.Sequential([
            # Input layer - expects embeddings
            keras.layers.Input(shape=(self.embedding_dim,)),
            
            # Dense layers with dropout for regularization
            keras.layers.Dense(512, activation='relu'),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.4),
            
            keras.layers.Dense(256, activation='relu'),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.3),
            
            keras.layers.Dense(128, activation='relu'),
            keras.layers.BatchNormalization(),
            keras.layers.Dropout(0.2),
            
            keras.layers.Dense(64, activation='relu'),
            
            # Output layer - multi-class classification
            keras.layers.Dense(self.num_classes, activation='softmax')
        ])
        
        # Compile with appropriate optimizer and loss
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        logger.info(f"Model created with {self.num_classes} vulnerability classes")
        return self.model
    
    def load_model(self) -> None:
        """Load a saved model."""
        try:
            self.model = keras.models.load_model(self.model_path)
            logger.info(f"Model loaded from {self.model_path}")
        except Exception as e:
            logger.warning(f"Could not load model: {e}, creating new")
            self.create_model()
    
    def save_model(self) -> None:
        """Save the model to disk."""
        if self.model:
            self.model.save(self.model_path)
            logger.info(f"Model saved to {self.model_path}")
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        epochs: int = 10,
        batch_size: int = 32
    ) -> Dict:
        """
        Train the model on vulnerability data.
        
        Args:
            X_train: Training embeddings (n_samples, embedding_dim)
            y_train: Training labels (n_samples,) or one-hot encoded
            X_val: Validation embeddings
            y_val: Validation labels
            epochs: Number of training epochs
            batch_size: Batch size for training
            
        Returns:
            Training history dictionary
        """
        if self.model is None:
            self.create_model()
        
        # Convert labels to one-hot if needed
        if len(y_train.shape) == 1:
            y_train = keras.utils.to_categorical(y_train, self.num_classes)
        
        validation_data = None
        if X_val is not None and y_val is not None:
            if len(y_val.shape) == 1:
                y_val = keras.utils.to_categorical(y_val, self.num_classes)
            validation_data = (X_val, y_val)
        
        # Callbacks
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss' if validation_data else 'loss',
                patience=3,
                restore_best_weights=True
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss' if validation_data else 'loss',
                factor=0.5,
                patience=2
            )
        ]
        
        logger.info(f"Training on {len(X_train)} samples for {epochs} epochs...")
        
        history = self.model.fit(
            X_train, y_train,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        # Save after training
        self.save_model()
        
        return {
            'loss': history.history['loss'],
            'accuracy': history.history['accuracy'],
            'val_loss': history.history.get('val_loss', []),
            'val_accuracy': history.history.get('val_accuracy', [])
        }
    
    def predict(self, embeddings: np.ndarray) -> List[Dict]:
        """
        Predict vulnerabilities for code embeddings.
        
        Args:
            embeddings: Code embeddings (n_samples, embedding_dim)
            
        Returns:
            List of prediction dictionaries
        """
        if self.model is None:
            self.create_model()
        
        # Ensure correct shape
        if len(embeddings.shape) == 1:
            embeddings = embeddings.reshape(1, -1)
        
        # Get predictions
        predictions = self.model.predict(embeddings, verbose=0)
        
        results = []
        for pred in predictions:
            top_indices = np.argsort(pred)[::-1][:3]  # Top 3 predictions
            
            result = {
                'primary': {
                    'vulnerability': self.VULNERABILITY_CLASSES[top_indices[0]],
                    'confidence': float(pred[top_indices[0]])
                },
                'alternatives': [
                    {
                        'vulnerability': self.VULNERABILITY_CLASSES[idx],
                        'confidence': float(pred[idx])
                    }
                    for idx in top_indices[1:]
                ],
                'is_vulnerable': self.VULNERABILITY_CLASSES[top_indices[0]] != 'safe',
                'risk_score': float(1 - pred[self.VULNERABILITY_CLASSES.index('safe')]) * 100
            }
            results.append(result)
        
        return results
    
    def analyze_code(self, code: str, embedder=None) -> Dict:
        """
        Analyze code for vulnerabilities.
        
        Args:
            code: Source code string
            embedder: Embedding function/model
            
        Returns:
            Analysis result dictionary
        """
        # For now, use random embeddings if no embedder provided
        # In production, this would use an actual code embedding model
        if embedder is None:
            embedding = np.random.randn(1, self.embedding_dim).astype(np.float32)
        else:
            embedding = embedder(code)
        
        predictions = self.predict(embedding)
        
        return {
            'code_length': len(code),
            'analysis': predictions[0],
            'recommendations': self._get_recommendations(predictions[0])
        }
    
    def _get_recommendations(self, prediction: Dict) -> List[str]:
        """Get security recommendations based on prediction."""
        vuln = prediction['primary']['vulnerability']
        
        recommendations = {
            'sql_injection': [
                'Use parameterized queries or prepared statements',
                'Implement input validation',
                'Use ORM frameworks'
            ],
            'xss': [
                'Sanitize all user input',
                'Use Content Security Policy (CSP)',
                'Encode output appropriately'
            ],
            'command_injection': [
                'Avoid shell=True in subprocess',
                'Use allowlist for commands',
                'Validate and escape all inputs'
            ],
            'path_traversal': [
                'Validate file paths against base directory',
                'Use os.path.realpath for canonicalization',
                'Implement file access controls'
            ],
            'weak_auth': [
                'Use bcrypt or Argon2 for password hashing',
                'Implement multi-factor authentication',
                'Use secure session management'
            ],
            'safe': [
                'Continue following security best practices',
                'Regular security audits recommended'
            ]
        }
        
        return recommendations.get(vuln, ['Review code for security issues'])


class ExploitPredictor:
    """
    Predicts likely exploit techniques for vulnerabilities.
    """
    
    EXPLOIT_TECHNIQUES = [
        'automated_scanner',
        'manual_exploitation',
        'metasploit_module',
        'custom_script',
        'social_engineering',
        'brute_force',
        'privilege_escalation',
        'lateral_movement',
        'data_exfiltration',
        'denial_of_service'
    ]
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or '/app/trained_models/exploit_predictor'
        self.model = None
        self.input_dim = 768
        self.num_classes = len(self.EXPLOIT_TECHNIQUES)
        
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            self.create_model()
    
    def create_model(self) -> keras.Model:
        """Create exploit prediction model."""
        self.model = keras.Sequential([
            keras.layers.Input(shape=(self.input_dim,)),
            keras.layers.Dense(256, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(self.num_classes, activation='sigmoid')  # Multi-label
        ])
        
        self.model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return self.model
    
    def load_model(self) -> None:
        """Load saved model."""
        try:
            self.model = keras.models.load_model(self.model_path)
        except:
            self.create_model()
    
    def predict(self, vulnerability_embedding: np.ndarray) -> List[Dict]:
        """Predict likely exploits for a vulnerability."""
        if self.model is None:
            self.create_model()
        
        if len(vulnerability_embedding.shape) == 1:
            vulnerability_embedding = vulnerability_embedding.reshape(1, -1)
        
        predictions = self.model.predict(vulnerability_embedding, verbose=0)
        
        results = []
        for pred in predictions:
            exploits = [
                {
                    'technique': self.EXPLOIT_TECHNIQUES[i],
                    'probability': float(pred[i])
                }
                for i in range(len(pred))
            ]
            # Sort by probability
            exploits.sort(key=lambda x: x['probability'], reverse=True)
            results.append({
                'likely_exploits': exploits[:5],
                'highest_risk': exploits[0]['technique']
            })
        
        return results


class DefenseRecommender:
    """
    Recommends defense strategies based on detected threats.
    """
    
    DEFENSE_CATEGORIES = [
        'network_security',
        'access_control',
        'encryption',
        'monitoring',
        'incident_response',
        'patch_management',
        'security_awareness',
        'application_security'
    ]
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or '/app/trained_models/defense_recommender'
        self.model = None
        self.input_dim = 768
        self.num_classes = len(self.DEFENSE_CATEGORIES)
        
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            self.create_model()
    
    def create_model(self) -> keras.Model:
        """Create defense recommendation model."""
        self.model = keras.Sequential([
            keras.layers.Input(shape=(self.input_dim,)),
            keras.layers.Dense(256, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dense(self.num_classes, activation='sigmoid')
        ])
        
        self.model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return self.model
    
    def load_model(self) -> None:
        """Load saved model."""
        try:
            self.model = keras.models.load_model(self.model_path)
        except:
            self.create_model()
    
    def recommend(self, threat_embedding: np.ndarray) -> Dict:
        """Recommend defenses for a threat."""
        if self.model is None:
            self.create_model()
        
        if len(threat_embedding.shape) == 1:
            threat_embedding = threat_embedding.reshape(1, -1)
        
        predictions = self.model.predict(threat_embedding, verbose=0)[0]
        
        recommendations = []
        for i, prob in enumerate(predictions):
            if prob > 0.3:  # Threshold for recommendation
                recommendations.append({
                    'category': self.DEFENSE_CATEGORIES[i],
                    'priority': float(prob),
                    'actions': self._get_actions(self.DEFENSE_CATEGORIES[i])
                })
        
        recommendations.sort(key=lambda x: x['priority'], reverse=True)
        
        return {
            'recommendations': recommendations,
            'top_priority': recommendations[0]['category'] if recommendations else 'review_needed'
        }
    
    def _get_actions(self, category: str) -> List[str]:
        """Get specific actions for a defense category."""
        actions = {
            'network_security': [
                'Implement network segmentation',
                'Deploy IDS/IPS',
                'Enable firewall rules'
            ],
            'access_control': [
                'Implement MFA',
                'Review permissions',
                'Enable least privilege'
            ],
            'encryption': [
                'Enable TLS 1.3',
                'Encrypt data at rest',
                'Implement key management'
            ],
            'monitoring': [
                'Deploy SIEM',
                'Enable log aggregation',
                'Set up alerting'
            ],
            'incident_response': [
                'Update IR playbooks',
                'Test backup procedures',
                'Train response team'
            ],
            'patch_management': [
                'Inventory vulnerable systems',
                'Schedule patching windows',
                'Test patches before deployment'
            ],
            'security_awareness': [
                'Conduct phishing simulations',
                'Update training materials',
                'Regular security briefings'
            ],
            'application_security': [
                'Code review',
                'SAST/DAST scanning',
                'WAF deployment'
            ]
        }
        return actions.get(category, ['Review security posture'])


if __name__ == '__main__':
    # Test the models
    print("Testing Vulnerability Detector...")
    detector = VulnerabilityDetector()
    
    # Test prediction with random embedding
    test_embedding = np.random.randn(1, 768).astype(np.float32)
    result = detector.predict(test_embedding)
    print(f"Prediction: {result[0]['primary']}")
    
    print("\nTesting Exploit Predictor...")
    predictor = ExploitPredictor()
    exploits = predictor.predict(test_embedding)
    print(f"Top exploit: {exploits[0]['highest_risk']}")
    
    print("\nTesting Defense Recommender...")
    recommender = DefenseRecommender()
    defenses = recommender.recommend(test_embedding)
    print(f"Top defense: {defenses['top_priority']}")
    
    print("\n✅ All models initialized successfully!")
