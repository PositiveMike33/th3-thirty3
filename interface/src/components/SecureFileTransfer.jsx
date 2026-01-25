/**
 * SecureFileTransfer.jsx
 * 
 * React component for CipherLink secure file transfer operations.
 * Provides UI for sending and receiving encrypted files using AES-256.
 */

import React, { useState, useEffect, useCallback } from 'react';
import apiService from '../services/apiService';
import './SecureFileTransfer.css';

const SecureFileTransfer = () => {
    // State management
    const [mode, setMode] = useState('send'); // 'send' or 'receive'
    const [status, setStatus] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    // Send mode fields
    const [sendHost, setSendHost] = useState('');
    const [sendPort, setSendPort] = useState('12345');
    const [sendFilePath, setSendFilePath] = useState('');
    const [sendPassword, setSendPassword] = useState('');

    // Receive mode fields
    const [receivePort, setReceivePort] = useState('12345');
    const [receivePassword, setReceivePassword] = useState('');
    const [receiveSaveDir, setReceiveSaveDir] = useState('/tmp/cipherlink_received');
    const [isReceiving, setIsReceiving] = useState(false);

    // Fetch CipherLink status on mount
    useEffect(() => {
        fetchStatus();
    }, []);

    const fetchStatus = async () => {
        try {
            const response = await apiService.get('/hexstrike/cipherlink/status');
            setStatus(response.data);
            setIsReceiving(response.data?.is_receiving || false);
        } catch (err) {
            console.error('[CipherLink] Status fetch error:', err);
            setStatus({ error: 'Service unavailable' });
        }
    };

    const handleSendFile = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);
        setResult(null);

        try {
            const response = await apiService.post('/hexstrike/cipherlink/send', {
                host: sendHost,
                port: parseInt(sendPort),
                filepath: sendFilePath,
                password: sendPassword,
                timeout: 30
            });

            setResult(response.data);
            if (response.data.success) {
                setError(null);
            } else {
                setError(response.data.error || 'Send failed');
            }
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setIsLoading(false);
            fetchStatus();
        }
    };

    const handleStartReceiver = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);
        setResult(null);

        try {
            const response = await apiService.post('/hexstrike/cipherlink/receive/start', {
                port: parseInt(receivePort),
                password: receivePassword,
                save_dir: receiveSaveDir,
                timeout: 300
            });

            setResult(response.data);
            if (response.data.success) {
                setIsReceiving(true);
            } else {
                setError(response.data.error || 'Failed to start receiver');
            }
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setIsLoading(false);
            fetchStatus();
        }
    };

    const handleStopReceiver = async () => {
        setIsLoading(true);
        try {
            await apiService.post('/hexstrike/cipherlink/receive/stop');
            setIsReceiving(false);
            setResult({ message: 'Receiver stopped' });
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        } finally {
            setIsLoading(false);
            fetchStatus();
        }
    };

    const handleCheckResult = async () => {
        try {
            const response = await apiService.get('/hexstrike/cipherlink/receive/result');
            setResult(response.data);
            setIsReceiving(response.data?.is_receiving || false);
        } catch (err) {
            setError(err.response?.data?.error || err.message);
        }
    };

    return (
        <div className="secure-file-transfer">
            <div className="sft-header">
                <div className="sft-icon">🔐</div>
                <h2>CipherLink Secure Transfer</h2>
                <p className="sft-subtitle">AES-256 Encrypted File Transfer</p>
            </div>

            {/* Status Badge */}
            <div className="sft-status">
                <span className={`status-badge ${status?.status === 'idle' ? 'idle' : status?.status === 'listening' ? 'listening' : 'active'}`}>
                    {status?.status || 'Unknown'}
                </span>
                {status?.features && (
                    <div className="sft-features">
                        {status.features.map((f, i) => (
                            <span key={i} className="feature-tag">{f}</span>
                        ))}
                    </div>
                )}
            </div>

            {/* Mode Tabs */}
            <div className="sft-tabs">
                <button
                    className={`sft-tab ${mode === 'send' ? 'active' : ''}`}
                    onClick={() => setMode('send')}
                >
                    📤 Send File
                </button>
                <button
                    className={`sft-tab ${mode === 'receive' ? 'active' : ''}`}
                    onClick={() => setMode('receive')}
                >
                    📥 Receive File
                </button>
            </div>

            {/* Send Mode */}
            {mode === 'send' && (
                <form className="sft-form" onSubmit={handleSendFile}>
                    <div className="form-group">
                        <label>🌐 Recipient Host</label>
                        <input
                            type="text"
                            value={sendHost}
                            onChange={(e) => setSendHost(e.target.value)}
                            placeholder="192.168.1.100"
                            required
                        />
                    </div>
                    <div className="form-group">
                        <label>🔌 Port</label>
                        <input
                            type="number"
                            value={sendPort}
                            onChange={(e) => setSendPort(e.target.value)}
                            placeholder="12345"
                            required
                        />
                    </div>
                    <div className="form-group">
                        <label>📁 File Path</label>
                        <input
                            type="text"
                            value={sendFilePath}
                            onChange={(e) => setSendFilePath(e.target.value)}
                            placeholder="/path/to/file.txt"
                            required
                        />
                    </div>
                    <div className="form-group">
                        <label>🔑 Encryption Password</label>
                        <input
                            type="password"
                            value={sendPassword}
                            onChange={(e) => setSendPassword(e.target.value)}
                            placeholder="Enter secure password"
                            required
                        />
                    </div>
                    <button
                        type="submit"
                        className="sft-btn send"
                        disabled={isLoading}
                    >
                        {isLoading ? '⏳ Sending...' : '🚀 Send Encrypted File'}
                    </button>
                </form>
            )}

            {/* Receive Mode */}
            {mode === 'receive' && (
                <div className="sft-form">
                    <div className="form-group">
                        <label>🔌 Listen Port</label>
                        <input
                            type="number"
                            value={receivePort}
                            onChange={(e) => setReceivePort(e.target.value)}
                            placeholder="12345"
                            disabled={isReceiving}
                        />
                    </div>
                    <div className="form-group">
                        <label>🔑 Decryption Password</label>
                        <input
                            type="password"
                            value={receivePassword}
                            onChange={(e) => setReceivePassword(e.target.value)}
                            placeholder="Same password used by sender"
                            disabled={isReceiving}
                        />
                    </div>
                    <div className="form-group">
                        <label>📂 Save Directory</label>
                        <input
                            type="text"
                            value={receiveSaveDir}
                            onChange={(e) => setReceiveSaveDir(e.target.value)}
                            placeholder="/tmp/cipherlink_received"
                            disabled={isReceiving}
                        />
                    </div>

                    <div className="sft-btn-group">
                        {!isReceiving ? (
                            <button
                                className="sft-btn receive"
                                onClick={handleStartReceiver}
                                disabled={isLoading}
                            >
                                {isLoading ? '⏳ Starting...' : '🎯 Start Receiving'}
                            </button>
                        ) : (
                            <>
                                <button
                                    className="sft-btn stop"
                                    onClick={handleStopReceiver}
                                    disabled={isLoading}
                                >
                                    ⏹️ Stop Receiver
                                </button>
                                <button
                                    className="sft-btn check"
                                    onClick={handleCheckResult}
                                >
                                    🔄 Check Status
                                </button>
                            </>
                        )}
                    </div>

                    {isReceiving && (
                        <div className="receiving-indicator">
                            <div className="pulse-dot"></div>
                            <span>Listening on port {receivePort}...</span>
                        </div>
                    )}
                </div>
            )}

            {/* Error Display */}
            {error && (
                <div className="sft-error">
                    <span className="error-icon">❌</span>
                    <span>{error}</span>
                </div>
            )}

            {/* Result Display */}
            {result && (
                <div className={`sft-result ${result.success ? 'success' : 'info'}`}>
                    <div className="result-header">
                        <span className="result-icon">{result.success ? '✅' : 'ℹ️'}</span>
                        <span>{result.message || 'Operation completed'}</span>
                    </div>
                    {result.filename && (
                        <div className="result-detail">
                            <strong>File:</strong> {result.filename}
                        </div>
                    )}
                    {result.filepath && (
                        <div className="result-detail">
                            <strong>Path:</strong> {result.filepath}
                        </div>
                    )}
                    {result.bytes_transferred > 0 && (
                        <div className="result-detail">
                            <strong>Size:</strong> {(result.bytes_transferred / 1024).toFixed(2)} KB
                        </div>
                    )}
                </div>
            )}

            {/* Security Info */}
            <div className="sft-security-info">
                <div className="security-item">
                    <span className="security-icon">🛡️</span>
                    <span>AES-256-CBC Encryption</span>
                </div>
                <div className="security-item">
                    <span className="security-icon">🔐</span>
                    <span>PBKDF2-HMAC-SHA256 (100K iterations)</span>
                </div>
                <div className="security-item">
                    <span className="security-icon">🎲</span>
                    <span>Random IV per session</span>
                </div>
            </div>
        </div>
    );
};

export default SecureFileTransfer;
