import React, { useState } from 'react';
import axios from 'axios';

const API_URL = 'http://localhost:8000';

function App() {
  const [file, setFile] = useState(null);
  const [algorithm, setAlgorithm] = useState('AES');
  const [kdf, setKdf] = useState('argon2');
  const [password, setPassword] = useState('');
  const [preview, setPreview] = useState('');
  const [mode, setMode] = useState('encrypt');
  const [downloadLink, setDownloadLink] = useState('');
  const [loading, setLoading] = useState(false);
  const [filename, setFilename] = useState('');
  const [isHash, setIsHash] = useState(false);

  const algorithms = ['AES', 'ChaCha20', 'Blowfish', 'Fernet', 'XOR', 'SHA-256'];
  const kdfs = ['argon2', 'scrypt', 'pbkdf2', 'bcrypt'];

  const algorithmInfo = {
    'AES': 'Advanced Encryption Standard - Industry gold standard, 256-bit security',
    'ChaCha20': 'Modern stream cipher - Faster than AES on mobile, used by Google',
    'Blowfish': 'Fast block cipher - 64-bit blocks, great for smaller files',
    'Fernet': 'Authenticated encryption - Built-in integrity verification',
    'XOR': 'Educational cipher - Simple bitwise encryption for learning',
    'SHA-256': 'One-way hash - Creates unique fingerprint, cannot be reversed'
  };

  const kdfInfo = {
    'argon2': 'Most secure - Winner of 2015 Password Hashing Competition',
    'scrypt': 'Memory-hard - Resistant to GPU and ASIC attacks',
    'pbkdf2': 'Industry standard - NIST recommended, FIPS validated',
    'bcrypt': 'Time-tested - Specifically designed for password hashing'
  };

  const needsPassword = ['AES', 'ChaCha20', 'Blowfish', 'XOR'];
  const needsKdf = ['AES', 'ChaCha20', 'Blowfish'];

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setFile(selectedFile);
    setPreview('');
    setDownloadLink('');
    setIsHash(false);
  };

  const handlePreview = async () => {
    if (!file) {
      alert('Please select a file first');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
      setLoading(true);
      const response = await axios.post(`${API_URL}/preview`, formData);
      setPreview(response.data.preview);
    } catch (error) {
      alert('Preview failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleEncrypt = async () => {
    if (!file) {
      alert('Please select a file first');
      return;
    }

    if (needsPassword.includes(algorithm) && !password.trim()) {
      alert('Please enter a password for ' + algorithm);
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('algorithm', algorithm);
    
    if (needsPassword.includes(algorithm)) {
      formData.append('password', password);
    }
    
    if (needsKdf.includes(algorithm)) {
      formData.append('kdf', kdf);
    }

    try {
      setLoading(true);
      const response = await axios.post(`${API_URL}/encrypt`, formData);
      
      setPreview(response.data.preview);
      setFilename(response.data.filename);
      setDownloadLink(`${API_URL}/download/${response.data.filename}`);
      setIsHash(response.data.is_hash || false);
    } catch (error) {
      alert('Encryption failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!file) {
      alert('Please select a file first');
      return;
    }

    if (algorithm === 'SHA-256') {
      alert('SHA-256 is a one-way hash function and cannot be decrypted!');
      return;
    }

    if (needsPassword.includes(algorithm) && !password.trim()) {
      alert('Please enter the password used for encryption');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('algorithm', algorithm);
    
    if (needsPassword.includes(algorithm)) {
      formData.append('password', password);
    }

    try {
      setLoading(true);
      const response = await axios.post(`${API_URL}/decrypt`, formData);
      
      setPreview(response.data.preview);
      setFilename(response.data.filename);
      setDownloadLink(`${API_URL}/download/${response.data.filename}`);
      setIsHash(false);
    } catch (error) {
      alert('Decryption failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-indigo-900 mb-2">
            Advanced File Encryption & Hashing Tool
          </h1>
          <p className="text-gray-600">Industry-standard algorithms with cutting-edge key derivation</p>
        </div>

        <div className="bg-white rounded-lg shadow-xl p-8">
          {/* Mode Selection */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Select Mode
            </label>
            <div className="flex gap-4">
              <button
                onClick={() => setMode('encrypt')}
                className={`flex-1 py-2 px-4 rounded-lg font-semibold transition ${
                  mode === 'encrypt'
                    ? 'bg-indigo-600 text-white'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                Encrypt / Hash
              </button>
              <button
                onClick={() => setMode('decrypt')}
                className={`flex-1 py-2 px-4 rounded-lg font-semibold transition ${
                  mode === 'decrypt'
                    ? 'bg-indigo-600 text-white'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                Decrypt
              </button>
            </div>
          </div>

          {/* File Upload */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Upload File
            </label>
            <div className="flex items-center justify-center w-full">
              <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-indigo-300 border-dashed rounded-lg cursor-pointer bg-indigo-50 hover:bg-indigo-100 transition">
                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                  <svg className="w-10 h-10 mb-3 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                  <p className="mb-2 text-sm text-gray-500">
                    <span className="font-semibold">Click to upload</span> or drag and drop
                  </p>
                  <p className="text-xs text-gray-500">TXT, PDF, DOCX, DOC</p>
                </div>
                <input 
                  type="file" 
                  className="hidden" 
                  onChange={handleFileChange}
                  accept=".txt,.pdf,.doc,.docx"
                />
              </label>
            </div>
            {file && (
              <p className="mt-2 text-sm text-gray-600">
                Selected: <span className="font-semibold">{file.name}</span> ({(file.size / 1024).toFixed(2)} KB)
              </p>
            )}
          </div>

          {/* Algorithm Selection */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Encryption Algorithm
            </label>
            <select
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            >
              {algorithms.map((algo) => (
                <option key={algo} value={algo}>
                  {algo}
                </option>
              ))}
            </select>
            <p className="mt-2 text-sm text-gray-600">
              ℹ️ {algorithmInfo[algorithm]}
            </p>
          </div>

          {/* KDF Selection - Show for AES, ChaCha20, Blowfish */}
          {needsKdf.includes(algorithm) && mode === 'encrypt' && (
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Key Derivation Function (KDF)
              </label>
              <select
                value={kdf}
                onChange={(e) => setKdf(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              >
                {kdfs.map((k) => (
                  <option key={k} value={k}>
                    {k.toUpperCase()}
                  </option>
                ))}
              </select>
              <p className="mt-2 text-sm text-green-700">
                ✓ {kdfInfo[kdf]}
              </p>
            </div>
          )}

          {/* Password Input */}
          {needsPassword.includes(algorithm) && (
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password {mode === 'decrypt' && <span className="text-red-600">*</span>}
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder={mode === 'encrypt' ? 'Enter strong password' : 'Enter decryption password'}
                required
              />
              <p className="mt-1 text-sm text-gray-500">
                {mode === 'encrypt' 
                  ? '⚠️ Remember this password - you\'ll need it to decrypt!' 
                  : '🔑 Must match the encryption password exactly'}
              </p>
            </div>
          )}

          {/* Info for Fernet */}
          {algorithm === 'Fernet' && (
            <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <p className="text-sm text-blue-800">
                ℹ️ <strong>Fernet:</strong> Uses an automatically generated key stored on the server. No password needed.
              </p>
            </div>
          )}

          {/* SHA-256 Warning */}
          {algorithm === 'SHA-256' && (
            <div className="mb-6 p-4 bg-amber-50 border border-amber-200 rounded-lg">
              <p className="text-sm text-amber-800">
                ⚠️ <strong>Note:</strong> SHA-256 creates a one-way hash. It cannot be reversed or decrypted.
              </p>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex gap-4 mb-6">
            <button
              onClick={handlePreview}
              disabled={loading}
              className="flex-1 bg-gray-600 text-white py-2 px-4 rounded-lg hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition font-medium"
            >
              {loading ? 'Loading...' : 'Preview File'}
            </button>
            <button
              onClick={mode === 'encrypt' ? handleEncrypt : handleDecrypt}
              disabled={loading}
              className="flex-1 bg-indigo-600 text-white py-2 px-4 rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition font-medium"
            >
              {loading 
                ? 'Processing...' 
                : mode === 'encrypt' 
                  ? (algorithm === 'SHA-256' ? 'Generate Hash' : 'Encrypt File') 
                  : 'Decrypt File'}
            </button>
          </div>

          {/* Preview Section */}
          {preview && (
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                {isHash ? '🔐 SHA-256 Hash Output' : '👁️ Preview'}
              </label>
              <div className="bg-gray-50 border border-gray-300 rounded-lg p-4 max-h-64 overflow-auto">
                <pre className="text-sm text-gray-800 whitespace-pre-wrap break-all font-mono">
                  {preview}
                </pre>
              </div>
              {isHash && (
                <p className="mt-2 text-xs text-gray-500">
                  This 64-character hexadecimal string is the unique fingerprint of your file.
                </p>
              )}
            </div>
          )}

          {/* Download Button */}
          {downloadLink && (
            <a
              href={downloadLink}
              download={filename}
              className="flex items-center justify-center gap-2 w-full bg-green-600 text-white py-3 px-4 rounded-lg hover:bg-green-700 transition font-medium"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Download {isHash ? 'Hash File' : (mode === 'encrypt' ? 'Encrypted' : 'Decrypted')} File
            </a>
          )}
        </div>

        {/* Algorithm Comparison Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8">
          <div className="bg-white rounded-lg shadow p-4 hover:shadow-lg transition">
            <h3 className="font-bold text-indigo-900 mb-3">🏆 Best Overall</h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700">Security:</span>
                <span className="text-sm font-semibold text-green-600">AES-256 + Argon2</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700">Speed:</span>
                <span className="text-sm font-semibold text-blue-600">ChaCha20</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-4 hover:shadow-lg transition">
            <h3 className="font-bold text-indigo-900 mb-3">⚡ Performance</h3>
            <p className="text-xs text-gray-600 mb-2">Encryption time (1MB file):</p>
            <ul className="text-xs space-y-1">
              <li>ChaCha20: ~10ms ⚡</li>
              <li>AES-256: ~15ms ⚡</li>
              <li>Blowfish: ~20ms</li>
            </ul>
          </div>

          <div className="bg-white rounded-lg shadow p-4 hover:shadow-lg transition">
            <h3 className="font-bold text-indigo-900 mb-3">🔐 Use Cases</h3>
            <ul className="text-xs space-y-1 text-gray-700">
              <li>• <strong>AES:</strong> Government data</li>
              <li>• <strong>ChaCha20:</strong> Mobile apps</li>
              <li>• <strong>SHA-256:</strong> File verification</li>
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center text-sm text-gray-600">
          <p>🔒 Military-grade encryption with state-of-the-art key derivation</p>
          <p className="text-xs mt-1">Powered by Python cryptography, PyCryptodome, Argon2</p>
        </div>
      </div>
    </div>
  );
}

export default App;
