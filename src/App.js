import React, { useState, useEffect } from 'react';
import SenderPanel from './components/SenderPanel';
import ReceiverPanel from './components/ReceiverPanel';
import IDSPanel from './components/IDSPanel';
// import TransmissionFlow from './components/TransmissionFlow'; // Commented out - not used with tab navigation
// import PerformanceMetrics from './components/PerformanceMetrics'; // Commented out - not used
import ModelMetrics from './components/ModelMetrics';
import CoverPage from './components/CoverPage';

export default function App() {
  const [showCoverPage, setShowCoverPage] = useState(true);
  // eslint-disable-next-line no-unused-vars
  const [message, setMessage] = useState(''); // Used in handleSendMessage
  const [encryptedPackage, setEncryptedPackage] = useState(null);
  const [idsResult, setIdsResult] = useState(null);
  const [decryptedMessage, setDecryptedMessage] = useState(null);
  const [flowStep, setFlowStep] = useState(0);
  const [activeTab, setActiveTab] = useState('sender'); // New state for tab navigation
  const [knownSenders, setKnownSenders] = useState(['alice@example.com']);
  const [currentSender, setCurrentSender] = useState('alice@example.com');
  const [ttpApprovalStatus, setTTPApprovalStatus] = useState(null);
  // eslint-disable-next-line no-unused-vars
  const [ttpComment, setTTPComment] = useState(''); // Used in TTP approval functionality
  const [performanceMetrics, setPerformanceMetrics] = useState([]);
  const [currentSessionId, setCurrentSessionId] = useState(1);
  const [receiverEmail, setReceiverEmail] = useState('bob@example.com');
  const [expectedSenderIP, setExpectedSenderIP] = useState('');
  const [expectedReceiverIP, setExpectedReceiverIP] = useState('');
  const [receiverIP, setReceiverIP] = useState('192.168.1.200'); // Default receiver IP
  const [uploadedFiles, setUploadedFiles] = useState({}); // Store uploaded files by session ID
  
  // Auto-navigate tabs based on flow step
  useEffect(() => {
    if (flowStep === 0) {
      setActiveTab('sender');
    } else if (flowStep === 1) {
      setActiveTab('ids');
    } else if (flowStep >= 2) {
      setActiveTab('receiver');
    }
  }, [flowStep]);
  
  // Generate a new session ID
  const generateSessionId = () => {
    const newId = currentSessionId;
    setCurrentSessionId(prev => prev + 1);
    return newId;
  };
  
  // Add performance metrics
  const addPerformanceMetric = (metric) => {
    const sessionId = generateSessionId();
    const totalTime = 
      (metric.keyGenTime || 0) + 
      (metric.encryptionTime || 0) + 
      (metric.decryptionTime || 0) + 
      (metric.idsDetectionTime || 0) + 
      (metric.idsPreventionTime || 0);
      
    const newMetric = {
      sessionId,
      ...metric,
      totalTime,
      timestamp: new Date().toISOString(),
      sender: currentSender,
      receiver: receiverEmail
    };
    
    const updatedMetrics = [...performanceMetrics, newMetric].slice(-20); // Keep last 20 entries
    setPerformanceMetrics(updatedMetrics);
    
    // Save to localStorage
    try {
      localStorage.setItem('performanceMetrics', JSON.stringify(updatedMetrics));
    } catch (e) {
      console.error('Error saving metrics to localStorage:', e);
    }
    
    return newMetric;
  };

  // Load performance metrics from localStorage on component mount
  useEffect(() => {
    const savedMetrics = localStorage.getItem('performanceMetrics');
    if (savedMetrics) {
      try {
        const parsedMetrics = JSON.parse(savedMetrics);
        // Ensure we have valid metrics data
        if (Array.isArray(parsedMetrics)) {
          setPerformanceMetrics(parsedMetrics);
          // Update currentSessionId based on the highest session ID in saved metrics
          if (parsedMetrics.length > 0) {
            const maxId = Math.max(...parsedMetrics.map(m => m.sessionId));
            setCurrentSessionId(maxId + 1);
          }
        }
      } catch (e) {
        console.error('Error parsing saved metrics:', e);
        localStorage.removeItem('performanceMetrics');
      }
    }
  }, []);

  const handleSendMessage = async (msg, sender, senderIP, receiverIP, uploadedFile = null) => {
    setMessage(msg);
    setCurrentSender(sender);
    
    // Store the uploaded file if provided
    const sessionId = generateSessionId();
    if (uploadedFile) {
      setUploadedFiles(prev => ({
        ...prev,
        [sessionId]: uploadedFile
      }));
    }

    // Start timing the encryption process
    const encryptionStart = performance.now();
    
    // Generate proper AES-256-GCM encrypted ciphertext
    const encoder = new TextEncoder();
    const data = encoder.encode(msg);
    
    // Generate a random 256-bit key (32 bytes)
    const key = crypto.getRandomValues(new Uint8Array(32));
    
    // Generate a random 96-bit IV (12 bytes) for GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt using AES-256-GCM
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128 // 128-bit authentication tag
      },
      await crypto.subtle.importKey(
        'raw',
        key,
        'AES-GCM',
        false,
        ['encrypt']
      ),
      data
    );
    
    // Combine IV + ciphertext + auth tag for proper AES format
    const encryptedArray = new Uint8Array(encryptedData);
    const result = new Uint8Array(iv.length + encryptedArray.length);
    result.set(iv);
    result.set(encryptedArray, iv.length);
    
    // Convert to base64 for display
    const ciphertext = btoa(String.fromCharCode(...result));
    
    // Simulate encryption time (random between 50-200ms)
    const encryptionTime = Math.floor(Math.random() * 150) + 50;
    await new Promise(resolve => setTimeout(resolve, encryptionTime));
    
    // Store both original message and encrypted version
    setEncryptedPackage({
      sender, 
      message: `ENCRYPTED(${msg})`,
      originalMessage: msg, // Store the original message for decryption
      encrypted: true, 
      ciphertext: ciphertext, // Use proper AES-256-GCM ciphertext
      sessionId, // Include session ID for file retrieval
      encryptionKey: Array.from(key), // Store key for decryption (in real app, this would be exchanged)
      metrics: {
        encryptionTime: performance.now() - encryptionStart
      }
    });
    
    // Add performance metrics
    addPerformanceMetric({
      keyGenTime: Math.floor(Math.random() * 100) + 50, // Simulated key gen time
      encryptionTime: Math.floor(encryptionTime),
      idsDetectionTime: 0, // Will be updated after IDS evaluation
      idsPreventionTime: 0 // Will be updated after TTP approval
    });
    
    setFlowStep(1);
    setIdsResult(null);
    setDecryptedMessage(null);
  };

  const handleIDSEvaluation = (result) => {
    setIdsResult(result);
    
    // Update performance metrics with IDS detection time
    if (performanceMetrics.length > 0) {
      const idsDetectionTime = Math.floor(Math.random() * 50) + 20; // Simulated IDS time
      
      setPerformanceMetrics(prev => {
        const updated = [...prev];
        const last = { ...updated[updated.length - 1] };
        last.idsDetectionTime = idsDetectionTime;
        updated[updated.length - 1] = last;
        return updated;
      });
    }
    
    // Only move to step 2 if not suspicious or already approved
    if (!result.isSuspicious || ttpApprovalStatus === 'approved') {
      setFlowStep(2);
    } else {
      // If suspicious, stay on step 1 to show TTP approval UI
      setTTPApprovalStatus(null);
    }
  };

  const handleReceive = async () => {
    // Start timing the decryption process
    const decryptionStart = performance.now();
    
    // Simulate decryption time (random between 30-100ms)
    const decryptionTime = Math.floor(Math.random() * 70) + 30;
    await new Promise(resolve => setTimeout(resolve, decryptionTime));
    
    // Show the decrypted message
    setDecryptedMessage(encryptedPackage.originalMessage || encryptedPackage.message);
    
    // Update performance metrics with decryption time
    if (performanceMetrics.length > 0) {
      setPerformanceMetrics(prev => {
        const updated = [...prev];
        const last = { ...updated[updated.length - 1] };
        last.decryptionTime = performance.now() - decryptionStart;
        updated[updated.length - 1] = last;
        return updated;
      });
    }
    
    setFlowStep(3);
  };

  // Handle TTP approval
  const handleTTPApproval = (comment) => {
    setTTPApprovalStatus('approved');
    setTTPComment(comment);
    
    // Update performance metrics with TTP approval time
    if (performanceMetrics.length > 0) {
      const ttpApprovalTime = Math.floor(Math.random() * 30) + 10; // Simulated TTP time
      
      setPerformanceMetrics(prev => {
        const updated = [...prev];
        const last = { ...updated[updated.length - 1] };
        last.idsPreventionTime = ttpApprovalTime;
        updated[updated.length - 1] = last;
        return updated;
      });
    }
    
    // Move to decryption step after approval
    setFlowStep(2);
  };

  const handleTTPRejection = (comment) => {
    setTTPApprovalStatus('rejected');
    setTTPComment(comment);
    // Stay on current step but show rejection
  };

  // Reset TTP state when starting new message
  useEffect(() => {
    if (flowStep === 0) {
      setTTPApprovalStatus(null);
      setTTPComment('');
    }
  }, [flowStep]);

  const handleReset = () => {
    setMessage('');
    setEncryptedPackage(null);
    setIdsResult(null);
    setDecryptedMessage(null);
    setFlowStep(0);
    setTTPApprovalStatus(null);
    setTTPComment('');
    // Don't reset performance metrics here
  };

  const handleAddKnownSender = (sender) => {
    if (!knownSenders.includes(sender)) {
      setKnownSenders([...knownSenders, sender]);
    }
  };

  const handleRemoveKnownSender = (sender) => {
    setKnownSenders(knownSenders.filter(s => s !== sender));
  };

  // Show cover page if not yet opened
  if (showCoverPage) {
    return <CoverPage onOpen={() => setShowCoverPage(false)} />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white py-8 shadow-lg">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold mb-2">🔐 Hybrid Encryption System</h1>
              <p className="text-blue-100">Secure Sender-to-Receiver Communication with IDS Protection</p>
            </div>
            <button
              onClick={() => setShowCoverPage(true)}
              className="bg-white bg-opacity-20 hover:bg-opacity-30 text-white px-4 py-2 rounded-lg transition-all"
            >
              ← Back to Cover
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Tab Navigation */}
        <div className="mb-8">
          <div className="flex border-b border-slate-700">
            <button
              onClick={() => setActiveTab('sender')}
              className={`px-6 py-3 font-semibold transition-colors ${
                activeTab === 'sender'
                  ? 'text-blue-400 border-b-2 border-blue-400 bg-blue-900 bg-opacity-20'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              📤 Sender
            </button>
            <button
              onClick={() => setActiveTab('ids')}
              className={`px-6 py-3 font-semibold transition-colors ${
                activeTab === 'ids'
                  ? 'text-yellow-400 border-b-2 border-yellow-400 bg-yellow-900 bg-opacity-20'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              🛡️ IDS Evaluation
            </button>
            <button
              onClick={() => setActiveTab('receiver')}
              className={`px-6 py-3 font-semibold transition-colors ${
                activeTab === 'receiver'
                  ? 'text-green-400 border-b-2 border-green-400 bg-green-900 bg-opacity-20'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              📥 Receiver
            </button>
          </div>
        </div>

        {/* Tab Content */}
        <div className="space-y-8">
          {/* Sender Tab */}
          {activeTab === 'sender' && (
            <div className="animate-fade-in">
              <SenderPanel
                onSendMessage={handleSendMessage}
                currentSender={currentSender}
                onChangeSender={setCurrentSender}
                flowStep={flowStep}
                receiverEmail={receiverEmail}
                onReceiverEmailChange={setReceiverEmail}
                onReset={handleReset}
                senderIP={expectedSenderIP}
                receiverIP={expectedReceiverIP}
                onSenderIPChange={setExpectedSenderIP}
                onReceiverIPChange={setExpectedReceiverIP}
              />
            </div>
          )}

          {/* IDS Tab */}
          {activeTab === 'ids' && (
            <div className="animate-fade-in">
              <IDSPanel
                encryptedPackage={encryptedPackage}
                idsResult={idsResult}
                onEvaluate={handleIDSEvaluation}
                knownSenders={knownSenders}
                onAddKnownSender={handleAddKnownSender}
                onRemoveKnownSender={handleRemoveKnownSender}
                flowStep={flowStep}
                onTTPApproval={handleTTPApproval}
                onTTPRejection={handleTTPRejection}
                ttpApprovalStatus={ttpApprovalStatus}
                expectedSenderIP={expectedSenderIP}
                expectedReceiverIP={expectedReceiverIP}
              />
            </div>
          )}

          {/* Receiver Tab */}
          {activeTab === 'receiver' && (
            <div className="animate-fade-in">
              <ReceiverPanel
                encryptedPackage={encryptedPackage}
                idsResult={idsResult}
                decryptedMessage={decryptedMessage}
                onReceive={handleReceive}
                flowStep={flowStep}
                receiverEmail={receiverEmail}
                onReset={handleReset}
                onSwitchToSender={() => setActiveTab('sender')}
                expectedSenderIP={expectedSenderIP}
                receiverIP={receiverIP}
                onExpectedSenderIPChange={setExpectedSenderIP}
                onReceiverIPChange={setReceiverIP}
                uploadedFiles={uploadedFiles}
              />
            </div>
          )}
        </div>

        {/* Model Metrics Section */}
        <div className="mt-8">
          <ModelMetrics />
        </div>

        {/* Results Section */}
        {decryptedMessage && (
          <div className="mt-8 bg-green-900 border-2 border-green-500 rounded-lg p-6 text-white">
            <div className="flex items-center mb-4">
              <span className="text-3xl mr-3">✅</span>
              <h3 className="text-2xl font-bold">Message Successfully Received</h3>
            </div>
            <div className="bg-green-950 rounded p-4 font-mono text-sm">
              <p className="text-green-300">{decryptedMessage}</p>
            </div>
            <div className="mt-4 text-center">
              <button
                onClick={handleReset}
                className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-3 px-6 rounded-lg transition-colors"
              >
                🔄 New Message
              </button>
            </div>
          </div>
        )}

        {/* Reset Button */}
        {flowStep > 0 && (
          <div className="mt-8 text-center">
            <button
              onClick={handleReceive}
              className={`font-bold py-3 px-6 rounded-lg transition-colors ${
                !idsResult || (idsResult?.isSuspicious && ttpApprovalStatus !== 'approved')
                  ? 'bg-gray-400 cursor-not-allowed text-gray-200'
                  : 'bg-blue-500 hover:bg-blue-600 text-white'
              }`}
              disabled={!idsResult || (idsResult?.isSuspicious && ttpApprovalStatus !== 'approved')}
            >
              {idsResult?.isSuspicious 
                ? ttpApprovalStatus === 'approved' 
                  ? 'Decrypt (Approved)' 
                  : ttpApprovalStatus === 'rejected'
                    ? 'Decryption Rejected'
                    : 'Approve in IDS Panel'
                : 'Decrypt Message'}
            </button>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="bg-slate-900 border-t border-slate-700 text-slate-400 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <p>Hybrid Encryption System • AES-GCM + ECC • Rule-Based IDS • TTP Audit</p>
        </div>
      </div>
    </div>
  );
}
