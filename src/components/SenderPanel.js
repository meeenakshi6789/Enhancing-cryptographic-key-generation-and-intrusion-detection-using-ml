import React, { useState, useEffect, useCallback } from 'react';
import { FiSend, FiUpload, FiFileText, FiKey, FiEye, FiEyeOff, FiImage } from 'react-icons/fi';
import CSVUploader from './CSVUploader';

// Mock function to generate key pair (in a real app, use a proper crypto library)
const generateKeyPair = () => {
  // This is a mock implementation - in a real app, use Web Crypto API or similar
  const publicKey = 'e0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2';
  const privateKey = 'x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9';
  
  return { publicKey, privateKey };
};

export default function SenderPanel({ 
  onSendMessage, 
  currentSender, 
  onChangeSender, 
  flowStep, 
  receiverEmail, 
  onReceiverEmailChange,
  onReset
}) {
  const [message, setMessage] = useState('');
  // Removed unused state
  const [csvData, setCSVData] = useState(null);
  const [csvFile, setCSVFile] = useState(null); // Track original CSV file
  const [publicKey, setPublicKey] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [showKeySection, setShowKeySection] = useState(false);
  const [useCSV, setUseCSV] = useState(false);
  const [imageFile, setImageFile] = useState(null);
  const [useImage, setUseImage] = useState(false);
  const [senderEmail, setSenderEmail] = useState('');
  const [senderName, setSenderName] = useState('');
  const [senderIP, setSenderIP] = useState('');
  const [receiverIP, setReceiverIP] = useState('');

  // Update currentSender when email or name changes
  const handleChange = useCallback(() => {
    if (senderEmail && senderName) {
      onChangeSender(senderEmail);
    }
  }, [senderEmail, senderName, onChangeSender]);

  useEffect(() => {
    handleChange();
  }, [handleChange]);

  const handleGenerateKeys = () => {
    if (message.trim() || csvData) {
      const { publicKey, privateKey } = generateKeyPair();
      setPublicKey(publicKey);
      setPrivateKey(privateKey);
      setShowKeySection(true);
    }
  };

  const handleCSVUpload = (csvData, originalFile) => {
    setCSVData(csvData);
    setCSVFile(originalFile); // Store original CSV file
    // Auto-populate message with a summary
    setMessage(`CSV with ${csvData.data.length} rows ready to send`);
  };

  const handleSend = (e) => {
    e.preventDefault();
    if ((message.trim() || csvData || imageFile) && senderEmail && publicKey && senderIP && receiverIP) {
      let contentToSend = message;
      let fileToSend = null;
      
      if (csvData) {
        contentToSend = JSON.stringify(csvData);
        fileToSend = csvFile; // Pass original CSV file
      } else if (imageFile) {
        contentToSend = `Image: ${imageFile.name} (${(imageFile.size / 1024).toFixed(1)} KB)`;
        fileToSend = imageFile; // Pass original image file
      }
      const messageWithKey = `[FROM:${senderName} <${senderEmail}>][PUBKEY:${publicKey}][SENDER_IP:${senderIP}][RECEIVER_IP:${receiverIP}] ${contentToSend}`;
      // Pass the appropriate file to onSendMessage for storage
      onSendMessage(messageWithKey, senderEmail, senderIP, receiverIP, fileToSend);
    } else if ((message.trim() || csvData || imageFile) && !publicKey) {
      alert('Please generate keys first');
    } else if (!senderEmail) {
      alert('Please enter your email');
    } else if (!senderIP) {
      alert('Please enter your IP address');
    } else if (!receiverIP) {
      alert('Please enter receiver IP address');
    }
  };

  const handleImageUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      // Check file size (1MB = 1024 * 1024 bytes)
      const maxSize = 1024 * 1024; // 1MB
      if (file.size > maxSize) {
        alert(`⚠️ LARGE IMAGE DETECTED!\n\nImage file size: ${(file.size / (1024 * 1024)).toFixed(2)} MB\n\nThis exceeds the 1MB limit and will be flagged by IDS as a potential security threat during evaluation.`);
        // Don't return - still allow the image to go through the flow
      }

      // Convert image to base64 for preservation
      const reader = new FileReader();
      reader.onload = (event) => {
        const base64Data = event.target.result;
        setImageFile(file);
        setMessage(`Image: ${file.name} (${(file.size / 1024).toFixed(1)} KB)\n[IMAGE_DATA:${base64Data}]`);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleNewMessage = () => {
    // Reset local state
    setMessage('');
    setCSVData(null);
    setPublicKey('');
    setPrivateKey('');
    setShowPrivateKey(false);
    setShowKeySection(false);
    // Call parent reset
    onReset();
  };

  const togglePrivateKeyVisibility = () => {
    setShowPrivateKey(!showPrivateKey);
  };

  // Removed handleSenderChange as we're using direct input fields now

  return (
    <div className="bg-slate-800 rounded-lg border-2 border-blue-500 shadow-xl overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-blue-700 px-6 py-4">
        <h2 className="text-2xl font-bold text-white flex items-center">
          <FiSend className="mr-2" /> Sender
        </h2>
      </div>

      {/* Key Generation Button - Only show if message exists but keys not generated */}
      {(message.trim() || csvData) && !showKeySection && (
        <div className="p-4 text-center">
          <button
            type="submit"
            className={`w-full text-white font-bold py-3 px-4 rounded-lg transition-colors flex items-center justify-center ${
              !publicKey || (!message.trim() && !csvData)
                ? 'bg-gray-500 cursor-not-allowed'
                : 'bg-green-600 hover:bg-green-700'
            }`}
            disabled={!publicKey || (!message.trim() && !csvData)}
          >
            <FiSend className="mr-2" />
            {!publicKey ? 'Generate Keys First' : csvData ? 'Send CSV Data' : 'Send Message'}
          </button>
        </div>
      )}

      {/* Key Information - Show after generation */}
      {showKeySection && (
        <div className="p-4 border-b border-slate-700">
          <h3 className="text-lg font-semibold text-blue-300 mb-3">🔑 Encryption Keys</h3>
          <div className="mb-3">
            <div className="flex items-center text-sm text-blue-300 mb-1">
              <FiKey className="mr-1" /> Public Key:
            </div>
            <div className="bg-slate-900 p-2 rounded text-xs font-mono break-all">
              {publicKey}
            </div>
          </div>
          
          <div>
            <div className="flex items-center justify-between text-sm text-blue-300 mb-1">
              <span className="flex items-center">
                <FiKey className="mr-1" /> Private Key:
              </span>
              <button 
                onClick={togglePrivateKeyVisibility}
                className="text-xs text-blue-400 hover:text-blue-200 flex items-center"
                type="button"
              >
                {showPrivateKey ? (
                  <>
                    <FiEyeOff className="mr-1" /> Hide
                  </>
                ) : (
                  <>
                    <FiEye className="mr-1" /> Show
                  </>
                )}
              </button>
            </div>
            <div className="bg-slate-900 p-2 rounded text-xs font-mono break-all">
              {showPrivateKey ? (
                privateKey
              ) : (
                <span className="text-slate-500">••••••••••••••••••••••••••••••••</span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              {showPrivateKey 
                ? '⚠️ Keep your private key secure! Never share it with anyone.'
                : 'Private key is hidden for security'}
            </p>
            <p className="text-xs text-green-400 mt-2">
              ✓ Keys generated successfully. You can now send your message securely.
            </p>
          </div>
        </div>
      )}

      {/* Generate Keys Button - Shows when message exists but keys not generated */}
      {(message.trim() || csvData) && !showKeySection && (
        <div className="pt-4">
          <button
            onClick={handleGenerateKeys}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition-colors flex items-center justify-center"
          >
            <FiKey className="mr-2" /> Generate Encryption Keys
          </button>
        </div>
      )}

      {/* Content */}
      <div className="p-6 space-y-6">
        {/* Sender Email and Name */}
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-semibold text-blue-300 mb-1">
                Your Email Address
              </label>
              <input
                type="email"
                value={senderEmail}
                onChange={(e) => setSenderEmail(e.target.value)}
                placeholder="Enter your email"
                className="w-full p-3 bg-slate-700 text-white rounded-lg border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-semibold text-blue-300 mb-1">
                Your Name
              </label>
              <input
                type="text"
                value={senderName}
                onChange={(e) => setSenderName(e.target.value)}
                placeholder="Enter your name"
                className="w-full p-3 bg-slate-700 text-white rounded-lg border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-semibold text-blue-300 mb-1">
                Your IP Address
              </label>
              <input
                type="text"
                value={senderIP}
                onChange={(e) => setSenderIP(e.target.value)}
                placeholder="Enter your IP (e.g., 192.168.1.100)"
                className="w-full p-3 bg-slate-700 text-white rounded-lg border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-semibold text-blue-300 mb-1">
                Receiver's IP Address
              </label>
              <input
                type="text"
                value={receiverIP}
                onChange={(e) => setReceiverIP(e.target.value)}
                placeholder="Enter receiver IP (e.g., 192.168.1.200)"
                className="w-full p-3 bg-slate-700 text-white rounded-lg border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-semibold text-blue-300 mb-1">
              Receiver's Email Address
            </label>
            <input
              type="email"
              value={receiverEmail}
              onChange={(e) => onReceiverEmailChange(e.target.value)}
              placeholder="Enter receiver's email"
              className="w-full p-3 bg-slate-700 text-white rounded-lg border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
          </div>
        </div>

        {/* Toggle between Message and CSV */}
        <div className="flex justify-center mb-4">
          <div className="inline-flex rounded-lg border border-slate-600 overflow-hidden">
            <button
              type="button"
              onClick={() => {
                setUseCSV(false);
                setUseImage(false);
              }}
              className={`px-4 py-2 text-sm font-medium ${
                !useCSV && !useImage
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              <FiFileText className="inline mr-2" />
              Enter Message
            </button>
            <button
              type="button"
              onClick={() => {
                setUseCSV(true);
                setUseImage(false);
              }}
              className={`px-4 py-2 text-sm font-medium ${
                useCSV
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              <FiUpload className="inline mr-2" />
              Upload CSV
            </button>
            <button
              type="button"
              onClick={() => {
                setUseCSV(false);
                setUseImage(true);
              }}
              className={`px-4 py-2 text-sm font-medium ${
                useImage
                  ? 'bg-blue-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              <FiImage className="inline mr-2" />
              Upload Image
            </button>
          </div>
        </div>

        {/* Message Input or CSV Upload or Image Upload */}
        <div>
          {useCSV ? (
            <div>
              <label className="block text-sm font-semibold text-blue-300 mb-3">
                Upload CSV File
              </label>
              <CSVUploader 
                onFileUpload={handleCSVUpload} 
                onExampleSelect={(num, type) => {
                  const exampleFile = `example_${type}_${num}.csv`;
                  setMessage(`Using example: ${exampleFile}`);
                }}
              />
            </div>
          ) : useImage ? (
            <div>
              <label className="block text-sm font-semibold text-blue-300 mb-3">
                Upload Image File (Max: 1MB)
              </label>
              <div className="border-2 border-dashed border-slate-600 rounded-lg p-6 text-center hover:border-blue-500 transition-colors">
                <FiImage className="mx-auto h-12 w-12 text-slate-400 mb-4" />
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleImageUpload}
                  className="hidden"
                  id="image-upload"
                  disabled={flowStep > 0}
                />
                <label
                  htmlFor="image-upload"
                  className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors inline-block"
                >
                  Choose Image File
                </label>
                <p className="text-xs text-slate-400 mt-2">
                  {imageFile ? `Selected: ${imageFile.name} (${(imageFile.size / 1024).toFixed(1)} KB)` : 'JPG, PNG, GIF up to 1MB'}
                </p>
                <p className="text-xs text-red-400 mt-1">
                  ⚠️ Files over 1MB will be flagged as security threats
                </p>
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-sm font-semibold text-blue-300 mb-3">
                Message to Send
              </label>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Enter your secret message here..."
                className="w-full px-4 py-3 rounded-lg bg-slate-700 text-white placeholder-slate-500 border-2 border-slate-600 focus:border-blue-500 focus:outline-none resize-none h-32"
                disabled={flowStep > 0}
              />
              <p className="text-xs text-slate-400 mt-2">
                {message.length} characters
              </p>
            </div>
          )}
        </div>

        {/* Send Button */}
        <button
          onClick={handleSend}
          disabled={(!message.trim() && !csvData && !imageFile) || flowStep > 0 || (!imageFile && (!senderIP || !receiverIP))}
          className={`w-full text-white font-bold py-3 px-4 rounded-lg transition-colors flex items-center justify-center ${
            (!message.trim() && !csvData && !imageFile) || flowStep > 0 || (!imageFile && (!senderIP || !receiverIP))
              ? 'bg-gray-500 cursor-not-allowed'
              : 'bg-green-600 hover:bg-green-700'
          }`}
        >
          <FiSend className="mr-2" />
          {csvData ? 'Send CSV Data' : imageFile ? 'Send Image' : 'Send Message'}
        </button>

        {/* Status and New Message Button */}
        {flowStep > 0 && (
          <div className="space-y-3">
            <div className="bg-blue-900 border-l-4 border-blue-400 rounded p-3">
              <p className="text-blue-200 text-sm">
                ✓ Message encrypted and sent for IDS evaluation
              </p>
            </div>
            <button
              onClick={handleNewMessage}
              className="w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-4 rounded-lg transition-colors flex items-center justify-center"
            >
              🔄 New Message
            </button>
          </div>
        )}

        {/* Info Box */}
        <div className="bg-slate-700 rounded-lg p-4 text-xs text-slate-300 space-y-2">
          <p className="font-semibold text-blue-300">🔐 Encryption Process:</p>
          <ul className="list-disc list-inside space-y-1">
            <li>Generate AES session key</li>
            <li>Encrypt with AES-GCM</li>
            <li>Compute HMAC for integrity</li>
            <li>Wrap key with ECC</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
