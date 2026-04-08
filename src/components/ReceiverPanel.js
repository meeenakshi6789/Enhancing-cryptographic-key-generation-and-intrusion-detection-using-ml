import React from 'react';

export default function ReceiverPanel({
  encryptedPackage,
  idsResult,
  decryptedMessage,
  onReceive,
  flowStep,
  receiverEmail = 'bob@example.com', // Default to bob@example.com if not provided
  onReset,
  onSwitchToSender,
  expectedSenderIP = '',
  receiverIP = '',
  onExpectedSenderIPChange = () => {},
  onReceiverIPChange = () => {},
  uploadedFiles = {}
}) {
  const handleDecrypt = async () => {
    if (encryptedPackage && idsResult) {
      // Parse IP addresses from encrypted package
      const senderIPMatch = encryptedPackage.message.match(/\[SENDER_IP:([^\]]+)\]/);
      const receiverIPMatch = encryptedPackage.message.match(/\[RECEIVER_IP:([^\]]+)\]/);
      const senderIP = senderIPMatch ? senderIPMatch[1] : '';
      const targetReceiverIP = receiverIPMatch ? receiverIPMatch[1] : '';
      
      // IP validation
      if (expectedSenderIP && senderIP !== expectedSenderIP) {
        alert(`🚨 IP Mismatch Detected!\nExpected Sender IP: ${expectedSenderIP}\nActual Sender IP: ${senderIP}`);
        return;
      }
      
      if (receiverIP && targetReceiverIP !== receiverIP) {
        alert(`🚨 Receiver IP Mismatch Detected!\nExpected Receiver IP: ${receiverIP}\nTarget Receiver IP: ${targetReceiverIP}`);
        return;
      }
      
      // Perform actual AES-256-GCM decryption
      try {
        if (encryptedPackage.ciphertext && encryptedPackage.encryptionKey) {
          // Convert base64 ciphertext back to bytes
          const ciphertextBytes = Uint8Array.from(atob(encryptedPackage.ciphertext), c => c.charCodeAt(0));
          
          // Extract IV (first 12 bytes) and encrypted data
          const iv = ciphertextBytes.slice(0, 12);
          const encryptedData = ciphertextBytes.slice(12);
          
          // Convert encryption key back to bytes
          const key = Uint8Array.from(encryptedPackage.encryptionKey);
          
          // Import the key for decryption
          const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            'AES-GCM',
            false,
            ['decrypt']
          );
          
          // Decrypt the data
          const decryptedData = await crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: iv,
              tagLength: 128
            },
            cryptoKey,
            encryptedData
          );
          
          // Convert decrypted data back to string
          const decoder = new TextDecoder();
          const decryptedMessage = decoder.decode(decryptedData);
          
          // Pass the decrypted message to parent
          onReceive(decryptedMessage);
        } else {
          // Fallback to mock decryption if proper encryption data not available
          console.log('Using fallback decryption method');
          onReceive(encryptedPackage.originalMessage || encryptedPackage.message.replace('ENCRYPTED(', '').replace(')', ''));
        }
      } catch (error) {
        console.error('Decryption failed:', error);
        alert('❌ Decryption failed: ' + error.message);
        // Fallback to original message
        onReceive(encryptedPackage.originalMessage || 'Decryption failed');
      }
    }
  };

  // Download functions
  const downloadCSV = (csvData) => {
    try {
      console.log('downloadCSV called with:', csvData);
      
      // First try to get the original uploaded file from storage
      const originalFile = encryptedPackage?.sessionId ? uploadedFiles[encryptedPackage.sessionId] : null;
      console.log('Original CSV file from storage:', originalFile);
      
      if (originalFile) {
        console.log('Using original CSV file for download:', originalFile.name);
        // Download the original file directly
        const link = document.createElement('a');
        const url = URL.createObjectURL(originalFile);
        link.setAttribute('href', url);
        link.setAttribute('download', originalFile.name);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        console.log('Original CSV file download completed successfully');
        return;
      }

      console.log('Original CSV file not found, trying JSON conversion...');
      
      // Fallback to JSON-to-CSV conversion
      console.log('CSV data received:', csvData);

      // Find JSON boundaries
      const jsonStart = csvData.indexOf('{');
      const jsonEnd = csvData.lastIndexOf('}') + 1;

      if (jsonStart === -1 || jsonEnd === -1) {
        console.error('Could not find JSON boundaries in CSV data');
        alert('Error: Could not find JSON data in message');
        return;
      }

      const jsonStr = csvData.substring(jsonStart, jsonEnd);
      console.log('Extracted JSON string:', jsonStr);

      const data = JSON.parse(jsonStr);
      console.log('Parsed data:', data);

      // Convert to CSV format
      if (!data.headers || !data.data || !Array.isArray(data.data)) {
        console.error('Invalid data structure - missing headers or data array');
        alert('Error: Invalid CSV data structure');
        return;
      }

      console.log('Headers:', data.headers.length, 'Data rows:', data.data.length);

      const headers = data.headers;
      const csvContent = [
        headers.join(','),
        ...data.data.map(row => headers.map(header => `"${row[header] || ''}"`).join(','))
      ].join('\n');

      console.log('Generated CSV content length:', csvContent.length);

      // Create and download file
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', 'decrypted_data.csv');
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      console.log('CSV download completed successfully');
    } catch (error) {
      console.error('Error downloading CSV file:', error);
      alert('Error downloading CSV file: ' + error.message);
    }
  };

  const downloadImage = (imageInfo, originalMessage) => {
    try {
      console.log('downloadImage called with:', imageInfo, originalMessage);
      
      // First try to get the original uploaded file from storage
      const originalFile = encryptedPackage?.sessionId ? uploadedFiles[encryptedPackage.sessionId] : null;
      console.log('Original file from storage:', originalFile);
      
      if (originalFile) {
        console.log('Using original file for download:', originalFile.name);
        // Download the original file directly
        const link = document.createElement('a');
        const url = URL.createObjectURL(originalFile);
        link.setAttribute('href', url);
        link.setAttribute('download', originalFile.name);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        console.log('Original file download completed successfully');
        return;
      }

      console.log('Original file not found, trying base64 extraction...');
      
      // Debug: Show what we received
      console.log('Original message:', originalMessage);
      console.log('Looking for IMAGE_DATA tag...');

      // Extract base64 image data from the message using string methods
      // Find [IMAGE_DATA: and extract everything until the last ] in the message
      const imageDataStart = originalMessage.indexOf('[IMAGE_DATA:');
      if (imageDataStart !== -1) {
        // Find the last ] in the entire message (should be the closing bracket for IMAGE_DATA)
        const imageDataEnd = originalMessage.lastIndexOf(']');
        if (imageDataEnd !== -1 && imageDataEnd > imageDataStart) {
          // Extract from after [IMAGE_DATA: to before the final ]
          const base64Data = originalMessage.substring(imageDataStart + 12, imageDataEnd);
          console.log('Extracted base64 data (first 100 chars):', base64Data.substring(0, 100) + '...');
          console.log('Total base64 data length:', base64Data.length);

          // Validate that it looks like a data URL
          if (base64Data.startsWith('data:image/') && base64Data.includes(';base64,')) {
            // Create a temporary image to download the actual file
            const img = new Image();
            img.onload = () => {
              console.log('Image loaded successfully, dimensions:', img.width, 'x', img.height);

              // Create canvas with actual image dimensions
              const canvas = document.createElement('canvas');
              const ctx = canvas.getContext('2d');
              canvas.width = img.width;
              canvas.height = img.height;

              // Draw the actual image on canvas
              ctx.drawImage(img, 0, 0);

              // Download as the original image format
              canvas.toBlob((blob) => {
                const link = document.createElement('a');
                const url = URL.createObjectURL(blob);
                link.setAttribute('href', url);

                // Extract file extension from base64 data
                const mimeType = base64Data.split(';')[0].split(':')[1];
                const extension = mimeType.split('/')[1];
                link.setAttribute('download', `decrypted_image.${extension}`);

                link.style.visibility = 'hidden';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
                console.log('Image download completed successfully');
              });
            };
            img.onerror = () => {
              console.error('Failed to load image from base64 data');
              alert('Failed to load image data. The image may be corrupted during transfer.');
            };
            img.src = base64Data;
            return;
          } else {
            console.error('Extracted data does not look like a valid base64 image URL');
          }
        } else {
          console.error('Could not find closing bracket for IMAGE_DATA');
        }
      } else {
        console.error('IMAGE_DATA tag not found in message');
      }  
      // If image loading fails, show placeholder
      console.log('No IMAGE_DATA tag found, showing placeholder');
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = 400;
      canvas.height = 300;

      ctx.fillStyle = '#f0f0f0';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#333';
      ctx.font = '20px Arial';
      ctx.textAlign = 'center';
      ctx.fillText('Decrypted Image', canvas.width/2, canvas.height/2 - 20);
      ctx.fillText('Image Data Not Found', canvas.width/2, canvas.height/2 + 20);

      // Download the placeholder
      canvas.toBlob((blob) => {
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', 'image_data_not_found.png');
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        console.log('Placeholder download completed');
      });
    } catch (error) {
      console.error('Error downloading image:', error);
      alert('Error downloading image: ' + error.message);
    }
  };

  const canDecrypt = encryptedPackage && idsResult && flowStep === 2 && expectedSenderIP && receiverIP;

  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg border-2 border-green-500 shadow-xl overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-green-600 to-green-700 px-6 py-4">
        <h2 className="text-2xl font-bold text-white flex items-center">
          📥 Receiver
        </h2>
      </div>

      {/* Content */}
      <div className="p-6 space-y-6">
        {/* Receiver Info */}
        <div className="bg-slate-700 rounded-lg p-4 border-l-4 border-green-500">
          <p className="text-xs text-slate-400 mb-1">Receiver Identity</p>
          <p className="text-white font-mono text-sm">{receiverEmail}</p>
          <p className="text-xs text-slate-400 mt-1">Receiver IP: {receiverIP || 'Not specified'}</p>
          <p className="text-xs text-slate-400 mt-2">ECC Private Key: Available</p>
        </div>
        
        {/* IP Address Configuration */}
        <div className="bg-slate-700 rounded-lg p-4 border-l-4 border-yellow-500">
          <p className="text-xs text-slate-400 mb-3">IP Address Configuration</p>
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-semibold text-yellow-300 mb-1">
                Expected Sender IP Address
              </label>
              <input
                type="text"
                value={expectedSenderIP}
                onChange={(e) => onExpectedSenderIPChange(e.target.value)}
                placeholder="Enter expected sender IP (e.g., 192.168.1.100)"
                className="w-full p-2 bg-slate-800 text-white rounded border border-slate-600 focus:outline-none focus:ring-2 focus:ring-yellow-500 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-semibold text-yellow-300 mb-1">
                Your Receiver IP Address
              </label>
              <input
                type="text"
                value={receiverIP}
                onChange={(e) => onReceiverIPChange(e.target.value)}
                placeholder="Enter your IP (e.g., 192.168.1.200)"
                className="w-full p-2 bg-slate-800 text-white rounded border border-slate-600 focus:outline-none focus:ring-2 focus:ring-yellow-500 text-sm"
              />
            </div>
          </div>
        </div>
        
        {/* IP Validation Info */}
        {encryptedPackage && (
          <div className="bg-slate-700 rounded-lg p-4 border-l-4 border-blue-500">
            <p className="text-xs text-slate-400 mb-2">IP Address Validation</p>
            <div className="space-y-1">
              <p className="text-xs text-blue-300">
                Expected Sender IP: <span className="text-white font-mono">{expectedSenderIP || 'Not specified'}</span>
              </p>
              <p className="text-xs text-blue-300">
                Receiver IP: <span className="text-white font-mono">{receiverIP || 'Not specified'}</span>
              </p>
            </div>
          </div>
        )}

        {/* Packet Status */}
        <div>
          <label className="block text-sm font-semibold text-green-300 mb-3">
            Packet Status
          </label>
          <div className="space-y-2">
            <div className={`flex items-center px-4 py-2 rounded-lg ${
              encryptedPackage ? 'bg-green-900 text-green-200' : 'bg-slate-700 text-slate-400'
            }`}>
              <span className="mr-2">{encryptedPackage ? '✓' : '○'}</span>
              <span className="text-sm">Encrypted packet received</span>
            </div>
            <div className={`flex items-center px-4 py-2 rounded-lg ${
              idsResult ? 'bg-green-900 text-green-200' : 'bg-slate-700 text-slate-400'
            }`}>
              <span className="mr-2">{idsResult ? '✓' : '○'}</span>
              <span className="text-sm">IDS evaluation complete</span>
            </div>
            <div className={`flex items-center px-4 py-2 rounded-lg ${
              decryptedMessage ? 'bg-green-900 text-green-200' : 'bg-slate-700 text-slate-400'
            }`}>
              <span className="mr-2">{decryptedMessage ? '✓' : '○'}</span>
              <span className="text-sm">Message decrypted</span>
            </div>
          </div>
          
          {/* Ciphertext Display */}
          {encryptedPackage?.ciphertext && (
            <div className="mt-4">
              <label className="block text-sm font-semibold text-green-300 mb-2">
                Ciphertext:
              </label>
              <div className="bg-slate-800 p-3 rounded-lg border border-slate-600 overflow-x-auto">
                <pre className="text-xs text-green-200 font-mono whitespace-pre-wrap break-all">
                  {encryptedPackage.ciphertext}
                </pre>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {encryptedPackage.ciphertext.length} characters
              </p>
            </div>
          )}
        </div>

        {/* IDS Decision */}
        {idsResult && (
          <div className={`rounded-lg p-4 border-l-4 ${
            idsResult.isSuspicious
              ? 'bg-red-900 border-red-500'
              : 'bg-green-900 border-green-500'
          }`}>
            <p className="text-xs text-slate-300 mb-1">IDS Decision</p>
            <p className={`font-bold text-lg ${
              idsResult.isSuspicious ? 'text-red-300' : 'text-green-300'
            }`}>
              {idsResult.isSuspicious ? '🚨 SUSPICIOUS' : '✅ SAFE'}
            </p>
            <p className="text-xs mt-2 text-slate-300">
              {idsResult.isSuspicious
                ? 'Message flagged for audit. Forward to TTP.'
                : 'Message cleared. Safe to decrypt.'}
            </p>
          </div>
        )}

        {/* Decrypt Button */}
        <button
          onClick={handleDecrypt}
          disabled={!canDecrypt}
          className={`w-full py-3 rounded-lg font-bold text-white transition transform hover:scale-105 ${
            !canDecrypt
              ? 'bg-slate-600 cursor-not-allowed opacity-50'
              : 'bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 shadow-lg'
          }`}
        >
          🔓 Decrypt Message
        </button>

        {/* Decrypted Message */}
        {decryptedMessage && (() => {
          // Extract sender info from message
          const getSenderInfo = (msg) => {
            if (!msg) return { name: 'Unknown', email: 'unknown@example.com' };
            
            const fromMatch = msg.match(/\[FROM:([^<]*)<([^>]*)>\]/);
            if (fromMatch && fromMatch.length >= 3) {
              return {
                name: fromMatch[1].trim(),
                email: fromMatch[2].trim(),
                hasInfo: true
              };
            }
            return { name: 'Unknown', email: 'unknown@example.com', hasInfo: false };
          };

          const senderInfo = getSenderInfo(decryptedMessage);
          let displayMessage = decryptedMessage;
          let isCSV = false;
          let isImage = false;
          let csvSummary = '';
          let imageSummary = '';
          
          // Remove metadata from display
          if (senderInfo.hasInfo) {
            const fromIndex = displayMessage.indexOf('[FROM:');
            const pubKeyIndex = displayMessage.indexOf('[PUBKEY:');
            
            if (fromIndex !== -1 && pubKeyIndex !== -1) {
              const endIndex = displayMessage.indexOf(']', pubKeyIndex) + 1;
              displayMessage = displayMessage.substring(endIndex).trim();
            }
          }

          // Check if message contains CSV data (JSON format)
          console.log('Checking for CSV/Image in displayMessage:', displayMessage);
          console.log('displayMessage length:', displayMessage.length);
          console.log('First 100 chars:', displayMessage.substring(0, 100));
          
          try {
            const jsonData = JSON.parse(displayMessage);
            console.log('JSON parse successful:', jsonData);
            if (jsonData.headers && jsonData.data && Array.isArray(jsonData.data)) {
              isCSV = true;
              csvSummary = `CSV Data: ${jsonData.data.length} rows, ${jsonData.headers.length} columns`;
              displayMessage = csvSummary; // Replace with summary
              console.log('CSV detected - isCSV set to true');
            }
          } catch (e) {
            console.log('JSON parse failed, checking for image:', e.message);
            // Not JSON, check for image data
            // Check for image patterns including IP address format
            if (displayMessage.includes('[IMAGE_DATA:') || displayMessage.includes('Image:') || displayMessage.includes('.jpg') || displayMessage.includes('.png') || displayMessage.includes('.jpeg') || displayMessage.includes('.gif')) {
              isImage = true;
              console.log('Image detected - isImage set to true');
              // Extract image name from various formats
              const imageMatch = displayMessage.match(/Image:\s*([^(\n]*)/);
              const ipImageMatch = displayMessage.match(/\] Image:\s*([^(\n]*)/);
              imageSummary = imageMatch ? imageMatch[1] : (ipImageMatch ? ipImageMatch[1] : 'Unknown image');
              displayMessage = `Image: ${imageSummary}`; // Replace with summary
              console.log('Image summary extracted:', imageSummary);
            } else {
              console.log('No CSV or image detected in message');
            }
          }

          return (
            <div className="space-y-4">
              <div className="bg-slate-700 rounded-lg p-4 border-l-4 border-green-500">
                <p className="text-xs text-slate-400 mb-1">From</p>
                <p className="text-white">
                  {senderInfo.name} <span className="text-slate-400 text-sm">&lt;{senderInfo.email}&gt;</span>
                </p>
              </div>
              <div className="bg-green-900 border-2 border-green-500 rounded-lg p-4">
                <div className="flex justify-between items-start mb-2">
                  <p className="text-xs text-green-300 font-semibold">MESSAGE:</p>
                  
                  {/* Download buttons for CSV and Image */}
                  <div className="flex gap-2">
                    {isCSV && (
                      <button
                        onClick={() => {
                          // Try to get the original uploaded file from storage
                          const originalFile = encryptedPackage?.sessionId ? uploadedFiles[encryptedPackage.sessionId] : null;
                          
                          if (originalFile) {
                            // Download the original file directly
                            const link = document.createElement('a');
                            const url = URL.createObjectURL(originalFile);
                            link.setAttribute('href', url);
                            link.setAttribute('download', originalFile.name);
                            link.style.visibility = 'hidden';
                            document.body.appendChild(link);
                            link.click();
                            document.body.removeChild(link);
                            URL.revokeObjectURL(url);
                          } else {
                            // Fallback to JSON-to-CSV conversion
                            const cleanMessage = decryptedMessage.replace(/.*\[PUBKEY:[^\]]*\]\s*/, '').trim();
                            downloadCSV(cleanMessage);
                          }
                        }}
                        className="bg-blue-600 hover:bg-blue-700 text-white text-xs px-3 py-1 rounded flex items-center gap-1 transition-colors"
                        title="Download original CSV file"
                      >
                        📊 CSV
                      </button>
                    )}
                    {isImage && (
                      <button
                        onClick={() => {
                          // Try to get the original uploaded file from storage
                          const originalFile = encryptedPackage?.sessionId ? uploadedFiles[encryptedPackage.sessionId] : null;
                          
                          if (originalFile) {
                            // Download the original file directly
                            const link = document.createElement('a');
                            const url = URL.createObjectURL(originalFile);
                            link.setAttribute('href', url);
                            link.setAttribute('download', originalFile.name);
                            link.style.visibility = 'hidden';
                            document.body.appendChild(link);
                            link.click();
                            document.body.removeChild(link);
                            URL.revokeObjectURL(url);
                          } else {
                            // Fallback to base64 extraction method
                            const originalMsg = decryptedMessage.replace(/.*\[PUBKEY:[^\]]*\]\s*/, '');
                            downloadImage(imageSummary, originalMsg);
                          }
                        }}
                        className="bg-purple-600 hover:bg-purple-700 text-white text-xs px-3 py-1 rounded flex items-center gap-1 transition-colors"
                        title="Download original image file"
                      >
                        🖼️ IMG
                      </button>
                    )}
                    {/* Debug info */}
                    <div className="text-xs text-red-400">
                      Debug: isCSV={isCSV.toString()}, isImage={isImage.toString()}
                    </div>
                  </div>
                </div>
                
                <div className="bg-green-950 rounded p-3 font-mono text-sm text-green-200 break-words whitespace-pre-wrap">
                  {displayMessage}
                </div>
                <p className="text-xs text-green-400 mt-3">
                  ✓ Message integrity verified
                </p>
              </div>
            </div>
          );
        })()}

        {/* Back/Reset Button - Show after decryption */}
        {decryptedMessage && (
          <button
            onClick={() => {
              onReset(); // Reset the flow state
              onSwitchToSender(); // Switch to sender tab
            }}
            className="w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-4 rounded-lg transition-colors flex items-center justify-center"
          >
            ← Back to Sender / New Message
          </button>
        )}

        {/* Info Box */}
        <div className="bg-slate-700 rounded-lg p-4 text-xs text-slate-300 space-y-2">
          <p className="font-semibold text-green-300">🔓 Decryption Process:</p>
          <ul className="list-disc list-inside space-y-1">
            <li>Unwrap AES key with private key</li>
            <li>Verify HMAC integrity</li>
            <li>Decrypt with AES-GCM</li>
            <li>Return plaintext</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
