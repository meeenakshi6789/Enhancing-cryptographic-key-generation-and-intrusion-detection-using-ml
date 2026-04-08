import React, { useState } from 'react';

export default function IDSPanel({
  encryptedPackage,
  idsResult,
  onEvaluate,
  knownSenders,
  onAddKnownSender,
  onRemoveKnownSender,
  flowStep,
  onTTPApproval,  // New prop for TTP approval callback
  onTTPRejection,  // New prop for TTP rejection callback
  ttpApprovalStatus, // 'pending', 'approved', 'rejected', or null
  expectedSenderIP = '',
  expectedReceiverIP = ''
}) {
  const [newSender, setNewSender] = useState('');
  const [ttpComment, setTTPComment] = useState('');

  const checkForSQLInjection = (text) => {
    const sqlPatterns = [
      /\b(SELECT\s+\*|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|UNION\s+SELECT)/i,
      /\b(OR\s+1=1|--\s|#|\/\*[^*]*\*\/|(\%27)|(\')|(\-\-))/
    ];
    return sqlPatterns.some(pattern => pattern.test(text));
  };

  const checkForXSS = (text) => {
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /<[^>]*on\w+\s*=[^>]*>|&lt;[^&]*on\w+\s*=[^&]*&gt;/gi,
      /javascript:/i,
      /<iframe[^>]*>.*<\/iframe>/gi
    ];
    return xssPatterns.some(pattern => pattern.test(text));
  };

  const checkForCommandInjection = (text) => {
    const cmdPatterns = [
      /(?:;|\|\||&&)\s*(?:rm\s+-[rf]|wget|curl|bash\s+-i|sh\s+-i)/i,
      /\b(cat\s+\/etc\/passwd|\/bin\/bash|\/bin\/sh)\b/i,
      /\b(echo\s+[^|&;]+\|\s*sh|sh\s+<\s*\(.*\))\b/i
    ];
    return cmdPatterns.some(pattern => pattern.test(text));
  };

  const checkForPathTraversal = (text) => {
    const pathPatterns = [
      /\.\.\//g,
      /\.\\/g,
      /\/etc\/passwd/i,
      /\/etc\/shadow/i,
      /\/etc\/hosts/i
    ];
    return pathPatterns.some(pattern => pattern.test(text));
  };

  const checkForSuspiciousKeywords = (text) => {
    // List of suspicious keywords to detect
    const suspiciousKeywords = [
      'intrusion',
      'hack',
      'exploit',
      'vulnerability',
      'malware',
      'ransomware',
      'ddos',
      'bruteforce',
      'sqlmap',
      'metasploit',
      'payload',
      'reverse shell',
      'attack',
      'malicious',
      'bypass',
      'injection',
      'xss',
      'cross site scripting',
      'sqli',
      'command injection',
      'path traversal',
      'zero day',
      '0day',
      'privilege escalation',
      'rootkit',
      'backdoor',
      'keylogger',
      'phishing',
      'spoofing',
      'man in the middle',
      'mitm',
      'credential stuffing',
      'password spray',
      'brute force',
      'cve-',
      'exploit-db',
      'shellcode',
      'buffer overflow',
      'format string',
      'race condition',
      'deserialization',
      'prototype pollution',
      'server-side request forgery',
      'ssrf',
      'xml external entity',
      'xxe',
      'insecure deserialization',
      'security misconfiguration',
      'broken access control',
      'sensitive data exposure',
      'api security',
      'insecure api'
    ];
    
    const lowerText = text.toLowerCase();
    
    // Check for exact matches in the suspicious keywords list
    if (suspiciousKeywords.some(keyword => lowerText.includes(keyword))) {
      return true;
    }
    
    // Additional pattern-based checks
    const suspiciousPatterns = [
      // Command execution patterns
      /(?:;|\|\||&&)\s*(?:rm\s+-[rf]|wget|curl|bash\s+-[ic]|sh\s+-[ic]|cmd\.exe|powershell)/i,
      
      // Common attack tools and frameworks
      /(?:\b|\W)(?:sqlmap|metasploit|nmap|burp|wireshark|john|hashcat|hydra|nessus|openvas|nikto|wpscan)(?:\b|\W)/i,
      
      // Common attack patterns
      /(?:\b|\W)(?:reverse[\s-]?shell|bind[\s-]?shell|web[\s-]?shell|php[\s-]?shell)(?:\b|\W)/i,
      
      // Network scanning patterns
      /(?:\b|\W)(?:port[\s-]?scan|vulnerability[\s-]?scan|network[\s-]?scan)(?:\b|\W)/i,
      
      // Common security vulnerability patterns
      /(?:\b|\W)(?:cve[\s-]\d{4}[\s-]\d{4,}|0day|zero[\s-]?day)(?:\b|\W)/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(lowerText));
  };

  const checkForSuspiciousCSV = (message) => {
    if (!message.includes('CSV Data')) return false;
    
    try {
      // Extract the JSON array from the message
      const jsonStart = message.indexOf('[');
      const jsonEnd = message.lastIndexOf(']') + 1;
      if (jsonStart === -1 || jsonEnd === 0) return false;
      
      const jsonStr = message.substring(jsonStart, jsonEnd);
      const data = JSON.parse(jsonStr);
      
      // Check each field in each row
      for (const row of data) {
        for (const [key, value] of Object.entries(row)) {
          const strValue = String(value).toLowerCase();
          
          // Check for various attack patterns
          if (
            checkForSQLInjection(strValue) ||
            checkForXSS(strValue) ||
            checkForCommandInjection(strValue) ||
            checkForPathTraversal(strValue) ||
            strValue.includes('<script>') ||
            strValue.includes('${') ||
            strValue.includes('`') ||
            strValue.includes('|') && strValue.includes('&') ||
            strValue.includes('../') ||
            strValue.includes('..\\') ||
            strValue.includes('rm -') ||
            strValue.includes('wget ') ||
            strValue.includes('curl ')
          ) {
            return true;
          }
        }
      }
    } catch (e) {
      console.error('Error checking CSV data:', e);
    }
    
    return false;
  };

  const handleEvaluate = () => {
    if (!encryptedPackage) return;

    const triggers = [];
    const message = encryptedPackage.message;
    
    // Parse IP addresses from encrypted package
    const senderIPMatch = message.match(/\[SENDER_IP:([^\]]+)\]/);
    const receiverIPMatch = message.match(/\[RECEIVER_IP:([^\]]+)\]/);
    const senderIP = senderIPMatch ? senderIPMatch[1] : '';
    const targetReceiverIP = receiverIPMatch ? receiverIPMatch[1] : '';
    
    // IP address validation
    if (expectedSenderIP && senderIP && senderIP !== expectedSenderIP) {
      triggers.push('rule_sender_ip_mismatch');
    }
    
    if (expectedReceiverIP && targetReceiverIP && targetReceiverIP !== expectedReceiverIP) {
      triggers.push('rule_receiver_ip_mismatch');
    }
    
    // Check for large image files (>1MB)
    if (message.includes('Image:') && message.includes('KB)')) {
      const sizeMatch = message.match(/(\d+(?:\.\d+)?)\s*KB\)/);
      if (sizeMatch) {
        const sizeKB = parseFloat(sizeMatch[1]);
        const sizeBytes = sizeKB * 1024;
        const maxSizeBytes = 1024 * 1024; // 1MB
        if (sizeBytes > maxSizeBytes) {
          triggers.push('rule_large_image_file');
        }
      }
    }
    
    // Check for unknown sender (but don't mark as suspicious, just log it)
    if (!knownSenders.includes(encryptedPackage.sender)) {
      console.log('Message from unknown sender:', encryptedPackage.sender);
    }
    
    // Only flag extremely large payloads (10KB+)
    if (message.length > 10000) {
      triggers.push('rule_large_payload');
    }
    
    // Check for suspicious patterns in the message or CSV data
    const isCSV = message.includes('CSV Data');
    
    if (isCSV) {
      // For CSV data, be more lenient
      if (checkForSuspiciousCSV(message)) {
        triggers.push('rule_suspicious_pattern');
      }
    } else {
      // For regular messages, check for all attack patterns including keywords
      if (
        checkForSQLInjection(message) ||
        checkForXSS(message) ||
        checkForCommandInjection(message) ||
        checkForPathTraversal(message) ||
        checkForSuspiciousKeywords(message)
      ) {
        triggers.push('rule_suspicious_pattern');
      }
    }
    
    const isSuspicious = triggers.length > 0;

    const result = {
      isSuspicious,
      triggers,
      timestamp: new Date().toLocaleTimeString(),
      sender: encryptedPackage.sender,
      senderIP,
      targetReceiverIP
    };

    onEvaluate(result);
  };

  const handleAddSender = () => {
    if (newSender.trim() && !knownSenders.includes(newSender)) {
      onAddKnownSender(newSender);
      setNewSender('');
    }
  };

  const [verificationEmail, setVerificationEmail] = useState('');
  const [isEmailVerified, setIsEmailVerified] = useState(false);
  const [verificationError, setVerificationError] = useState('');

  // Handle TTP approval
  const handleTTPApprove = () => {
    if (verificationEmail.toLowerCase() === encryptedPackage.sender.toLowerCase()) {
      setIsEmailVerified(true);
      setVerificationError('');
      onTTPApproval && onTTPApproval(`Sender verified: ${verificationEmail}`);
    } else {
      setIsEmailVerified(false);
      setVerificationError('Email does not match the sender\'s email');
    }
  };

  // Handle TTP rejection
  const handleTTPReject = () => {
    onTTPRejection && onTTPRejection(`Rejected: Sender verification failed for ${verificationEmail}`);
  };

  // Handle email input change
  const handleEmailChange = (e) => {
    setVerificationEmail(e.target.value);
    // Reset verification status when email changes
    if (isEmailVerified) setIsEmailVerified(false);
    if (verificationError) setVerificationError('');
  };

  return (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg border-2 border-yellow-500 shadow-xl overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-yellow-600 to-yellow-700 px-6 py-4">
        <h2 className="text-2xl font-bold text-white flex items-center">
          🛡️ IDS Engine
        </h2>
      </div>

      {/* Content */}
      <div className="p-6 space-y-6">
        {/* Known Senders */}
        <div>
          <label className="block text-sm font-semibold text-yellow-300 mb-3">
            Known Senders (Whitelist)
          </label>
          <div className="space-y-2 max-h-32 overflow-y-auto">
            {knownSenders.length === 0 ? (
              <p className="text-slate-400 text-sm italic">No known senders</p>
            ) : (
              knownSenders.map((sender) => (
                <div
                  key={sender}
                  className="flex items-center justify-between bg-slate-700 px-3 py-2 rounded-lg"
                >
                  <span className="text-green-300 text-sm font-mono">{sender}</span>
                  <button
                    onClick={() => onRemoveKnownSender(sender)}
                    className="text-red-400 hover:text-red-300 text-xs font-bold"
                  >
                    ✕
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Add Sender */}
        <div>
          <label className="block text-sm font-semibold text-yellow-300 mb-2">
            Add Trusted Sender
          </label>
          <div className="flex gap-2">
            <input
              type="email"
              value={newSender}
              onChange={(e) => setNewSender(e.target.value)}
              placeholder="email@example.com"
              className="flex-1 px-3 py-2 rounded-lg bg-slate-700 text-white placeholder-slate-500 border-2 border-slate-600 focus:border-yellow-500 focus:outline-none text-sm"
              onKeyPress={(e) => e.key === 'Enter' && handleAddSender()}
            />
            <button
              onClick={handleAddSender}
              className="bg-green-600 hover:bg-green-700 text-white px-3 py-2 rounded-lg font-bold text-sm transition"
            >
              +
            </button>
          </div>
        </div>

        {/* Evaluate Button */}
        <button
          onClick={handleEvaluate}
          disabled={!encryptedPackage || flowStep < 1 || flowStep > 1}
          className={`w-full py-3 rounded-lg font-bold text-white transition transform hover:scale-105 ${
            !encryptedPackage || flowStep < 1 || flowStep > 1
              ? 'bg-slate-600 cursor-not-allowed opacity-50'
              : 'bg-gradient-to-r from-yellow-500 to-yellow-600 hover:from-yellow-600 hover:to-yellow-700 shadow-lg'
          }`}
        >
          🔍 Evaluate Message
        </button>

        {/* Results */}
        {idsResult && (
          <div
            className={`rounded-lg p-4 border-l-4 ${
              idsResult.isSuspicious
                ? 'bg-red-900 border-red-500 text-red-100'
                : 'bg-green-900 border-green-500 text-green-100'
            }`}
          >
            <div className="flex items-center mb-3">
              <span className="text-2xl mr-2">
                {idsResult.isSuspicious ? '🚨' : '✅'}
              </span>
              <span className="font-bold">
                {idsResult.isSuspicious ? 'SUSPICIOUS' : 'SAFE'}
              </span>
            </div>

            {idsResult.triggers.length > 0 && (
              <div className="space-y-1">
                <p className="text-xs font-semibold mb-2">Triggered Rules:</p>
                {idsResult.triggers.map((trigger) => (
                  <div
                    key={trigger}
                    className={`text-xs px-2 py-1 rounded ${
                      idsResult.isSuspicious
                        ? 'bg-red-800 text-red-200'
                        : 'bg-green-800 text-green-200'
                    }`}
                  >
                    • {trigger}
                  </div>
                ))}
              </div>
            )}

            <p className="text-xs mt-3 opacity-75">
              Time: {idsResult.timestamp}
            </p>

            {/* TTP Approval Section */}
            {idsResult.isSuspicious && ttpApprovalStatus === null && (
              <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <h4 className="font-medium text-blue-800 mb-2">🔒 Sender Verification Required</h4>
                <p className="text-sm text-blue-700 mb-3">
                  Please enter the expected sender's email to verify this request.
                </p>
                
                <div className="mb-3">
                  <label htmlFor="verification-email" className="block text-sm font-medium text-gray-700 mb-1">
                    Expected Sender's Email:
                  </label>
                  <input
                    type="email"
                    id="verification-email"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                    placeholder="e.g., alice@example.com"
                    value={verificationEmail}
                    onChange={handleEmailChange}
                    disabled={isEmailVerified}
                  />
                  {verificationError && (
                    <p className="mt-1 text-sm text-red-600">{verificationError}</p>
                  )}
                  {isEmailVerified && (
                    <p className="mt-1 text-sm text-green-600">✓ Sender verified successfully</p>
                  )}
                </div>
                
                <div className="flex space-x-3">
                  <button
                    onClick={handleTTPApprove}
                    disabled={isEmailVerified}
                    className={`flex-1 font-medium py-2 px-4 rounded-md ${
                      isEmailVerified
                        ? 'bg-gray-400 cursor-not-allowed'
                        : 'bg-green-600 hover:bg-green-700 text-white'
                    }`}
                  >
                    {isEmailVerified ? 'Verified' : 'Verify Sender'}
                  </button>
                  <button
                    onClick={handleTTPReject}
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-md"
                  >
                    Reject Request
                  </button>
                </div>
              </div>
            )}

            {/* TTP Approval Status */}
            {ttpApprovalStatus === 'approved' && (
              <div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-lg">
                <div className="flex items-center">
                  <svg className="h-5 w-5 text-green-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                  <p className="text-sm font-medium text-green-800">
                    TTP Approval Granted{ttpComment && ": " + ttpComment}
                  </p>
                </div>
              </div>
            )}

            {ttpApprovalStatus === 'rejected' && (
              <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-center">
                  <svg className="h-5 w-5 text-red-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                  <p className="text-sm font-medium text-red-800">
                    Decryption Rejected by TTP{ttpComment && ": " + ttpComment}
                  </p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
