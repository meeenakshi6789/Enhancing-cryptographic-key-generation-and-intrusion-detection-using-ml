import React from 'react';
import { FiArrowRight, FiShield, FiLock, FiAlertTriangle } from 'react-icons/fi';

export default function CoverPage({ onOpen }) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-blue-900 to-slate-950 flex items-center justify-center p-4 overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-20 left-10 w-72 h-72 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse"></div>
        <div className="absolute top-40 right-10 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse" style={{ animationDelay: '2s' }}></div>
        <div className="absolute bottom-20 left-1/2 w-72 h-72 bg-cyan-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse" style={{ animationDelay: '4s' }}></div>
      </div>

      {/* Floating animated elements */}
      <style>{`
        @keyframes float {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(-20px); }
        }
        @keyframes float-reverse {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(20px); }
        }
        @keyframes rotate-slow {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes pulse-glow {
          0%, 100% { box-shadow: 0 0 20px rgba(59, 130, 246, 0.5); }
          50% { box-shadow: 0 0 40px rgba(59, 130, 246, 0.8); }
        }
        .float-animation {
          animation: float 3s ease-in-out infinite;
        }
        .float-reverse-animation {
          animation: float-reverse 4s ease-in-out infinite;
        }
        .rotate-animation {
          animation: rotate-slow 20s linear infinite;
        }
        .pulse-glow-animation {
          animation: pulse-glow 2s ease-in-out infinite;
        }
      `}</style>

      {/* Floating Avatar 1 - Shield */}
      <div className="absolute top-32 left-20 float-animation">
        <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-full p-4 pulse-glow-animation">
          <FiShield className="w-12 h-12 text-white" />
        </div>
      </div>

      {/* Floating Avatar 2 - Lock */}
      <div className="absolute top-48 right-32 float-reverse-animation" style={{ animationDelay: '1s' }}>
        <div className="bg-gradient-to-br from-cyan-500 to-cyan-600 rounded-full p-4 pulse-glow-animation" style={{ animationDelay: '0.5s' }}>
          <FiLock className="w-12 h-12 text-white" />
        </div>
      </div>

      {/* Floating Avatar 3 - Alert */}
      <div className="absolute bottom-40 left-32 float-animation" style={{ animationDelay: '2s' }}>
        <div className="bg-gradient-to-br from-purple-500 to-purple-600 rounded-full p-4 pulse-glow-animation" style={{ animationDelay: '1s' }}>
          <FiAlertTriangle className="w-12 h-12 text-white" />
        </div>
      </div>

      {/* Rotating circle background */}
      <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 border-2 border-blue-500 border-opacity-20 rounded-full rotate-animation"></div>

      {/* Content */}
      <div className="relative z-10 max-w-3xl w-full">
        {/* Main Card */}
        <div className="bg-slate-900 border-2 border-blue-500 rounded-2xl shadow-2xl p-8 md:p-16 backdrop-blur-sm text-center transform hover:scale-105 transition-transform duration-300">
          {/* Animated icon above title */}
          <div className="flex justify-center mb-8">
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full blur opacity-75 animate-pulse"></div>
              <div className="relative bg-slate-900 rounded-full p-6 rotate-animation">
                <div className="w-12 h-12 bg-gradient-to-r from-blue-400 to-cyan-400 rounded-full flex items-center justify-center">
                  <FiShield className="w-8 h-8 text-white" />
                </div>
              </div>
            </div>
          </div>

          {/* Title */}
          <h1 className="text-4xl md:text-5xl font-bold bg-gradient-to-r from-blue-400 via-cyan-400 to-purple-400 bg-clip-text text-transparent mb-12 animate-pulse">
            Enhancing Cryptographic Key Generation and Intrusion Detection Using Machine Learning Techniques
          </h1>

          {/* Open Button with animation */}
          <button
            onClick={onOpen}
            className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-4 px-6 rounded-lg transition-all duration-300 flex items-center justify-center group shadow-lg hover:shadow-cyan-500/50 transform hover:scale-105 active:scale-95"
          >
            <span className="text-lg">Open System</span>
            <FiArrowRight className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform" />
          </button>
        </div>

        {/* Animated bottom text */}
        <div className="text-center mt-12 animate-bounce">
          <p className="text-cyan-400 text-sm font-semibold">↓ Click to Enter ↓</p>
        </div>
      </div>
    </div>
  );
}
