import React from 'react';

export default function TransmissionFlow({ flowStep }) {
  const steps = [
    { id: 1, label: 'Sender Encrypts', icon: '📤', color: 'blue' },
    { id: 2, label: 'IDS Evaluates', icon: '🛡️', color: 'yellow' },
    { id: 3, label: 'Receiver Decrypts', icon: '📥', color: 'green' },
  ];

  return (
    <div className="bg-gradient-to-r from-slate-800 to-slate-900 rounded-lg border-2 border-purple-500 p-6 shadow-xl">
      <h3 className="text-lg font-bold text-purple-300 mb-6">📊 Message Flow</h3>

      <div className="flex items-center justify-between">
        {steps.map((step, index) => (
          <React.Fragment key={step.id}>
            {/* Step */}
            <div className="flex flex-col items-center flex-1">
              <div
                className={`w-16 h-16 rounded-full flex items-center justify-center text-2xl font-bold transition transform ${
                  flowStep >= step.id
                    ? `bg-gradient-to-r from-${step.color}-500 to-${step.color}-600 text-white shadow-lg scale-110`
                    : 'bg-slate-700 text-slate-400'
                }`}
              >
                {step.icon}
              </div>
              <p
                className={`mt-3 text-sm font-semibold text-center ${
                  flowStep >= step.id ? `text-${step.color}-300` : 'text-slate-400'
                }`}
              >
                {step.label}
              </p>
            </div>

            {/* Arrow */}
            {index < steps.length - 1 && (
              <div className="flex-1 flex justify-center px-4">
                <div
                  className={`h-1 w-full rounded transition ${
                    flowStep > step.id
                      ? 'bg-gradient-to-r from-purple-500 to-purple-600'
                      : 'bg-slate-600'
                  }`}
                />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Status Messages */}
      <div className="mt-6 grid grid-cols-3 gap-4">
        <div className="text-center">
          <p className="text-xs text-slate-400 mb-1">Step 1</p>
          <p className="text-xs text-slate-300">
            {flowStep >= 1 ? '✓ Message encrypted' : 'Waiting...'}
          </p>
        </div>
        <div className="text-center">
          <p className="text-xs text-slate-400 mb-1">Step 2</p>
          <p className="text-xs text-slate-300">
            {flowStep >= 2 ? '✓ IDS evaluated' : 'Waiting...'}
          </p>
        </div>
        <div className="text-center">
          <p className="text-xs text-slate-400 mb-1">Step 3</p>
          <p className="text-xs text-slate-300">
            {flowStep >= 3 ? '✓ Message received' : 'Waiting...'}
          </p>
        </div>
      </div>
    </div>
  );
}
