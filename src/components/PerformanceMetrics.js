import React, { useState, useEffect } from 'react';
import { FiActivity, FiClock, FiTrendingUp, FiRefreshCw, FiTrash2, FiKey, FiSend } from 'react-icons/fi';

export default function PerformanceMetrics({ metrics = [] }) {
  const [activeTab, setActiveTab] = useState('table');
  const [chartData, setChartData] = useState([]);
  const [showDetails, setShowDetails] = useState({});

  // Format time in milliseconds to a readable format
  const formatTime = (ms) => {
    if (!ms && ms !== 0) return 'N/A';
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  // Toggle details for a specific metric
  const toggleDetails = (id) => {
    setShowDetails(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  // Clear all metrics
  const clearMetrics = () => {
    if (window.confirm('Are you sure you want to clear all performance metrics? This cannot be undone.')) {
      localStorage.removeItem('performanceMetrics');
      window.location.reload();
    }
  };

  // Update chart data when metrics change
  useEffect(() => {
    if (metrics.length > 0) {
      const latestMetric = metrics[metrics.length - 1];
      setChartData([
        { name: 'Key Gen', value: latestMetric.keyGenTime || 0 },
        { name: 'Encryption', value: latestMetric.encryptionTime || 0 },
        { name: 'Decryption', value: latestMetric.decryptionTime || 0 },
        { name: 'IDS Detection', value: latestMetric.idsDetectionTime || 0 },
        { name: 'Total', value: latestMetric.totalTime || 0 }
      ]);
    }
  }, [metrics]);

  if (metrics.length === 0) {
    return (
      <div className="bg-slate-800 rounded-lg border-2 border-purple-500 p-4 mt-6">
        <div className="flex justify-between items-center mb-3">
          <h3 className="text-lg font-semibold text-purple-300 flex items-center">
            <FiActivity className="mr-2" /> Performance Metrics
          </h3>
        </div>
        <p className="text-sm text-slate-400">No performance data available yet. Send a message to see metrics.</p>
      </div>
    );
  }

  // Sort metrics by timestamp (newest first)
  const sortedMetrics = [...metrics].sort((a, b) => 
    new Date(b.timestamp) - new Date(a.timestamp)
  );

  return (
    <div className="bg-slate-800 rounded-lg border-2 border-purple-500 p-4 mt-6">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold text-purple-300 flex items-center">
          <FiActivity className="mr-2" /> Performance Metrics
        </h3>
        <div className="flex space-x-2">
          <button
            onClick={() => window.location.reload()}
            className="text-xs text-blue-400 hover:text-blue-300 flex items-center"
            title="Refresh metrics"
          >
            <FiRefreshCw className="mr-1" /> Refresh
          </button>
          <button
            onClick={clearMetrics}
            className="text-xs text-red-400 hover:text-red-300 flex items-center"
            title="Clear all metrics"
          >
            <FiTrash2 className="mr-1" /> Clear All
          </button>
        </div>
      </div>

      {/* Table Container */}
      <div className="overflow-x-auto max-h-96 overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="bg-slate-700 sticky top-0">
            <tr className="border-b border-slate-600">
              <th className="px-3 py-2 text-left text-purple-300 font-semibold">Session</th>
              <th className="px-3 py-2 text-left text-purple-300 font-semibold">From → To</th>
              <th className="px-3 py-2 text-center text-purple-300 font-semibold">Key Gen</th>
              <th className="px-3 py-2 text-center text-purple-300 font-semibold">Encryption</th>
              <th className="px-3 py-2 text-center text-purple-300 font-semibold">IDS Detection</th>
              <th className="px-3 py-2 text-center text-purple-300 font-semibold">IDS Prevention</th>
              <th className="px-3 py-2 text-center text-purple-300 font-semibold">Decryption</th>
              <th className="px-3 py-2 text-center text-purple-300 font-semibold">Total Time</th>
              <th className="px-3 py-2 text-center text-purple-300 font-semibold">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {sortedMetrics.map((metric, index) => (
              <tr 
                key={index}
                className={`border-b border-slate-700 hover:bg-slate-700 transition-colors ${
                  index % 2 === 0 ? 'bg-slate-800' : 'bg-slate-750'
                }`}
              >
                <td className="px-3 py-2 text-white font-medium">
                  #{metric.sessionId}
                </td>
                <td className="px-3 py-2 text-slate-300 text-xs">
                  <div>{metric.sender || 'Unknown'}</div>
                  <div className="text-slate-500">→ {metric.receiver || 'Unknown'}</div>
                </td>
                <td className="px-3 py-2 text-center">
                  <span className="bg-blue-900 text-blue-300 px-2 py-1 rounded text-xs font-mono">
                    {formatTime(metric.keyGenTime)}
                  </span>
                </td>
                <td className="px-3 py-2 text-center">
                  <span className="bg-green-900 text-green-300 px-2 py-1 rounded text-xs font-mono">
                    {formatTime(metric.encryptionTime)}
                  </span>
                </td>
                <td className="px-3 py-2 text-center">
                  <span className="bg-yellow-900 text-yellow-300 px-2 py-1 rounded text-xs font-mono">
                    {formatTime(metric.idsDetectionTime)}
                  </span>
                </td>
                <td className="px-3 py-2 text-center">
                  <span className="bg-purple-900 text-purple-300 px-2 py-1 rounded text-xs font-mono">
                    {formatTime(metric.idsPreventionTime)}
                  </span>
                </td>
                <td className="px-3 py-2 text-center">
                  <span className="bg-red-900 text-red-300 px-2 py-1 rounded text-xs font-mono">
                    {formatTime(metric.decryptionTime)}
                  </span>
                </td>
                <td className="px-3 py-2 text-center">
                  <span className="bg-cyan-900 text-cyan-300 px-2 py-1 rounded text-xs font-mono font-bold">
                    {formatTime(metric.totalTime)}
                  </span>
                </td>
                <td className="px-3 py-2 text-center text-slate-400 text-xs">
                  {new Date(metric.timestamp).toLocaleTimeString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Summary Stats */}
      {sortedMetrics.length > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-700 grid grid-cols-4 gap-3">
          <div className="bg-slate-700 rounded p-3 text-center">
            <div className="text-xs text-slate-400">Total Sessions</div>
            <div className="text-lg font-bold text-cyan-400">{sortedMetrics.length}</div>
          </div>
          <div className="bg-slate-700 rounded p-3 text-center">
            <div className="text-xs text-slate-400">Avg Total Time</div>
            <div className="text-lg font-bold text-cyan-400">
              {formatTime(Math.round(sortedMetrics.reduce((sum, m) => sum + (m.totalTime || 0), 0) / sortedMetrics.length))}
            </div>
          </div>
          <div className="bg-slate-700 rounded p-3 text-center">
            <div className="text-xs text-slate-400">Max Total Time</div>
            <div className="text-lg font-bold text-cyan-400">
              {formatTime(Math.max(...sortedMetrics.map(m => m.totalTime || 0)))}
            </div>
          </div>
          <div className="bg-slate-700 rounded p-3 text-center">
            <div className="text-xs text-slate-400">Min Total Time</div>
            <div className="text-lg font-bold text-cyan-400">
              {formatTime(Math.min(...sortedMetrics.map(m => m.totalTime || 0)))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
