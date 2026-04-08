import React, { useState } from 'react';

export default function CSVUploader({ onFileUpload, onExampleSelect }) {
  const [fileName, setFileName] = useState('');
  const [previewData, setPreviewData] = useState(null);
  const [error, setError] = useState('');

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setFileName(file.name);
    setError('');
    
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const csvData = parseCSV(event.target.result);
        setPreviewData(csvData);
        // Pass both csvData and original file
        onFileUpload(csvData, file);
      } catch (err) {
        setError('Error parsing CSV file');
        console.error('CSV parse error:', err);
      }
    };
    reader.readAsText(file);
  };

  const parseCSV = (csvText) => {
    const lines = csvText.split('\n').filter(line => line.trim() !== '');
    if (lines.length < 2) throw new Error('CSV must have at least one data row');
    
    const headers = lines[0].split(',').map(h => h.trim());
    const data = [];
    
    for (let i = 1; i < lines.length; i++) {
      const values = lines[i].split(',');
      const row = {};
      headers.forEach((header, index) => {
        row[header] = values[index] ? values[index].trim() : '';
      });
      data.push(row);
    }
    
    return { headers, data };
  };

  const handleExampleSelect = (exampleNumber, type) => {
    const exampleFile = `example_${type}_${exampleNumber}.csv`;
    fetch(exampleFile)
      .then(response => response.text())
      .then(csvText => {
        const csvData = parseCSV(csvText);
        setPreviewData(csvData);
        onFileUpload(csvData);
        setFileName(exampleFile);
      })
      .catch(err => {
        setError(`Error loading example file: ${err.message}`);
      });
  };

  return (
    <div className="space-y-4">
      <div className="border-2 border-dashed border-blue-400 rounded-lg p-6 text-center">
        <input
          type="file"
          id="csv-upload"
          accept=".csv"
          onChange={handleFileChange}
          className="hidden"
        />
        <label
          htmlFor="csv-upload"
          className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg transition"
        >
          📄 Upload CSV File
        </label>
        {fileName && (
          <p className="mt-2 text-sm text-blue-200">
            Selected: <span className="font-mono">{fileName}</span>
          </p>
        )}
      </div>

      <div className="text-center">
        <p className="text-sm text-slate-400 mb-2">Or try an example:</p>
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={() => handleExampleSelect(1, 'normal')}
            className="bg-green-600 hover:bg-green-700 text-white text-sm py-2 px-3 rounded-lg transition"
          >
            Normal Messages 1
          </button>
          <button
            onClick={() => handleExampleSelect(2, 'normal')}
            className="bg-green-600 hover:bg-green-700 text-white text-sm py-2 px-3 rounded-lg transition"
          >
            Normal Messages 2
          </button>
          <button
            onClick={() => handleExampleSelect(1, 'intrusion')}
            className="bg-red-600 hover:bg-red-700 text-white text-sm py-2 px-3 rounded-lg transition"
          >
            Intrusion Attempts 1
          </button>
          <button
            onClick={() => handleExampleSelect(2, 'intrusion')}
            className="bg-red-600 hover:bg-red-700 text-white text-sm py-2 px-3 rounded-lg transition"
          >
            Intrusion Attempts 2
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-900 text-red-100 p-3 rounded-lg text-sm">
          ❌ {error}
        </div>
      )}

      {previewData && (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-blue-300 mb-2">
            Preview ({previewData.data.length} rows):
          </h4>
          <div className="overflow-x-auto bg-slate-800 rounded-lg p-2 max-h-60 overflow-y-auto">
            <table className="min-w-full text-xs">
              <thead>
                <tr className="bg-slate-700">
                  {previewData.headers.map((header, idx) => (
                    <th key={idx} className="px-2 py-1 text-left">
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {previewData.data.slice(0, 5).map((row, rowIdx) => (
                  <tr 
                    key={rowIdx} 
                    className={`${rowIdx % 2 === 0 ? 'bg-slate-800' : 'bg-slate-750'}`}
                  >
                    {previewData.headers.map((header, colIdx) => (
                      <td key={colIdx} className="px-2 py-1 border-b border-slate-700 truncate max-w-xs">
                        {String(row[header] || '')}
                      </td>
                    ))}
                  </tr>
                ))}
                {previewData.data.length > 5 && (
                  <tr>
                    <td colSpan={previewData.headers.length} className="text-center py-1 text-slate-400">
                      ... and {previewData.data.length - 5} more rows
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
