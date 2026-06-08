'use client';

import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle, AlertTriangle } from 'lucide-react';

interface RiskExceptionModalProps {
  findingKey: string;
  findingTitle: string;
  scanId: string;
  onClose: () => void;
  onSuccess: () => void;
}

export default function RiskExceptionModal({ findingKey, findingTitle, scanId, onClose, onSuccess }: RiskExceptionModalProps) {
  const [status, setStatus] = useState<'accepted' | 'mitigated' | 'false_positive'>('accepted');
  const [justification, setJustification] = useState('');
  const [owner, setOwner] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      const token = localStorage.getItem('token');
      const payload = {
        finding_key: findingKey,
        status,
        justification,
        owner,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null
      };

      const res = await fetch(`http://localhost:8000/api/v1/exceptions/scans/${scanId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        throw new Error('Failed to save exception');
      }

      onSuccess();
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 w-full max-w-lg rounded-xl shadow-2xl p-6 relative">
        <button 
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>
        
        <h2 className="text-xl font-semibold text-white mb-2 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-amber-500" />
          Manage Risk Exception
        </h2>
        <p className="text-sm text-slate-400 mb-6">
          Setting an exception for: <span className="font-mono text-slate-200">{findingTitle}</span>
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Exception Type</label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setStatus('accepted')}
                className={`py-2 px-3 text-xs font-medium rounded-md border flex items-center justify-center gap-1.5 transition-colors ${
                  status === 'accepted' 
                    ? 'bg-amber-500/20 border-amber-500/50 text-amber-300' 
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" /> Accept Risk
              </button>
              <button
                type="button"
                onClick={() => setStatus('mitigated')}
                className={`py-2 px-3 text-xs font-medium rounded-md border flex items-center justify-center gap-1.5 transition-colors ${
                  status === 'mitigated' 
                    ? 'bg-green-500/20 border-green-500/50 text-green-300' 
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
                }`}
              >
                <CheckCircle className="w-3.5 h-3.5" /> Mitigated
              </button>
              <button
                type="button"
                onClick={() => setStatus('false_positive')}
                className={`py-2 px-3 text-xs font-medium rounded-md border flex items-center justify-center gap-1.5 transition-colors ${
                  status === 'false_positive' 
                    ? 'bg-blue-500/20 border-blue-500/50 text-blue-300' 
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5" /> False Positive
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Justification</label>
            <textarea 
              required
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-md p-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500 min-h-[100px]"
              placeholder="Explain why this risk is being excepted..."
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Owner</label>
              <input 
                required
                type="text"
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-md p-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                placeholder="e.g. security-team"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Expiration Date (Optional)</label>
              <input 
                type="date"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-md p-2.5 text-sm text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
          </div>

          {error && <p className="text-red-400 text-sm mt-2">{error}</p>}

          <div className="pt-4 flex justify-end gap-3 border-t border-slate-700">
            <button 
              type="button" 
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
            >
              Cancel
            </button>
            <button 
              type="submit" 
              disabled={isSubmitting}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors disabled:opacity-50"
            >
              {isSubmitting ? 'Saving...' : 'Save Exception'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
