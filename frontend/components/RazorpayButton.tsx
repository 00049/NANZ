'use client';

import { useState } from 'react';
import { usePayment } from '../hooks/usePayment';
import { Loader2 } from 'lucide-react';

export default function RazorpayButton({ scanId }: { scanId: string }) {
  const [email, setEmail] = useState('');
  const [showEmailInput, setShowEmailInput] = useState(false);
  const { openPayment, isLoading, error } = usePayment();

  const handleUnlockClick = () => {
    if (!showEmailInput) {
      setShowEmailInput(true);
      return;
    }
    
    if (!email || !email.includes('@')) {
      alert("Please enter a valid email address");
      return;
    }
    
    openPayment(scanId, email);
  };

  return (
    <div className="w-full max-w-sm flex flex-col gap-3">
      {showEmailInput && (
        <input
          type="email"
          placeholder="Enter email to receive report"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full bg-background border border-card-border rounded-btn px-4 py-3 text-text-primary outline-none focus:border-primary transition-colors"
          disabled={isLoading}
          autoFocus
        />
      )}
      
      <button 
        onClick={handleUnlockClick}
        disabled={isLoading}
        className="w-full bg-primary hover:bg-blue-600 text-white rounded-btn px-8 py-4 font-bold text-lg transition-all shadow-lg shadow-primary/20 disabled:opacity-70 flex items-center justify-center gap-2"
      >
        {isLoading ? (
          <><Loader2 className="w-5 h-5 animate-spin" /> Processing...</>
        ) : (
          "Unlock Full Report"
        )}
      </button>
      
      {error && <p className="text-high text-sm mt-2">{error}</p>}
    </div>
  );
}
