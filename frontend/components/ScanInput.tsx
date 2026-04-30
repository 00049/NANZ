'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useScanStore } from '../store/scanStore';
import { startScan } from '../lib/api';
import { scanUrlSchema } from '../lib/validations';

export default function ScanInput() {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();
  const { initScan } = useScanStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    let inputUrl = url.trim();
    if (inputUrl && !inputUrl.startsWith('http://') && !inputUrl.startsWith('https://')) {
      inputUrl = 'https://' + inputUrl;
    }

    const validation = scanUrlSchema.safeParse({ url: inputUrl });
    if (!validation.success) {
      setError(validation.error.errors[0].message);
      return;
    }

    setIsLoading(true);
    try {
      const res = await startScan(inputUrl);
      initScan(res.scan_id, inputUrl);
      router.push(`/scan/${res.scan_id}`);
    } catch (err: any) {
      setError(err.message || 'An error occurred while starting the scan');
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto mt-8 flex flex-col items-center">
      <div className="relative w-full flex flex-col md:flex-row gap-4">
        <input 
          type="text" 
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://yourwebsite.com" 
          className="flex-1 bg-surface border border-card-border text-text-primary rounded-btn px-6 py-4 outline-none focus:border-primary transition-colors text-lg shadow-lg placeholder-text-muted/50"
          disabled={isLoading}
        />
        <button 
          type="submit" 
          disabled={isLoading}
          className="bg-primary hover:bg-blue-600 text-white rounded-btn px-8 py-4 font-bold text-lg whitespace-nowrap transition-colors shadow-lg shadow-primary/20 disabled:opacity-70 disabled:cursor-not-allowed"
        >
          {isLoading ? 'Starting...' : 'Scan My Website Free'}
        </button>
      </div>
      {error && <p className="text-high text-sm mt-3 self-start md:self-center font-medium bg-high/10 px-3 py-1 rounded-md border border-high/20">{error}</p>}
      <p className="text-sm text-text-muted mt-4 font-medium">No signup required · Takes 30-90 seconds · 100% passive</p>
    </form>
  );
}
