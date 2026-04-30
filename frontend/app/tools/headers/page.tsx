'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { Loader2 } from 'lucide-react';
import { scanUrlSchema } from '@/lib/validations';

export default function HeadersTool() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    let inputUrl = url.trim();
    if (inputUrl && !inputUrl.startsWith('http')) inputUrl = 'https://' + inputUrl;
    
    if (!scanUrlSchema.safeParse({ url: inputUrl }).success) {
      setError("Please enter a valid URL");
      return;
    }

    setIsLoading(true);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/headers-check?url=${encodeURIComponent(inputUrl)}`);
      if (!res.ok) throw new Error('Failed to fetch headers');
      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <Navbar />
      <main className="flex-1 bg-background py-16 px-6">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-3xl md:text-4xl font-bold text-text-primary mb-4">Free Security Headers Scanner</h1>
            <p className="text-text-muted">Analyze your HTTP response headers for missing browser protections.</p>
          </div>
          
          <form onSubmit={handleSubmit} className="flex gap-4 mb-12">
            <input 
              type="text" 
              placeholder="https://example.com" 
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1 bg-surface border border-card-border rounded-btn px-4 py-3 text-text-primary outline-none focus:border-primary transition-colors"
            />
            <button type="submit" disabled={isLoading} className="bg-primary hover:bg-blue-600 text-white px-6 py-3 rounded-btn font-bold flex items-center justify-center min-w-[120px]">
              {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Scan Headers'}
            </button>
          </form>

          {error && <p className="text-high bg-high/10 border border-high/30 p-4 rounded-md mb-8">{error}</p>}

          {result && (
            <div className="bg-surface rounded-card border border-card-border p-8 shadow-xl animate-fade-in">
              <div className="flex items-center gap-6 mb-8 border-b border-card-border pb-6">
                <div className="w-24 h-24 rounded-full border-4 border-card-border flex items-center justify-center bg-background">
                  <span className={`text-4xl font-black ${result.grade.startsWith('A') ? 'text-low' : result.grade.startsWith('B') ? 'text-medium' : 'text-high'}`}>{result.grade}</span>
                </div>
                <div>
                  <h3 className="text-xl font-bold text-text-primary mb-1">Score: {result.score}/100</h3>
                  <p className="text-text-muted text-sm">Target: {result.url}</p>
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="font-bold text-text-primary">Header Status</h4>
                {['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy'].map(header => {
                  const isMissing = result.missing_important?.includes(header.toLowerCase());
                  return (
                    <div key={header} className="flex justify-between items-center p-3 bg-background rounded border border-card-border">
                      <span className="font-mono text-sm text-text-primary">{header}</span>
                      {isMissing ? <span className="text-high text-xs font-bold bg-high/10 px-2 py-1 rounded">MISSING</span> : <span className="text-low text-xs font-bold bg-low/10 px-2 py-1 rounded">PRESENT</span>}
                    </div>
                  );
                })}
              </div>
              
              <div className="mt-12 text-center p-6 bg-primary/10 border border-primary/20 rounded-lg">
                <h4 className="font-bold text-text-primary mb-2">Want a deeper analysis?</h4>
                <p className="text-text-muted text-sm mb-4">Our full security scan includes headers + 14 more advanced checks.</p>
                <a href="/" className="inline-block bg-primary text-white font-bold px-6 py-2 rounded-btn">Start Full Free Scan</a>
              </div>
            </div>
          )}
        </div>
      </main>
      <Footer />
    </>
  );
}
