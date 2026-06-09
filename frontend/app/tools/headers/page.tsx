'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { Loader2, CheckCircle2, AlertCircle, XCircle, ArrowRight } from 'lucide-react';
import { scanUrlSchema } from '@/lib/validations';
import Link from 'next/link';

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
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/tools/headers?url=${encodeURIComponent(inputUrl)}`);
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
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-3xl md:text-4xl font-bold text-text-primary mb-4">Free Security Headers Scanner</h1>
            <p className="text-text-muted">Analyze your HTTP response headers for missing browser protections.</p>
          </div>
          
          <form onSubmit={handleSubmit} className="flex gap-4 mb-12 max-w-3xl mx-auto">
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

          {error && <p className="text-high bg-high/10 border border-high/30 p-4 rounded-md mb-8 max-w-3xl mx-auto text-center">{error}</p>}

          {result && (
            <div className="bg-surface rounded-card border border-card-border p-8 shadow-xl animate-fade-in">
              <div className="flex items-center gap-6 mb-8 border-b border-card-border pb-6">
                <div className="w-24 h-24 rounded-full border-4 border-card-border flex items-center justify-center bg-background">
                  <span className={`text-4xl font-black ${result.grade.startsWith('A') ? 'text-low' : result.grade.startsWith('B') ? 'text-medium' : 'text-high'}`}>{result.grade}</span>
                </div>
                <div>
                  <h3 className="text-xl font-bold text-text-primary mb-1">Security Headers Analysis</h3>
                  <p className="text-text-muted text-sm">Target: {url}</p>
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="font-bold text-text-primary text-lg mb-4">Header Status</h4>
                <div className="grid gap-4">
                  {result.headers?.map((header: any, idx: number) => {
                    const isPresent = header.status === 'present';
                    const isWarning = header.status === 'misconfigured';
                    const isMissing = header.status === 'missing';
                    
                    return (
                      <div key={idx} className="flex flex-col md:flex-row gap-4 p-4 bg-background rounded-lg border border-card-border">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            {isPresent && <CheckCircle2 className="w-5 h-5 text-low" />}
                            {isWarning && <AlertCircle className="w-5 h-5 text-medium" />}
                            {isMissing && <XCircle className="w-5 h-5 text-high" />}
                            <span className="font-mono text-sm font-bold text-text-primary">{header.name}</span>
                          </div>
                          <p className="text-sm text-text-muted mb-2">{header.description}</p>
                          {header.fix && <p className="text-xs font-semibold text-primary/80">Fix: {header.fix}</p>}
                        </div>
                        <div className="md:w-1/3 break-all">
                          {header.value ? (
                            <div className="bg-surface-hover/30 p-2 rounded text-xs font-mono text-text-secondary border border-card-border">
                              {header.value}
                            </div>
                          ) : (
                            <span className="text-xs text-text-muted italic">No value provided</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
              
              <div className="mt-12 text-center p-8 bg-gradient-to-r from-primary/5 to-primary/10 border border-primary/20 rounded-xl">
                <h4 className="text-xl font-bold text-text-primary mb-3">Want a full 29-module scan?</h4>
                <p className="text-text-muted text-sm mb-6 max-w-xl mx-auto">
                  Our comprehensive platform checks your web application for OWASP Top 10 vulnerabilities, cloud exposure, email security, leaked credentials, and more.
                </p>
                <Link href="/" className="inline-flex items-center gap-2 bg-primary hover:bg-blue-600 transition-colors text-white font-bold px-8 py-3 rounded-btn shadow-lg shadow-primary/20">
                  Run Full Audit (Free Preview) <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          )}
        </div>
      </main>
      <Footer />
    </>
  );
}
