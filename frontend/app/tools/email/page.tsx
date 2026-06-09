'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { Loader2, CheckCircle2, AlertCircle, XCircle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

export default function EmailTool() {
  const [domain, setDomain] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    let inputDomain = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!inputDomain) {
      setError("Please enter a valid domain");
      return;
    }

    setIsLoading(true);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/tools/email?domain=${encodeURIComponent(inputDomain)}`);
      if (!res.ok) throw new Error('Failed to fetch email security data');
      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-low';
    if (score >= 70) return 'text-medium';
    return 'text-high';
  };

  return (
    <>
      <Navbar />
      <main className="flex-1 bg-background py-16 px-6">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-3xl md:text-4xl font-bold text-text-primary mb-4">Free Email Security Scanner</h1>
            <p className="text-text-muted">Check your domain&apos;s SPF, DMARC, and DKIM configuration to prevent spoofing.</p>
          </div>
          
          <form onSubmit={handleSubmit} className="flex max-w-xl mx-auto gap-4 mb-12">
            <input 
              type="text" 
              placeholder="example.com" 
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="flex-1 bg-surface border border-card-border rounded-btn px-4 py-3 text-text-primary outline-none focus:border-primary transition-colors"
            />
            <button type="submit" disabled={isLoading} className="bg-primary hover:bg-blue-600 text-white px-6 py-3 rounded-btn font-bold flex items-center justify-center min-w-[120px]">
              {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Scan Domain'}
            </button>
          </form>

          {error && <p className="text-high bg-high/10 border border-high/30 p-4 rounded-md mb-8 max-w-xl mx-auto text-center">{error}</p>}

          {result && (
            <div className="bg-surface rounded-card border border-card-border p-8 shadow-xl animate-fade-in">
              <div className="flex items-center gap-6 mb-8 border-b border-card-border pb-6">
                <div className="w-24 h-24 rounded-full border-4 border-card-border flex items-center justify-center bg-background">
                  <span className={`text-4xl font-black ${getScoreColor(result.overall_score)}`}>{result.overall_score}</span>
                </div>
                <div>
                  <h3 className="text-xl font-bold text-text-primary mb-1">Email Security Analysis</h3>
                  <p className="text-text-muted text-sm">Target: {domain}</p>
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="font-bold text-text-primary text-lg mb-4">DNS Records Analysis</h4>
                <div className="grid gap-4">
                  {result.records?.map((record: any, idx: number) => {
                    const isPresent = record.status === 'present';
                    const isMissing = record.status === 'missing';
                    // We assume it's a warning if it's present but has a fix recommended
                    const isWarning = isPresent && record.fix !== "";

                    return (
                      <div key={idx} className="flex flex-col md:flex-row gap-4 p-4 bg-background rounded-lg border border-card-border">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            {isPresent && !isWarning && <CheckCircle2 className="w-5 h-5 text-low" />}
                            {isWarning && <AlertCircle className="w-5 h-5 text-medium" />}
                            {isMissing && <XCircle className="w-5 h-5 text-high" />}
                            <span className="font-mono text-sm font-bold text-text-primary">{record.type}</span>
                            <span className={`ml-2 text-xs font-bold px-2 py-0.5 rounded ${
                              !isMissing && !isWarning ? 'bg-low/10 text-low' : 
                              isWarning ? 'bg-medium/10 text-medium' : 
                              'bg-high/10 text-high'
                            }`}>
                              {!isMissing && !isWarning ? 'SECURE' : isWarning ? 'WARNING' : 'MISSING'}
                            </span>
                          </div>
                          <p className="text-sm text-text-muted mb-2">{record.risk}</p>
                          {record.fix && <p className="text-xs font-semibold text-primary/80">Fix: {record.fix}</p>}
                        </div>
                        <div className="md:w-1/3 break-all">
                          <div className="bg-surface-hover/30 p-2 rounded text-xs font-mono text-text-secondary border border-card-border">
                            {record.value}
                          </div>
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
