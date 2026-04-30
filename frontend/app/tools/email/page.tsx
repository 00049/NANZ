'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import EmailSecurityGrade from '@/components/EmailSecurityGrade';
import { Loader2 } from 'lucide-react';

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
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/email-check?domain=${encodeURIComponent(inputDomain)}`);
      if (!res.ok) throw new Error('Failed to fetch email security data');
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
            <div className="animate-fade-in">
              <EmailSecurityGrade grade={result.grade} details={result} />
              
              <div className="mt-12 text-center max-w-2xl mx-auto p-6 bg-primary/10 border border-primary/20 rounded-lg">
                <h4 className="font-bold text-text-primary mb-2">Want a deeper analysis?</h4>
                <p className="text-text-muted text-sm mb-4">Our full security scan includes email security + 14 more advanced checks.</p>
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
