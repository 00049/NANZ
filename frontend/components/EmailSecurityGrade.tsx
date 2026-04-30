export default function EmailSecurityGrade({ grade, details }: { grade: string, details: any }) {
  const getGradeColor = (g: string) => {
    if (g.startsWith('A')) return 'text-low';
    if (g.startsWith('B') || g.startsWith('C')) return 'text-medium';
    return 'text-high';
  };

  const passFailIcon = (status: boolean) => 
    status ? <span className="text-low font-bold">✅ PASS</span> : <span className="text-high font-bold">❌ FAIL</span>;

  return (
    <div className="flex flex-col md:flex-row gap-8 bg-surface rounded-card border border-card-border p-8 shadow-xl">
      <div className="flex flex-col items-center justify-center min-w-[200px] border-b md:border-b-0 md:border-r border-card-border pb-8 md:pb-0 md:pr-8">
        <h4 className="text-text-muted font-medium mb-4 uppercase tracking-widest text-sm">Overall Grade</h4>
        <div className="relative w-32 h-32 flex items-center justify-center rounded-full border-4 border-card-border bg-background shadow-inner">
          <span className={`text-6xl font-black ${getGradeColor(grade)}`}>
            {grade || 'F'}
          </span>
        </div>
      </div>
      
      <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="bg-background p-4 rounded-lg border border-card-border">
          <div className="flex items-center justify-between mb-2">
            <h5 className="font-bold text-text-primary">SPF Record</h5>
            {passFailIcon(details?.has_spf)}
          </div>
          <p className="text-xs text-text-muted">Prevents unauthorized senders from using your domain.</p>
        </div>
        
        <div className="bg-background p-4 rounded-lg border border-card-border">
          <div className="flex items-center justify-between mb-2">
            <h5 className="font-bold text-text-primary">DMARC Policy</h5>
            {passFailIcon(details?.has_dmarc)}
          </div>
          <p className="text-xs text-text-muted">Instructs email providers how to handle spoofed emails.</p>
        </div>
        
        <div className="bg-background p-4 rounded-lg border border-card-border">
          <div className="flex items-center justify-between mb-2">
            <h5 className="font-bold text-text-primary">DKIM Signatures</h5>
            {passFailIcon(details?.has_dkim)}
          </div>
          <p className="text-xs text-text-muted">Cryptographically signs emails to prove authenticity.</p>
        </div>
        
        <div className="bg-background p-4 rounded-lg border border-card-border">
          <div className="flex items-center justify-between mb-2">
            <h5 className="font-bold text-text-primary">MX Security</h5>
            {passFailIcon(details?.smtp_tls_enabled !== false)}
          </div>
          <p className="text-xs text-text-muted">Ensures email servers support encrypted connections.</p>
        </div>
      </div>
    </div>
  );
}
