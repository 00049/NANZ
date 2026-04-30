export default function TechInventory({ inventory }: { inventory: any }) {
  if (!inventory || !inventory.technologies || inventory.technologies.length === 0) {
    return <div className="p-6 bg-surface rounded-card border border-card-border text-text-muted">No specific technologies detected.</div>;
  }

  return (
    <div className="bg-surface rounded-card border border-card-border overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="bg-background text-text-muted uppercase text-xs">
            <tr>
              <th className="px-6 py-4 font-medium tracking-wider">Technology</th>
              <th className="px-6 py-4 font-medium tracking-wider">Detected Version</th>
              <th className="px-6 py-4 font-medium tracking-wider">Status</th>
              <th className="px-6 py-4 font-medium tracking-wider">CVEs</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-card-border">
            {inventory.technologies.map((tech: any, idx: number) => {
              const statusColor = tech.status === 'secure' ? 'bg-low/10 text-low border-low/30' : 
                                  tech.status === 'outdated' ? 'bg-medium/10 text-medium border-medium/30' : 
                                  'bg-high/10 text-high border-high/30';
              
              return (
                <tr key={idx} className="hover:bg-background/50 transition-colors">
                  <td className="px-6 py-4 font-medium text-text-primary flex items-center gap-3">
                    {tech.name}
                  </td>
                  <td className="px-6 py-4 font-mono text-text-muted">
                    {tech.version || 'Unknown'}
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase border ${statusColor}`}>
                      {tech.status || 'Unknown'}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    {tech.cves && tech.cves.length > 0 ? (
                      <div className="flex flex-col gap-1">
                        <span className="text-high font-bold">{tech.cves.length} Vulnerabilities</span>
                        <div className="text-xs text-text-muted">
                          {tech.cves.slice(0, 2).map((cve: any) => cve.id).join(', ')}
                          {tech.cves.length > 2 && ' ...'}
                        </div>
                      </div>
                    ) : (
                      <span className="text-text-muted">None detected</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
