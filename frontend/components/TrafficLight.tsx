export default function TrafficLight({ severity }: { severity: string }) {
  return (
    <div className="flex gap-2 p-3 bg-surface border border-card-border rounded-full w-max shadow-lg">
      <div className={`w-6 h-6 rounded-full transition-all duration-300 ${severity === 'RED' || severity === 'CRITICAL' ? 'bg-high shadow-[0_0_15px_rgba(239,68,68,0.6)]' : 'bg-high/20'}`} />
      <div className={`w-6 h-6 rounded-full transition-all duration-300 ${severity === 'AMBER' ? 'bg-medium shadow-[0_0_15px_rgba(245,158,11,0.6)]' : 'bg-medium/20'}`} />
      <div className={`w-6 h-6 rounded-full transition-all duration-300 ${severity === 'GREEN' ? 'bg-low shadow-[0_0_15px_rgba(34,197,94,0.6)]' : 'bg-low/20'}`} />
    </div>
  );
}
