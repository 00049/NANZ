'use client';

import { RadialBarChart, RadialBar, PolarAngleAxis } from 'recharts';
import { useEffect, useState } from 'react';
import { normalizeSeverity } from '@/lib/severity';

export default function ScoreRing({ score, severity, hideText = false }: { score: number, severity: string, hideText?: boolean }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const duration = 1500;
    const steps = 60;
    const stepTime = duration / steps;
    const increment = score / steps;

    let current = 0;
    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        setAnimatedScore(score);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.floor(current));
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [score]);

  const getColor = (score: number) => {
    if (score < 50) return '#EF4444'; // RED
    if (score < 70) return '#F59E0B'; // AMBER
    return '#22C55E'; // GREEN
  };

  const data = [{ name: 'Score', value: animatedScore, fill: getColor(score) }];

  const ringSize = hideText ? 32 : 240;

  const normalized = normalizeSeverity(severity);
  const severityLabel = normalized === 'CRITICAL' ? 'CRITICAL RISK' :
    normalized === 'HIGH' ? 'HIGH RISK' :
    normalized === 'MEDIUM' ? 'MEDIUM RISK' :
    normalized === 'LOW' ? 'LOW RISK' : normalized + ' RISK';

  return (
    <div className={hideText ? 'relative flex items-center justify-center' : 'flex flex-col items-center justify-center p-6 bg-surface rounded-card border border-card-border shadow-lg'}>
      <div className={`relative flex items-center justify-center`} style={{ width: hideText ? 32 : 192, height: hideText ? 32 : 192 }}>
        <RadialBarChart
          width={ringSize}
          height={ringSize}
          innerRadius="70%"
          outerRadius="90%"
          data={data}
          startAngle={90}
          endAngle={-270}
          className="absolute"
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar background={{ fill: '#334155' }} dataKey="value" cornerRadius={10} />
        </RadialBarChart>
        {!hideText && (
          <div className="absolute flex flex-col items-center justify-center">
            <span className="text-5xl font-black tabular-nums tracking-tighter" style={{ color: getColor(score) }}>
              {animatedScore}
            </span>
            <span className="text-sm font-medium text-text-muted mt-1 uppercase tracking-widest">/ 100</span>
          </div>
        )}
      </div>
      {!hideText && (
        <div className="mt-4 text-center">
          <div className={`inline-flex items-center px-4 py-1.5 rounded-full text-sm font-bold uppercase tracking-wider ${
            normalized === 'CRITICAL' || normalized === 'HIGH' ? 'bg-critical-bg text-high border border-high/30' :
              normalized === 'MEDIUM' ? 'bg-medium-bg text-medium border border-medium/30' :
                'bg-low/10 text-low border border-low/30'
            }`}>
            {severityLabel}
          </div>
        </div>
      )}
    </div>
  );
}

