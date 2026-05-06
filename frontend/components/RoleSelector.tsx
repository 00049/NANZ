'use client';

import { useEffect, useState } from 'react';
import { Briefcase, Monitor, Code2 } from 'lucide-react';
import { Role } from '@/types';

interface RoleSelectorProps {
  value: Role;
  onChange: (role: Role) => void;
}

const ROLES: { id: Role; label: string; icon: React.ReactNode; description: string }[] = [
  {
    id: 'ciso',
    label: 'CISO',
    icon: <Briefcase className="w-3.5 h-3.5" />,
    description: 'Financial risk & compliance',
  },
  {
    id: 'analyst',
    label: 'Analyst',
    icon: <Monitor className="w-3.5 h-3.5" />,
    description: 'Threat intelligence & attack paths',
  },
  {
    id: 'developer',
    label: 'Developer',
    icon: <Code2 className="w-3.5 h-3.5" />,
    description: 'Code-level fixes & quick wins',
  },
];

const LS_KEY = 'shield_role';

export default function RoleSelector({ value, onChange }: RoleSelectorProps) {
  return (
    <div className="flex items-center gap-3 p-1.5 bg-[#0a0a0d] border border-slate-800/60 rounded-xl w-fit">
      <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600 pl-1.5 shrink-0">
        Viewing as:
      </span>
      <div className="flex items-center gap-1">
        {ROLES.map(role => (
          <button
            key={role.id}
            onClick={() => onChange(role.id)}
            title={role.description}
            className={`
              flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all
              ${value === role.id
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/40'
                : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/50'
              }
            `}
          >
            {role.icon}
            {role.label}
            {value === role.id && (
              <span className="w-1.5 h-1.5 rounded-full bg-white/60 ml-0.5" />
            )}
          </button>
        ))}
      </div>
    </div>
  );
}

/** Hook to persist role in localStorage */
export function useRole(): [Role, (r: Role) => void] {
  const [role, setRole] = useState<Role>('ciso');

  useEffect(() => {
    const stored = localStorage.getItem(LS_KEY) as Role | null;
    if (stored && ['ciso', 'analyst', 'developer'].includes(stored)) {
      setRole(stored);
    }
  }, []);

  const setAndPersist = (r: Role) => {
    setRole(r);
    localStorage.setItem(LS_KEY, r);
  };

  return [role, setAndPersist];
}
