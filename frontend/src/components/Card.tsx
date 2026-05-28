import type { ReactNode } from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: ReactNode;
  trend?: number;
  status?: 'success' | 'warning' | 'danger' | 'info';
  subtext?: string;
}

export default function MetricCard({
  title,
  value,
  icon,
  trend,
  status = 'info',
  subtext,
}: MetricCardProps) {
  const statusColors = {
    success: 'border-cyber-green/30 bg-cyber-green/5',
    warning: 'border-cyber-yellow/30 bg-cyber-yellow/5',
    danger: 'border-cyber-red/30 bg-cyber-red/5',
    info: 'border-cyber-blue/30 bg-cyber-blue/5',
  };

  const textColors = {
    success: 'text-cyber-green',
    warning: 'text-cyber-yellow',
    danger: 'text-cyber-red',
    info: 'text-cyber-blue',
  };

  return (
    <div className={`glass-card border-2 ${statusColors[status]}`}>
      <div className="flex items-start justify-between mb-4">
        <div>
          <p className="text-gray-400 text-sm font-medium">{title}</p>
        </div>
        <div className={`${textColors[status]} opacity-80`}>{icon}</div>
      </div>

      <div className="flex items-baseline gap-2 mb-2">
        <span className="text-3xl font-bold text-white">{value}</span>
        {trend !== undefined && (
          <div className={`flex items-center gap-1 text-sm ${trend >= 0 ? 'text-cyber-red' : 'text-cyber-green'}`}>
            {trend >= 0 ? (
              <TrendingUp className="w-4 h-4" />
            ) : (
              <TrendingDown className="w-4 h-4" />
            )}
            <span>{Math.abs(trend)}%</span>
          </div>
        )}
      </div>

      {subtext && (
        <p className="text-xs text-gray-500">{subtext}</p>
      )}
    </div>
  );
}

interface SimpleCardProps {
  title: string;
  children: ReactNode;
  className?: string;
}

export function SimpleCard({ title, children, className = '' }: SimpleCardProps) {
  return (
    <div className={`glass-card ${className}`}>
      {title && (
        <h3 className="text-lg font-semibold text-white mb-4">{title}</h3>
      )}
      {children}
    </div>
  );
}
