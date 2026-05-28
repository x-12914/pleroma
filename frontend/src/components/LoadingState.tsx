import { AlertCircle, RefreshCw } from 'lucide-react';

export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center py-12">
      <div className="animate-spin-slow">
        <div className="w-12 h-12 border-2 border-dark-700 border-t-cyber-blue rounded-full" />
      </div>
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="glass-card border-2 border-cyber-red/30 bg-cyber-red/5 text-center py-12">
      <AlertCircle className="w-12 h-12 text-cyber-red mx-auto mb-4" />
      <p className="text-gray-300 mb-4">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-2 px-4 py-2 bg-cyber-red/20 hover:bg-cyber-red/30 text-cyber-red rounded-lg transition-colors duration-200"
        >
          <RefreshCw className="w-4 h-4" />
          Retry
        </button>
      )}
    </div>
  );
}

export function WarningState({ message }: { message: string }) {
  return (
    <div className="glass-card border-2 border-cyber-yellow/30 bg-cyber-yellow/5 p-4">
      <div className="flex gap-3">
        <AlertCircle className="w-5 h-5 text-cyber-yellow flex-shrink-0 mt-0.5" />
        <p className="text-gray-300">{message}</p>
      </div>
    </div>
  );
}
