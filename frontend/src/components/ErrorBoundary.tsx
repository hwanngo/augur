import React from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle } from 'lucide-react';

interface Props {
  children: React.ReactNode;
  /** Optional override for the reload affordance (defaults to a full page reload). */
  onReload?: () => void;
}

interface State {
  error: Error | null;
}

/**
 * Localized fallback rendered when a subtree throws. Kept as a separate
 * function component so it can use the i18next hook (class components cannot).
 */
function Fallback({ error, onReload }: { error: Error; onReload: () => void }) {
  const { t } = useTranslation();
  return (
    <div
      role="alert"
      className="flex flex-col items-center justify-center gap-4 p-8 m-6 rounded-lg border text-center"
      style={{ background: 'var(--panel)', borderColor: 'var(--border)', color: 'var(--fg)' }}
    >
      <AlertTriangle size={32} style={{ color: 'var(--accent)' }} aria-hidden />
      <h2 className="text-lg font-semibold">{t('errorBoundary.title')}</h2>
      <p className="text-sm max-w-md" style={{ color: 'var(--muted)' }}>
        {t('errorBoundary.message')}
      </p>
      {error.message ? (
        <details className="text-xs max-w-md w-full text-left" style={{ color: 'var(--muted)' }}>
          <summary className="cursor-pointer">{t('errorBoundary.details')}</summary>
          <pre className="mt-2 overflow-auto whitespace-pre-wrap wrap-break-word">{error.message}</pre>
        </details>
      ) : null}
      <button
        type="button"
        onClick={onReload}
        className="px-4 py-2 rounded-md text-sm font-medium transition-colors cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-(--focus)"
        style={{ background: 'var(--accent)', color: '#0d1117' }}
      >
        {t('errorBoundary.reload')}
      </button>
    </div>
  );
}

/**
 * Top-level React error boundary. Wraps routed content so a single page crash
 * renders a localized fallback instead of blanking the whole console.
 */
export default class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    // No remote telemetry (AI-free, no external calls) — log to the console only.
     
    console.error('ErrorBoundary caught an error:', error, info.componentStack);
  }

  handleReload = (): void => {
    if (this.props.onReload) {
      this.props.onReload();
    } else if (typeof window !== 'undefined') {
      window.location.reload();
    }
  };

  render(): React.ReactNode {
    if (this.state.error) {
      return <Fallback error={this.state.error} onReload={this.handleReload} />;
    }
    return this.props.children;
  }
}
