import { Navigate, useLocation } from 'react-router-dom';
import useAuthStore from '../store/auth';

export default function RequireAuth({ children }: { children: React.ReactNode }) {
  const status = useAuthStore((s) => s.status);
  const location = useLocation();

  if (status === 'loading') {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ color: 'var(--muted)' }}>
        <div className="w-6 h-6 rounded-full border-2 border-(--border) border-t-(--accent) animate-spin" />
      </div>
    );
  }

  if (status === 'anon') {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
