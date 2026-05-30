import { useTranslation } from 'react-i18next';
import useAuthStore, { type Role } from '../store/auth';

const ROLE_RANK: Record<Role, number> = {
  viewer: 1,
  analyst: 2,
  admin: 3,
};

interface RequireRoleProps {
  role: Role;
  children: React.ReactNode;
}

export default function RequireRole({ role, children }: RequireRoleProps) {
  const { t } = useTranslation();
  const userRole = useAuthStore((s) => s.role);

  const allowed = userRole != null && ROLE_RANK[userRole] >= ROLE_RANK[role];

  if (!allowed) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <div className="text-4xl font-bold tabular-nums" style={{ color: 'var(--muted)' }}>403</div>
        <p className="text-sm" style={{ color: 'var(--muted)' }}>
          {t('common.forbidden')}
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
