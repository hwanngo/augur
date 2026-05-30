import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { ConfirmHost } from '../components/useConfirm';
import Toaster from '../components/Toaster';
import ErrorBoundary from '../components/ErrorBoundary';
import { Activity, Shield, LayoutDashboard, Users, BookOpen, LogOut, Languages, Network, ShieldAlert, Grid3x3, History, KeyRound, MonitorSmartphone, ScrollText, Sparkles, Bell, Crosshair, Telescope, Menu, X, Route as RouteIcon, ClipboardCheck, ScanSearch, GitFork, Layers, GitMerge, Filter } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import React, { useEffect, useState } from 'react';
import useAuthStore, { setNavigate } from '../store/auth';
import { useAlertSummary } from '../lib/useAlertSummary';

const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3 };

const LANGS = [
  { code: 'en', label: 'EN' },
  { code: 'vi', label: 'VI' },
] as const;

export default function AppShell() {
  const { t, i18n } = useTranslation();
  const user = useAuthStore((s) => s.user);
  const role = useAuthStore((s) => s.role);
  const logout = useAuthStore((s) => s.logout);
  const navigate = useNavigate();
  const location = useLocation();
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Wire navigate into the store for 401 redirects
  setNavigate(navigate);

  const canSeeAlerts = role != null && { viewer: 1, analyst: 2, admin: 3 }[role] >= 2;
  const { openCount, newCount, clearNew } = useAlertSummary(canSeeAlerts);

  useEffect(() => { if (newCount > 0) { const id = setTimeout(clearNew, 6000); return () => clearTimeout(id); } }, [newCount, clearNew]);

  // Close the mobile drawer whenever the route changes.
  useEffect(() => { setDrawerOpen(false); }, [location.pathname]);

  // Close the mobile drawer on Escape.
  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setDrawerOpen(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [drawerOpen]);

  type NavItem = {
    to: string;
    label: string;
    icon: React.ElementType;
    minRole: 'viewer' | 'analyst' | 'admin';
    badge?: number;
  };

  type NavSection = {
    key: string;
    labelKey: string;
    items: NavItem[];
    adminSection?: boolean;
  };

  const NAV_SECTIONS: NavSection[] = [
    {
      key: 'operations',
      labelKey: 'nav.section.operations',
      items: [
        { to: '/dashboard', label: t('nav.dashboard'), icon: LayoutDashboard, minRole: 'viewer' as const },
        { to: '/alerts', label: t('nav.alerts'), icon: Bell, minRole: 'analyst' as const, badge: openCount },
        { to: '/host-risk', label: t('nav.hostRisk'), icon: ShieldAlert, minRole: 'viewer' as const },
        { to: '/handover', label: t('nav.handover'), icon: History, minRole: 'viewer' as const },
      ],
    },
    {
      key: 'investigate',
      labelKey: 'nav.section.investigate',
      items: [
        { to: '/hunts', label: t('nav.hunts'), icon: Telescope, minRole: 'viewer' as const },
        { to: '/pivot', label: t('nav.pivot'), icon: GitFork, minRole: 'viewer' as const },
        { to: '/intel', label: t('nav.intel'), icon: ScanSearch, minRole: 'viewer' as const },
        { to: '/stack', label: t('nav.stack'), icon: Layers, minRole: 'viewer' as const },
        { to: '/tuning', label: t('nav.tuning'), icon: Filter, minRole: 'viewer' as const },
        { to: '/incidents', label: t('nav.incidents'), icon: GitMerge, minRole: 'viewer' as const },
      ],
    },
    {
      key: 'posture',
      labelKey: 'nav.section.posture',
      items: [
        { to: '/attack-paths', label: t('nav.attackPaths'), icon: RouteIcon, minRole: 'viewer' as const },
        { to: '/coverage-gaps', label: t('nav.coverageGaps'), icon: Grid3x3, minRole: 'viewer' as const },
        { to: '/topology', label: t('nav.topology'), icon: Network, minRole: 'viewer' as const },
        { to: '/scenarios', label: t('nav.scenarios'), icon: BookOpen, minRole: 'viewer' as const },
        { to: '/health', label: t('nav.detectionHealth'), icon: Activity, minRole: 'viewer' as const },
      ],
    },
    {
      key: 'validate',
      labelKey: 'nav.section.validate',
      items: [
        { to: '/campaign', label: t('nav.campaign'), icon: ClipboardCheck, minRole: 'viewer' as const },
        { to: '/drill', label: t('nav.drill'), icon: Crosshair, minRole: 'analyst' as const },
        { to: '/candidates', label: t('nav.candidates'), icon: Sparkles, minRole: 'analyst' as const },
      ],
    },
    {
      key: 'admin',
      labelKey: 'nav.section.admin',
      adminSection: true,
      items: [
        { to: '/account', label: t('nav.account'), icon: KeyRound, minRole: 'viewer' as const },
        { to: '/sessions', label: t('nav.sessions'), icon: MonitorSmartphone, minRole: 'viewer' as const },
        { to: '/users', label: t('nav.users'), icon: Users, minRole: 'admin' as const },
        { to: '/audit', label: t('nav.audit'), icon: ScrollText, minRole: 'admin' as const },
      ],
    },
  ];

  const visibleSections = NAV_SECTIONS.map((section) => ({
    ...section,
    visibleItems: section.items.filter(
      (item) => role != null && ROLE_RANK[role] >= ROLE_RANK[item.minRole]
    ),
  })).filter((section) => section.visibleItems.length > 0);

  // Normalize language code (e.g. 'en-US' → 'en')
  const currentLang = i18n.language?.split('-')[0] ?? 'en';

  return (
    <div className="flex h-dvh overflow-hidden" style={{ background: 'var(--bg)' }}>
      {/* Scrim — only below lg, only while the drawer is open */}
      {drawerOpen && (
        <div
          className="lg:hidden fixed inset-0 z-40 bg-black/60"
          onClick={() => setDrawerOpen(false)}
          aria-hidden
        />
      )}

      {/* Sidebar — persistent on lg+, off-canvas drawer below lg */}
      <aside
        id="app-sidebar"
        className={
          'fixed inset-y-0 left-0 z-50 w-64 flex flex-col border-r transform transition-transform duration-200 ease-out ' +
          'lg:static lg:z-auto lg:w-56 lg:translate-x-0 ' +
          (drawerOpen ? 'translate-x-0' : '-translate-x-full')
        }
        style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
        aria-label="Main navigation"
      >
        {/* Logo + (mobile) close */}
        <div className="flex items-center gap-2 px-4 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
          <Shield size={20} style={{ color: 'var(--accent)' }} aria-hidden />
          <span className="font-semibold text-sm tracking-wide" style={{ color: 'var(--fg)' }}>
            {t('nav.appName')}
          </span>
          <button
            type="button"
            onClick={() => setDrawerOpen(false)}
            className="lg:hidden ml-auto p-2 -mr-1 rounded-md transition-colors hover:bg-[#21262d] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
            style={{ color: 'var(--muted)' }}
            aria-label={t('nav.closeMenu')}
          >
            <X size={18} aria-hidden />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 min-h-0 overflow-y-auto py-3 px-2" aria-label="Sidebar">
          {visibleSections.map((section, i) => {
            const sectionLabel = t(section.labelKey);
            const headerId = `nav-section-${section.key}`;
            // Inter-section rhythm: first flush to the top, workflow groups get a
            // 16px gap, the admin block is separated further with a divider.
            const spacing = section.adminSection
              ? 'mt-5 pt-4 border-t'
              : i === 0 ? '' : 'mt-4';
            return (
              <div
                key={section.key}
                role="group"
                aria-labelledby={headerId}
                className={spacing}
                style={section.adminSection ? { borderColor: 'var(--border)' } : undefined}
              >
                <div
                  id={headerId}
                  className="px-3 pb-1.5 text-xs uppercase tracking-wider font-medium select-none"
                  style={{ color: 'var(--muted)' }}
                  aria-hidden="false"
                >
                  {sectionLabel}
                </div>
                <div className="space-y-0.5">
                  {section.visibleItems.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      onClick={() => setDrawerOpen(false)}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ` +
                        (isActive
                          ? 'bg-[#21262d] text-[var(--accent)]'
                          : 'text-[var(--muted)] hover:bg-[#21262d] hover:text-[var(--fg)]')
                      }
                    >
                      <item.icon size={16} aria-hidden />
                      {item.label}
                      {item.badge ? (
                        <span className="ml-auto px-1.5 py-0.5 rounded-full text-[10px] font-bold tabular-nums"
                              style={{ background: 'var(--accent)', color: '#0d1117' }}>
                          {item.badge}
                        </span>
                      ) : null}
                    </NavLink>
                  ))}
                </div>
              </div>
            );
          })}
        </nav>

        {/* User / logout — flex-shrink-0 so a long nav can never squeeze/clip it. */}
        <div className="px-3 py-3 border-t flex-shrink-0" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-center gap-2 mb-2">
            <div
              className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold uppercase flex-shrink-0"
              style={{ background: 'var(--accent)', color: '#0d1117' }}
              aria-hidden
            >
              {user?.[0] ?? '?'}
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-xs font-medium truncate" style={{ color: 'var(--fg)' }}>
                {user}
              </div>
              <div className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--muted)' }}>
                {role}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void logout()}
            className="flex items-center gap-2 w-full px-2 py-2 rounded-md text-xs transition-colors duration-150 cursor-pointer hover:bg-[#21262d] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
            style={{ color: 'var(--muted)' }}
            aria-label={t('nav.logout')}
          >
            <LogOut size={13} aria-hidden />
            {t('nav.logout')}
          </button>

          {/* Language switcher */}
          <div
            className="flex items-center gap-1.5 mt-2 pt-2 border-t"
            style={{ borderColor: 'var(--border)' }}
            aria-label={t('nav.toggleLanguage')}
            role="group"
          >
            <Languages size={12} style={{ color: 'var(--muted)' }} aria-hidden />
            {LANGS.map(({ code, label }) => (
              <button
                key={code}
                type="button"
                onClick={() => void i18n.changeLanguage(code)}
                className="px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
                style={{
                  background: currentLang === code ? 'var(--accent)' : 'transparent',
                  color: currentLang === code ? '#0d1117' : 'var(--muted)',
                }}
                aria-pressed={currentLang === code}
                aria-label={`Switch to ${label}`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Mobile top bar (hidden on lg+) */}
        <header
          className="lg:hidden flex items-center gap-3 px-4 h-14 border-b flex-shrink-0"
          style={{ background: 'var(--panel)', borderColor: 'var(--border)' }}
        >
          <button
            type="button"
            onClick={() => setDrawerOpen(true)}
            className="p-2 -ml-2 rounded-md transition-colors hover:bg-[#21262d] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
            style={{ color: 'var(--fg)' }}
            aria-label={t('nav.openMenu')}
            aria-expanded={drawerOpen}
            aria-controls="app-sidebar"
          >
            <Menu size={22} aria-hidden />
          </button>
          <Shield size={18} style={{ color: 'var(--accent)' }} aria-hidden />
          <span className="font-semibold text-sm tracking-wide" style={{ color: 'var(--fg)' }}>
            {t('nav.appName')}
          </span>
        </header>

        <main className="flex-1 min-w-0 overflow-auto">
          {/* Key by route so navigating away from a crashed page clears the error. */}
          <ErrorBoundary key={location.pathname}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>

      {newCount > 0 && (
        <div role="alert" aria-live="polite" className="fixed bottom-5 right-5 z-50">
          <button type="button"
             className="flex items-center gap-2 px-4 py-3 rounded-lg border text-sm shadow-lg cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus)]"
             style={{ background: '#3a2600', borderColor: '#ffae57', color: '#ffae57' }}
             onClick={() => { clearNew(); navigate('/alerts'); }}>
            <Bell size={14} aria-hidden /> {t('alerts.newAlerts', { count: newCount })}
          </button>
        </div>
      )}
      <ConfirmHost />
      <Toaster />
    </div>
  );
}
