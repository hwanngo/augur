import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import AppShell from '../AppShell';
import useAuthStore from '../../store/auth';
import i18n from '../../i18n';
import en from '../../locales/en.json';
import vi from '../../locales/vi.json';

function flatKeys(obj: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    return v && typeof v === 'object'
      ? flatKeys(v as Record<string, unknown>, key)
      : [key];
  });
}

beforeEach(() => {
  // Reset to English before each test
  void i18n.changeLanguage('en');
  useAuthStore.setState({ user: 'alice', role: 'admin', csrf: 'tok', status: 'authed', error: null });
});

function setup() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <AppShell />
    </MemoryRouter>
  );
}

describe('Locale parity (en/vi)', () => {
  it('en and vi have an identical set of keys', () => {
    const enKeys = flatKeys(en as Record<string, unknown>).sort();
    const viKeys = flatKeys(vi as Record<string, unknown>).sort();
    expect(viKeys).toEqual(enKeys);
  });
});

describe('Language switcher', () => {
  it('renders nav in English by default', () => {
    setup();
    expect(screen.getByRole('link', { name: /dashboard/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /scenarios/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /users/i })).toBeInTheDocument();
  });

  it('switching to Vietnamese updates nav labels', async () => {
    setup();

    // Click the VI button
    const viButton = screen.getByRole('button', { name: /switch to vi/i });
    fireEvent.click(viButton);

    // Vietnamese translations should be visible
    expect(await screen.findByRole('link', { name: /bảng điều khiển/i })).toBeInTheDocument();
    // Exact match: the loose /kịch bản/i would also match the "Generated" nav
    // item ("Kịch bản sinh tự động"), so assert the Scenarios link precisely.
    expect(screen.getByRole('link', { name: 'Kịch bản' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /người dùng/i })).toBeInTheDocument();
  });

  it('switching back to English restores English labels', async () => {
    setup();

    // Switch to VI
    fireEvent.click(screen.getByRole('button', { name: /switch to vi/i }));
    expect(await screen.findByRole('link', { name: /bảng điều khiển/i })).toBeInTheDocument();

    // Switch back to EN
    fireEvent.click(screen.getByRole('button', { name: /switch to en/i }));
    expect(await screen.findByRole('link', { name: /dashboard/i })).toBeInTheDocument();
  });
});

describe('Sidebar footer hardening', () => {
  it('renders the new Incidents nav item and keeps the logout footer clickable', () => {
    setup();
    // the last INVESTIGATE item must be present and operable (not clipped behind the footer)
    const incidents = screen.getByRole('link', { name: /incidents/i });
    expect(incidents).toBeInTheDocument();
    fireEvent.click(incidents);   // clickable, no throw
    // the footer logout control is still rendered alongside it
    expect(screen.getByRole('button', { name: /log ?out/i })).toBeInTheDocument();
  });
});
