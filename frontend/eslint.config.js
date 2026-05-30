import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import jsxA11y from 'eslint-plugin-jsx-a11y';

export default tseslint.config(
  {
    // Build output, deps, and generated PWA assets are never linted.
    ignores: ['dist', 'dev-dist', 'node_modules', 'coverage'],
  },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.recommended,
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: { ...globals.browser, ...globals.node },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
      'jsx-a11y': jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.configs.recommended.rules,
      // `role` is also a legitimate prop on our custom components (e.g. <RequireRole role="admin">).
      // Restrict the ARIA-role check to real DOM elements so custom components are not flagged.
      'jsx-a11y/aria-role': ['error', { ignoreNonDOM: true }],
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      // Allow intentional `_`-prefixed unused vars/args.
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  {
    // These modules deliberately colocate a component with non-component exports that are part of
    // their public contract: shared design tokens / helpers (criticality), a hook + its host
    // (useConfirm), a localized fallback beside the boundary class (ErrorBoundary), and pure
    // graph-mapping helpers exported for unit tests (Pivot, AttackPaths, Topology). Fast-refresh
    // granularity is not meaningful here, so the advisory react-refresh rule is scoped off for them only.
    files: [
      'src/lib/criticality.tsx',
      'src/components/useConfirm.tsx',
      'src/components/ErrorBoundary.tsx',
      'src/pages/Pivot.tsx',
      'src/pages/AttackPaths.tsx',
      'src/pages/Topology.tsx',
    ],
    rules: {
      'react-refresh/only-export-components': 'off',
    },
  },
  {
    // Tests use globals from vitest and may stub liberally.
    files: ['**/*.test.{ts,tsx}', '**/__tests__/**', 'src/test-setup.ts'],
    languageOptions: {
      globals: { ...globals.node },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      // Tests build synthetic markup/fixtures and use dynamic requires for lazy stubbing.
      '@typescript-eslint/no-require-imports': 'off',
      'jsx-a11y/no-static-element-interactions': 'off',
      'jsx-a11y/no-noninteractive-element-interactions': 'off',
      'jsx-a11y/click-events-have-key-events': 'off',
    },
  }
);
