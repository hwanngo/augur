import { useTranslation } from 'react-i18next';
import Dialog from './Dialog';
import { useConfirmStore, type ConfirmOptions } from '../store/confirm';

/** Imperative promise-based confirm for pure yes/no destructive callsites. */
export function useConfirm(): (opts: ConfirmOptions) => Promise<boolean> {
  return useConfirmStore((s) => s.request);
}

/** Single mounted dialog instance that renders whatever confirm is pending. Mount once in AppShell. */
export function ConfirmHost() {
  const { t } = useTranslation();
  const open = useConfirmStore((s) => s.open);
  const options = useConfirmStore((s) => s.options);
  const dismiss = useConfirmStore((s) => s.dismiss);

  if (!options) return null;

  return (
    <Dialog
      open={open}
      title={options.title}
      message={options.message}
      variant={options.variant ?? 'destructive'}
      confirmLabel={options.confirmLabel ?? t('common.confirm')}
      onClose={() => dismiss(false)}
      onConfirm={() => dismiss(true)}
    />
  );
}
