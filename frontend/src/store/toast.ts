import { create } from 'zustand';

export type ToastStatus = 'success' | 'error' | 'warning' | 'info';

interface ToastStore {
  message: string;
  status: ToastStatus;
  show: boolean;
  toast: (message: string, status?: ToastStatus) => void;
  dismiss: () => void;
}

export const useToastStore = create<ToastStore>((set) => ({
  message: '',
  status: 'success',
  show: false,
  toast: (message, status = 'success') => set({ message, status, show: true }),
  dismiss: () => set({ show: false }),
}));

/** Convenience hook so callsites read `const toast = useToast(); toast(msg, 'error');` */
export function useToast(): (message: string, status?: ToastStatus) => void {
  return useToastStore((s) => s.toast);
}
