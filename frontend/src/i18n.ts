import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import en from './locales/en.json';
import vi from './locales/vi.json';

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      vi: { translation: vi },
    },
    fallbackLng: 'en',
    supportedLngs: ['en', 'vi'],
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'fs_lang',
      caches: ['localStorage'],
    },
    interpolation: {
      escapeValue: false,
    },
  });

// Keep <html lang> in sync with the active language (a11y + SEO + correct
// hyphenation/voice-over). Normalize e.g. 'en-US' → 'en'.
function syncHtmlLang(lng: string | undefined): void {
  if (typeof document === 'undefined') return;
  const lang = (lng ?? i18n.language ?? 'en').split('-')[0];
  document.documentElement.lang = lang;
}

syncHtmlLang(i18n.language);
i18n.on('languageChanged', syncHtmlLang);

export default i18n;
