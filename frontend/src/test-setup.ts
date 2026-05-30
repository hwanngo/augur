import '@testing-library/jest-dom';
import './i18n';

// Create modal-root for portal tests
const modalRoot = document.createElement('div');
modalRoot.id = 'modal-root';
document.body.appendChild(modalRoot);
