import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

// Silence non-critical console output in production — console.error still runs
// so genuine crashes stay visible in the browser devtools and error reporters.
if (process.env.NODE_ENV === 'production') {
  const noop = () => {};
  ['log', 'debug', 'info', 'warn'].forEach(k => { console[k] = noop; });
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
