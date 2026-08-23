// Content-script bridge: forwards a window message from the page to the background service worker.
// This is the classic "unvalidated web -> extension" bridge that makes the extension reachable
// from attacker-controlled page script.
window.addEventListener('message', (e) => {
  const d = e.data;
  if (d && d.__fixture === 'fetch' && d.url) {
    chrome.runtime.sendMessage({ __fixture: 'fetch', url: d.url });
  }
});
console.log('[fixture:vuln_1way] content script ready');
