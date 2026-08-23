// Same web->extension bridge as the vulnerable fixture, so the control receives the identical attack.
window.addEventListener('message', (e) => {
  const d = e.data;
  if (d && d.__fixture === 'fetch' && d.url) {
    chrome.runtime.sendMessage({ __fixture: 'fetch', url: d.url });
  }
});
console.log('[fixture:benign_validates] content script ready');
