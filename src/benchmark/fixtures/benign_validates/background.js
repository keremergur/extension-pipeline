// SAFE: only ever talks to its own allow-listed API host. An attacker-supplied URL (e.g. the mock
// server) fails the check, so NO request is made -> the verifier must not detect anything.
const ALLOWED_PREFIX = 'https://api.myextension.example/';

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.__fixture === 'fetch' && msg.url) {
    if (msg.url.startsWith(ALLOWED_PREFIX)) {
      fetch(msg.url);  // would be fine: own trusted endpoint
    } else {
      console.log('[fixture:benign_validates] refused untrusted URL', msg.url);
    }
  }
});
