// VULNERABLE: fetches an attacker-controlled URL from the privileged extension context with NO
// validation. The request is tagged with chrome.runtime.id, which only the extension context can
// read -- this is the signal the mock server uses to attribute a request to the extension.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.__fixture === 'fetch' && msg.url) {
    const u = msg.url + (msg.url.includes('?') ? '&' : '?') + 'ext=' + chrome.runtime.id;
    fetch(u).then(() => console.log('[fixture:vuln_1way] fetched', u))
            .catch((err) => console.log('[fixture:vuln_1way] fetch error', err));
  }
});
