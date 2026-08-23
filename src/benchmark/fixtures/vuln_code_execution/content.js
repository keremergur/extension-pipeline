// Forwards an attacker-named command + argument from the page into the privileged background.
window.addEventListener('message', (e) => {
  const d = e.data;
  if (d && d.__fixture === 'exec' && d.cmd) {
    chrome.runtime.sendMessage({ __fixture: 'exec', cmd: d.cmd, arg: d.arg });
  }
});
console.log('[fixture:vuln_codeexec] content script ready');
