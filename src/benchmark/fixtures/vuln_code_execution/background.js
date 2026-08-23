// VULNERABLE: dispatches attacker-named commands with attacker-supplied arguments in the privileged
// extension context, with no allow-listing of the caller. Modeling command-injection-style code
// execution: the page controls WHICH privileged action runs and WITH WHAT argument.
const COMMANDS = {
  // A privileged network action; the request is tagged with chrome.runtime.id (extension context).
  report: (arg) => {
    const u = arg + (arg.includes('?') ? '&' : '?') + 'ext=' + chrome.runtime.id;
    return fetch(u).then(() => console.log('[fixture:vuln_codeexec] ran report', u));
  },
};

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.__fixture === 'exec' && COMMANDS[msg.cmd]) {
    try {
      COMMANDS[msg.cmd](msg.arg);
    } catch (err) {
      console.log('[fixture:vuln_codeexec] command error', err);
    }
  }
});
