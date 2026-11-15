// Логи для звіту й скріншотів: кожен крок — окремий яскравий рядок, байти — перші/останні 8 (повністю з --verbose).
const C = { reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m', red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', magenta: '\x1b[35m' };
const ROLE_COLOR = { CLIENT: C.cyan, SERVER: C.magenta, MITM: C.yellow };

function createLogger(role, { verbose = false, silent = false, tag = '', out = process.stdout, color } = {}) {
  const useColor = color ?? (Boolean(out.isTTY) || process.env.FORCE_COLOR === '1');
  const paint = (style, s) => (useColor ? style + s + C.reset : s);
  const R = role.toUpperCase();
  const rc = ROLE_COLOR[R] || '';
  const label = paint(C.bold + rc, `${R}${tag}`.padEnd(9));
  const ts = () => new Date().toISOString().slice(11, 23);
  const write = (s) => { if (!silent) out.write(`${s}\n`); };
  const details = (d) => {
    if (!d) return;
    for (const [k, v] of Object.entries(d)) write(`${' '.repeat(24)}${paint(C.dim, k.padEnd(20))} ${v}`);
  };
  const frag = (b) => {
    const buf = Buffer.isBuffer(b) ? b : Buffer.from(b);
    const h = buf.toString('hex');
    if (verbose || buf.length <= 16) return `${h} (${buf.length} Б)`;
    return `${h.slice(0, 16)}…${h.slice(-16)} (${buf.length} Б)`;
  };
  const line = (mark, style, m, d) => { write(`[${ts()}] ${label} ${paint(style, mark + m)}`); details(d); };
  return {
    verbose,
    frag,
    step: (n, title, d) => line(`━━ КРОК ${n}/7 ━━ `, C.bold + rc, title, d),
    info: (m, d) => line('', '', m, d),
    ok: (m, d) => line('✔ ', C.bold + C.green, m, d),
    warn: (m, d) => line('⚠ ', C.bold + C.yellow, m, d),
    err: (m, d) => line('✘ ', C.bold + C.red, m, d),
  };
}

module.exports = { createLogger };
