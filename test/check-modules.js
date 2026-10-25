// 用 Surge Mac 自带的离线语言服务器检查模块文件（含 #!arguments 头部）。
// 运行：node test/check-modules.js；需要装有 Surge Mac，不需要 Surge 在运行。
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const CLI = '/Applications/Surge.app/Contents/Applications/surge-cli';
if (!fs.existsSync(CLI)) {
  console.log('跳过：本机没有 Surge Mac 的 surge-cli');
  process.exit(0);
}

const root = path.join(__dirname, '..');
const files = process.argv.slice(2).length
  ? process.argv.slice(2).map(f => path.resolve(f))
  : fs.readdirSync(root).filter(f => f.endsWith('.sgmodule')).map(f => path.join(root, f));

const lsp = spawn(CLI, ['lsp']);
const send = m => {
  const s = JSON.stringify(m);
  lsp.stdin.write(`Content-Length: ${Buffer.byteLength(s)}\r\n\r\n${s}`);
};
const diags = {};
let buf = Buffer.alloc(0);
lsp.stdout.on('data', d => {
  buf = Buffer.concat([buf, d]);
  for (;;) {
    const i = buf.indexOf('\r\n\r\n');
    if (i < 0) break;
    const len = Number(/Content-Length: (\d+)/i.exec(buf.slice(0, i).toString())[1]);
    if (buf.length < i + 4 + len) break;
    const msg = JSON.parse(buf.slice(i + 4, i + 4 + len).toString());
    buf = buf.slice(i + 4 + len);
    if (msg.method === 'textDocument/publishDiagnostics') diags[msg.params.uri] = msg.params.diagnostics;
  }
});

send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { processId: process.pid, rootUri: null, capabilities: {} } });
send({ jsonrpc: '2.0', method: 'initialized', params: {} });
files.forEach(f => send({ jsonrpc: '2.0', method: 'textDocument/didOpen', params: { textDocument: { uri: 'file://' + f, languageId: 'surge-module', version: 1, text: fs.readFileSync(f, 'utf8') } } }));

setTimeout(() => {
  let errors = 0;
  files.forEach(f => {
    const list = diags['file://' + f];
    if (!list) {
      errors++;
      console.log(`✖ ${path.basename(f)}：语言服务器没有返回结果`);
      return;
    }
    const bad = list.filter(d => d.severity === 1);
    errors += bad.length;
    console.log(`${bad.length ? '✖' : '✔'} ${path.basename(f)}`);
    list.forEach(d => console.log(`    第 ${d.range.start.line + 1} 行 [${['', '错误', '警告', '信息', '提示'][d.severity] || d.severity}] ${d.message}`));
  });
  lsp.kill();
  process.exit(errors ? 1 : 0);
}, 4000);
