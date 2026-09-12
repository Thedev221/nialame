// Petit pont Node.js : lit du code JS/TS sur stdin, retourne son AST
// (format ESTree, via esprima) en JSON sur stdout. Invoqué en
// sous-processus depuis scanner_js.py — aucune autre responsabilité.
const esprima = require("esprima");

let source = "";
process.stdin.setEncoding("utf8");

process.stdin.on("data", (chunk) => {
  source += chunk;
});

process.stdin.on("end", () => {
  try {
    const ast = esprima.parseModule(source, {
      loc: true,
      range: true,
      tolerant: false,
    });
    process.stdout.write(JSON.stringify(ast));
    process.exit(0);
  } catch (err) {
    process.stderr.write(JSON.stringify({ error: err.message }));
    process.exit(1);
  }
});
