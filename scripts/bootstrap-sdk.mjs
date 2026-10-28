// Build the SDK bundled into MCP from an immutable public source commit.
import { spawnSync } from 'node:child_process';
import { mkdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ref = '7e3571ebe82e28d7e9133642ca679bb67c1f1cf5';
const folder = resolve(root, '.deps/shieldlabs-node');
const deps = resolve(root, '.deps');
function run(command, args, cwd = root, capture = false) {
  const r = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: capture ? 'pipe' : 'inherit',
  });
  if (r.status !== 0) throw new Error(`${command} exited with ${r.status}`);
  return r.stdout?.trim();
}
mkdirSync(folder, { recursive: true });
if (!existsSync(resolve(folder, '.git'))) {
  run('git', ['init', folder]);
  run(
    'git',
    ['remote', 'add', 'origin', 'https://github.com/ShieldLabs-ai/shieldlabs-node.git'],
    folder,
  );
}
if (run('git', ['status', '--porcelain'], folder, true))
  throw new Error('SDK checkout has local changes');
run('git', ['fetch', '--depth=1', 'origin', ref], folder);
run('git', ['checkout', '--detach', 'FETCH_HEAD'], folder);
if (run('git', ['rev-parse', 'HEAD'], folder, true) !== ref)
  throw new Error('Unexpected SDK revision');
run('npm', ['ci', '--ignore-scripts'], folder);
run('npm', ['pack', '--pack-destination', deps], folder);
run('npm', [
  'install',
  '--no-save',
  '--package-lock=false',
  '--ignore-scripts',
  resolve(deps, 'shieldlabs-ai-node-1.2.0.tgz'),
]);
