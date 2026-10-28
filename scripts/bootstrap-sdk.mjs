// Build the SDK bundled into MCP from an immutable public source commit.
import { spawnSync } from 'node:child_process';
import { mkdirSync, existsSync, readFileSync, rmSync, cpSync, copyFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ref = '7e3571ebe82e28d7e9133642ca679bb67c1f1cf5';
const folder = resolve(root, '.deps/shieldlabs-node');
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
run('npm', ['run', 'build'], folder);
const metadata = JSON.parse(readFileSync(resolve(folder, 'package.json'), 'utf8'));
if (Object.keys(metadata.dependencies ?? {}).length !== 0)
  throw new Error('SDK staging requires a dependency-free runtime');
// Stage the verified build directly: the SDK has no runtime dependencies. Avoid npm 10's
// Arborist failure when adding an extraneous local tarball to an already-installed tree.
const target = resolve(root, 'node_modules/@shieldlabs-ai/node');
rmSync(target, { recursive: true, force: true });
mkdirSync(target, { recursive: true });
cpSync(resolve(folder, 'dist'), resolve(target, 'dist'), { recursive: true });
for (const file of ['package.json', 'LICENSE'])
  copyFileSync(resolve(folder, file), resolve(target, file));
console.log('Staged @shieldlabs-ai/node from ' + ref);
