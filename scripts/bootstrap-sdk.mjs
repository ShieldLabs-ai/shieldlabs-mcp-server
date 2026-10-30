// Verify the exact published SDK that tsup bundles into the executable.
// npm ci installs the immutable package and verifies package-lock.json integrity.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const metadata = require('@shieldlabs-ai/node/package.json');
if (metadata.version !== '1.3.2') throw new Error('Expected @shieldlabs-ai/node 1.3.2');
if (Object.keys(metadata.dependencies ?? {}).length !== 0)
  throw new Error('Bundled SDK must have a dependency-free runtime');
console.log('Verified published @shieldlabs-ai/node ' + metadata.version);
