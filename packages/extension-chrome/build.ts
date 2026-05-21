import { build } from 'esbuild';
import { mkdir, copyFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const OUT = 'dist';

async function main(): Promise<void> {
  await mkdir(OUT, { recursive: true });
  await mkdir(join(OUT, 'icons'), { recursive: true });

  // Bundle each entry point.
  await build({
    entryPoints: {
      background: '../extension-core/src/background.ts',
      content: '../extension-core/src/content.ts',
      popup: '../extension-core/src/popup/popup.ts',
    },
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: 'chrome120',
    outdir: OUT,
    sourcemap: 'inline',
  });

  // Copy static files.
  await copyFile('manifest.json', join(OUT, 'manifest.json'));
  await copyFile('../extension-core/src/popup/popup.html', join(OUT, 'popup.html'));
  // Icons (placeholder solid-color PNGs; replace with real artwork later)
  for (const f of await readdir('icons')) {
    await copyFile(join('icons', f), join(OUT, 'icons', f));
  }
  console.log('extension-chrome built →', OUT);
}

void main();
