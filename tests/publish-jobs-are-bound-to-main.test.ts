import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const WORKFLOWS = join(ROOT, '.github', 'workflows');

/**
 * npm Trusted Publishing trusts a workflow FILENAME in this repository. With
 * nothing else bound, anyone who can push a branch and dispatch a workflow can
 * publish that branch's code as `@fetchproxy/*` under valid provenance —
 * `release-please-next.yml` is dispatch-only and checks out `github.ref`, and
 * `release-please.yml`'s publish job is reachable through its dispatch input.
 *
 * So every job that runs `npm publish` must (a) run in the `npm-publish`
 * environment, whose deployment-branch policy (configured on GitHub, and named
 * in each package's Trusted Publisher on npm) is what actually enforces "main
 * only" — a guard in the YAML alone is editable by whoever controls the branch
 * — and (b) carry an explicit `refs/heads/main` guard, so a dispatch from any
 * other ref is skipped visibly instead of failing at the environment gate.
 */
interface Job {
  file: string;
  name: string;
  body: string;
}

function jobsOf(file: string): Job[] {
  const text = readFileSync(join(WORKFLOWS, file), 'utf8');
  const start = text.search(/^jobs:\s*$/m);
  if (start < 0) return [];
  const lines = text.slice(start).split('\n').slice(1);
  const jobs: Job[] = [];
  let current: Job | null = null;
  for (const line of lines) {
    const header = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (header) {
      current = { file, name: header[1]!, body: '' };
      jobs.push(current);
      continue;
    }
    if (current) current.body += line + '\n';
  }
  return jobs;
}

const PUBLISH_JOBS: Job[] = readdirSync(WORKFLOWS)
  .filter((f) => /\.ya?ml$/.test(f))
  .flatMap(jobsOf)
  .filter((j) => /^\s*npm publish\b/m.test(j.body));

describe('npm publish jobs are bound to main', () => {
  it('found the publish jobs', () => {
    // Guard against a parsing bug emptying the sweep and making every case
    // below vacuous.
    expect(PUBLISH_JOBS.map((j) => `${j.file}:${j.name}`).sort()).toEqual([
      'release-please-next.yml:publish-rc',
      'release-please.yml:publish',
    ]);
  });

  it.each(PUBLISH_JOBS.map((j) => [`${j.file}:${j.name}`, j] as const))(
    '%s runs in the npm-publish environment',
    (_label, job) => {
      expect(job.body).toMatch(/^ {4}environment:\s*npm-publish\s*$/m);
    },
  );

  it.each(PUBLISH_JOBS.map((j) => [`${j.file}:${j.name}`, j] as const))(
    '%s is guarded to refs/heads/main',
    (_label, job) => {
      const guard = /^ {4}if:\s*(.+)$/m.exec(job.body);
      expect(guard?.[1]).toContain("github.ref == 'refs/heads/main'");
    },
  );
});
