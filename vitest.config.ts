import { configDefaults, defineConfig } from 'vitest/config';

// Root config for the top-level `npm test` (`vitest run`), which globs the
// whole monorepo. Without it, vitest discovers test files inside stale
// `.claude/worktrees/agent-*/` checkouts (pinned to old branches) and reports
// phantom failures that mask the real — green — suite. `**/dist/**` is in
// vitest's defaults; we keep it explicit so build output stays excluded even
// if the defaults change.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, '**/.claude/**', '**/dist/**'],
  },
});
