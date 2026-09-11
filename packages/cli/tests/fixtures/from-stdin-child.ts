/**
 * Child for the real-pipe `--from-stdin` test. Runs the parser with EVERY
 * dependency defaulted, so the stdin reader under test is the one production
 * uses, reading a real pipe off a real fd 0. Prints the parsed set as JSON.
 */
import { parseCliArgs } from '../../src/args.js';

const cmd = parseCliArgs(['write-cookies', '-p', 'x', '--from-stdin']);
process.stdout.write(JSON.stringify((cmd as { cookies: Record<string, string> }).cookies));
