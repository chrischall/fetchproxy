#!/usr/bin/env node
import { runCli } from './main.js';

const io = {
  out: (line: string) => process.stdout.write(`${line}\n`),
  err: (line: string) => process.stderr.write(`${line}\n`),
};

process.exitCode = await runCli(process.argv.slice(2), io);
