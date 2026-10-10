#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { run } from "./src/cli.ts";

const code = await run(process.argv.slice(2), {
  out: text => process.stdout.write(text),
  err: text => process.stderr.write(text),
  env: process.env,
  prompt: process.stdin.isTTY
    ? async question => {
        const rl = createInterface({ input: process.stdin, output: process.stderr });
        try { return await rl.question(question); } finally { rl.close(); }
      }
    : undefined,
});
process.exit(code);
