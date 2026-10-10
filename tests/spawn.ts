import { spawn as nodeSpawn } from "node:child_process";

export interface SpawnOptions {
  cmd: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdout?: "ignore" | "inherit";
  stderr?: "ignore" | "inherit";
}

/** Child process with `kill()` and an `exited` promise that resolves on exit. */
export function spawn(options: SpawnOptions) {
  const [command, ...rest] = options.cmd;
  const args = rest;
  const child = nodeSpawn(command!, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: ["ignore", options.stdout ?? "inherit", options.stderr ?? "inherit"],
  });
  const exited = new Promise<number | null>(resolve => child.once("exit", code => resolve(code)));
  return { kill: () => child.kill(), exited };
}
export type Spawned = ReturnType<typeof spawn>;
