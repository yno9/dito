import { expect, test } from "vitest";
import { decryptIdentityContainer, encryptIdentityContainer } from "../packages/wallet/src/wallet-backup.ts";

test("identity container is a Master-seed-wrapped JWE and preserves its manifest", async () => {
  const payload = {
    format: "did.md/identity-container",
    version: 1,
    manifest: { format: "did.md/identity-container", version: 1, identities: [] },
    files: { "metadata/device-bindings.json": [], "metadata/grants.json": { oauth: [] } },
  };
  const masterSeed = crypto.getRandomValues(new Uint8Array(32));
  const otherSeed = crypto.getRandomValues(new Uint8Array(32));
  const compact = await encryptIdentityContainer(payload, masterSeed);
  expect(compact.split(".")).toHaveLength(5);
  expect(await decryptIdentityContainer(compact, masterSeed)).toEqual(payload);
  await expect(decryptIdentityContainer(compact, otherSeed)).rejects.toThrow("incorrect");
});
