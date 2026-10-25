// Test-only: a did:vh identity born at `<username>.<domain>` (its first document already names that place), in the
// shape the older tests built identities.
import { createGenesisEntry } from "../../packages/wallet/src/vh-ops.ts";
import type { ControllerKey } from "../../packages/wallet/src/keys.ts";

export function buildGenesis(args: {
  username?: string; domain: string; displayName?: string; root: ControllerKey; sign: ControllerKey; nextSpare: ControllerKey; api?: string;
  service?: { id: string; type: string; serviceEndpoint: string }[];
}) {
  return createGenesisEntry({
    src: `https://${args.username ? `${args.username}.` : ""}${args.domain}`,
    root: args.root, sign: args.sign, nextSpare: args.nextSpare, api: args.api, displayName: args.displayName, service: args.service,
  });
}
