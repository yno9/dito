// Shared test helper for PLAN3: builds
// a capability credential in the VC-DM 2.0 envelope the server now expects
// (see verifiedOauthCapability in server/server.ts), and wraps it in the
// OID4VP DCQL vp_token response shape. Centralized here so the wire shape
// only needs to change in one place if it changes again.
import { createDataIntegrityProof } from "../../packages/wallet/src/did-webvh.ts";

export async function buildCapabilityCredential(args: {
  privateKey: Uint8Array; did: string; verificationMethod: string; capabilityType: string;
  audience: string; scope: string[]; issuedAt: string; expiresAt: string;
  deviceJkt?: string; authorizationDetails?: unknown[]; created?: string;
}): Promise<any> {
  const unsigned = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential", args.capabilityType],
    issuer: args.did,
    credentialSubject: {
      audience: args.audience, scope: args.scope, issuedAt: args.issuedAt, expiresAt: args.expiresAt,
      ...(args.deviceJkt !== undefined ? { deviceJkt: args.deviceJkt } : {}),
      ...(args.authorizationDetails !== undefined ? { authorizationDetails: args.authorizationDetails } : {}),
    },
  };
  const proof = await createDataIntegrityProof(unsigned, { privateKey: args.privateKey, verificationMethod: args.verificationMethod, proofPurpose: "authentication", created: args.created ?? args.issuedAt });
  return { ...unsigned, proof };
}

/** Wraps a single capability credential in the vp_token DCQL response shape (one fixed query id, see CAPABILITY_DCQL_QUERY_ID in server/server.ts). */
export function vpToken(credential: unknown) {
  return { capability: [credential] };
}
