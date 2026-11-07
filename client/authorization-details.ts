// The OAuth `authorization_details` (RFC 9396) the wallet understands, validated
// before anything is shown or signed. Pure functions: no DOM, no wallet state.
import { assertEditSparesMethods, assertEndpointRemovals, assertServiceEndpointMode, assertVerificationMethodEdit, type DidDocumentEdit } from "../packages/wallet/src/did-document-edit.ts";
import { ROOT_KEY_FRAGMENT } from "../packages/vh/src/index.ts";

export const DID_DOCUMENT_EDIT_DETAIL = "urn:did-core:document-edit:v1";
export const KEY_AUTHORIZATION_DETAIL = "urn:did.md:key-authorization:v1";
export const DERIVED_SECRET_DETAIL = "urn:did.md:derived-secret:v1";

// Request JSON is checked field by field below; until then it is untyped.
type Detail = Record<string, any>;

function detailObject(value: unknown, label: string): Detail {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid.`);
  return value as Detail;
}

function detailKeys(value: Detail, keys: string[], label: string) {
  if (Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) throw new Error(`${label} has unexpected fields.`);
}

export function oauthAuthorizationDetails(value: unknown): Detail[] {
  if (value === null) return [];
  if (typeof value !== "string" || value.length < 2 || value.length > 16_384) throw new Error("The OAuth authorization details are invalid.");
  let details: unknown;
  try { details = JSON.parse(value); } catch { throw new Error("The OAuth authorization details are invalid."); }
  if (!Array.isArray(details) || !details.length || details.length > 16) throw new Error("The OAuth authorization details are invalid.");
  for (const [index, detail] of details.entries()) {
    const object = detailObject(detail, `Authorization detail ${index + 1}`);
    if (typeof object.type !== "string" || !/^[A-Za-z][A-Za-z0-9:._/-]{0,127}$/.test(object.type)) throw new Error("The OAuth authorization details are invalid.");
  }
  return details;
}

export function didDocumentEditDetail(details: Detail[], did: string): Detail | undefined {
  const matches = details.filter(detail => detail.type === DID_DOCUMENT_EDIT_DETAIL);
  if (!matches.length) return undefined;
  if (matches.length !== 1) throw new Error("The DID document edit request is duplicated.");
  const detail = detailObject(matches[0], "The DID document edit request");
  const detailShape = ["type", "services", "verificationMethods", "remove", ...(detail.serviceKeyBindings === undefined ? [] : ["serviceKeyBindings"]), ...(detail.removeEndpoints === undefined ? [] : ["removeEndpoints"])];
  detailKeys(detail, detailShape, "The DID document edit request");
  if (!Array.isArray(detail.services) || !Array.isArray(detail.verificationMethods) || !Array.isArray(detail.remove)
    || detail.services.length > 64 || detail.verificationMethods.length > 64 || detail.remove.length > 128) throw new Error("The DID document edit request is invalid.");
  // DID Core permits a fragment-only relative DID URL (for example
  // `#didcomm`) for resources in this same DID Document.
  const validId = (id: unknown): boolean => typeof id === "string" && (/^#[^\s#]+$/.test(id)
    || ((did ? id.startsWith(`${did}#`) : id.startsWith("did:vh:")) && id.includes("#") && !/[\s#]/.test(id.slice(id.indexOf("#") + 1))));
  // DID Core allows serviceEndpoint to be a string, a map, or a set of
  // strings and/or maps -- accept all three shapes, not just the first two.
  const validEndpoint = (endpoint: unknown): boolean => typeof endpoint === "string" || (!!endpoint && typeof endpoint === "object" && !Array.isArray(endpoint));
  for (const value of detail.services) {
    const service = detailObject(value, "DID service"); detailKeys(service, ["id", "type", "serviceEndpoint", ...(service.endpointMode === undefined ? [] : ["endpointMode"])], "DID service");
    const endpointValid = Array.isArray(service.serviceEndpoint)
      ? service.serviceEndpoint.length > 0 && service.serviceEndpoint.length <= 8 && service.serviceEndpoint.every(validEndpoint)
      : validEndpoint(service.serviceEndpoint);
    if (!validId(service.id) || typeof service.type !== "string" || !service.type.trim() || !endpointValid) throw new Error("A DID service is invalid.");
    assertServiceEndpointMode(service);
  }
  if (detail.removeEndpoints !== undefined) assertEndpointRemovals(detail.removeEndpoints, validId);
  // controller is force-set to the Wallet's own loaded DID below, never
  // trusted from the relying party's request -- a verification method
  // published into THIS identity's own DID Document must be controlled by
  // THIS identity, regardless of what a relying party (which doesn't
  // necessarily know the DID yet when it builds this request) claims.
  detail.verificationMethods = detail.verificationMethods.map((value: unknown) => {
    const method = detailObject(value, "DID verification method");
    detailKeys(method, ["id", "type", "controller", "publicKeyMultibase", ...(method.relationships === undefined ? [] : ["relationships"]), ...(method.mode === undefined ? [] : ["mode"])], "DID verification method");
    if (!validId(method.id) || typeof method.type !== "string" || !method.type.trim() || typeof method.controller !== "string" || typeof method.publicKeyMultibase !== "string") throw new Error("A DID verification method is invalid.");
    assertVerificationMethodEdit(method);
    return { ...method, controller: did };
  });
  // The identity's own Root key is this Wallet's, never a relying party's to
  // replace or remove: without it the identity can no longer be opened.
  assertEditSparesMethods(detail as DidDocumentEdit, did, [ROOT_KEY_FRAGMENT]);
  if (detail.serviceKeyBindings !== undefined) {
    if (!Array.isArray(detail.serviceKeyBindings) || detail.serviceKeyBindings.length > detail.services.length) throw new Error("The DID service/key bindings are invalid.");
    const serviceIds = new Set(detail.services.map((service: Detail) => service.id));
    const keyIds = new Set(detail.verificationMethods.map((method: Detail) => method.id));
    const seenServices = new Set<unknown>();
    for (const value of detail.serviceKeyBindings) {
      const binding = detailObject(value, "DID service/key binding");
      detailKeys(binding, ["serviceId", "keyIds"], "DID service/key binding");
      if (!serviceIds.has(binding.serviceId) || seenServices.has(binding.serviceId) || !Array.isArray(binding.keyIds)
        || binding.keyIds.some((id: unknown) => !keyIds.has(id)) || new Set(binding.keyIds).size !== binding.keyIds.length) throw new Error("The DID service/key bindings are invalid.");
      seenServices.add(binding.serviceId);
    }
  }
  if (detail.remove.some((id: unknown) => !validId(id)) || new Set([...detail.services.map((x: Detail) => x.id), ...detail.verificationMethods.map((x: Detail) => x.id), ...detail.remove]).size !== detail.services.length + detail.verificationMethods.length + detail.remove.length) throw new Error("The DID document edit contains duplicate or invalid ids.");
  return detail;
}

export function keyAuthorizationDetail(details: Detail[]): Detail | undefined {
  const matches = details.filter(detail => detail.type === KEY_AUTHORIZATION_DETAIL);
  if (!matches.length) return undefined;
  if (matches.length !== 1) throw new Error("The key authorization request is duplicated.");
  const detail = detailObject(matches[0], "The key authorization request");
  detailKeys(detail, ["type", "subject", "publicKey", "purposes"], "The key authorization request");
  const key = detailObject(detail.publicKey, "The authorized public key");
  detailKeys(key, ["type", "publicKeyMultibase"], "The authorized public key");
  if (!/^urn:uuid:[0-9a-f-]{36}$/i.test(detail.subject) || typeof key.type !== "string" || !key.type.trim()
    || typeof key.publicKeyMultibase !== "string" || !key.publicKeyMultibase.startsWith("z")
    || !Array.isArray(detail.purposes) || !detail.purposes.length || detail.purposes.length > 16
    || detail.purposes.some((value: unknown) => typeof value !== "string" || !value.trim() || value.length > 64)) throw new Error("The key authorization request is invalid.");
  return detail;
}

// A relying party's own devices sometimes need to agree on a value (e.g. a
// storage locator) without that value ever being published anywhere public.
// Rather than trust an RP-supplied secret (which would need transporting
// over the very channel it's trying to keep private), the Wallet derives it
// itself from the identity's Root private key and hands back only the
// result -- see deriveWalletSecret in packages/wallet/src/keys.ts. purpose/context are
// domain-separation labels the RP supplies; several distinct requests may
// appear in one authorization, so (unlike the "exactly one" detail types
// above) this collects every match.
export function derivedSecretDetails(details: Detail[]): Detail[] {
  const matches = details.filter(detail => detail.type === DERIVED_SECRET_DETAIL);
  if (matches.length > 8) throw new Error("Too many derived secret requests.");
  const seen = new Set<string>();
  return matches.map(value => {
    const detail = detailObject(value, "The derived secret request");
    const shape = ["type", "purpose", ...(detail.context === undefined ? [] : ["context"])];
    detailKeys(detail, shape, "The derived secret request");
    if (typeof detail.purpose !== "string" || !/^[A-Za-z][A-Za-z0-9:._-]{0,127}$/.test(detail.purpose)) throw new Error("The derived secret purpose is invalid.");
    if (detail.context !== undefined && (typeof detail.context !== "string" || !detail.context.trim() || detail.context.length > 2048)) throw new Error("The derived secret context is invalid.");
    const key = `${detail.purpose}\u0000${detail.context ?? ""}`;
    if (seen.has(key)) throw new Error("The derived secret requests are duplicated.");
    seen.add(key);
    return detail;
  });
}
