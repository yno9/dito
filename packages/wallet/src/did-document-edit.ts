/**
 * Applying an approved `urn:did-core:document-edit:v1` authorization detail to a DID
 * document. The result is committed as a signed did:webvh log entry; that entry is the only
 * place the edit is published (there is no separate routing.json resource).
 *
 * A service can carry several endpoints (DID Core: a `serviceEndpoint` that is a set of
 * strings and/or maps). Two relying parties, or two devices of one relying party, then
 * share one service, and replacing it wholesale would drop whatever the other one put
 * there. So an edit may address the endpoints of a service one by one:
 *
 *   - `endpointMode: "merge"` on a service adds its endpoints to the service already in
 *     the document instead of replacing it (default and `"replace"`: replace by id).
 *   - `removeEndpoints` removes the endpoints of a service that match given properties.
 *
 * The merge happens here, at approval time, against the document as it is then -- not
 * against a copy the relying party read earlier, and without it having to know the DID.
 */

/** Same DID URL, whether written relative ("#key-1") or absolute ("did:...#key-1"). */
export function sameDidDocumentReference(did: string, left: unknown, right: unknown): boolean {
  const absolute = (value: unknown) => typeof value === "string" && value.startsWith("#") ? `${did}${value}` : value;
  return absolute(left) === absolute(right);
}

export type DidDocumentEndpoint = string | Record<string, unknown>;

export type DidDocumentService = {
  id: string;
  type?: string;
  serviceEndpoint?: DidDocumentEndpoint | DidDocumentEndpoint[];
  /** Absent or "replace": the service replaces the one with this id. "merge": its endpoints are added to it. */
  endpointMode?: "replace" | "merge";
};

/** Removes, from the service `serviceId`, every endpoint whose properties equal all of `match`. */
export type DidDocumentEndpointRemoval = { serviceId: string; match: Record<string, unknown> };

/** DID Core's verification relationships: what a verification method is authorized for. */
export const VERIFICATION_RELATIONSHIPS = ["authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"] as const;
export type VerificationRelationship = typeof VERIFICATION_RELATIONSHIPS[number];

/**
 * A verification method to add, with how to add it. Neither field is published: they
 * say what to do with the method, which is published without them.
 *
 *   - `relationships`: the verification relationships to reference it from. Absent:
 *     `keyAgreement` alone (what every edit meant before the field existed).
 *   - `mode`: absent or `"replace"` adds it, or replaces the method with the same id
 *     (and its references). `"ifAbsent"` adds it only when the document has no method
 *     with that id yet, and otherwise leaves the document as it is -- so several
 *     parties can each ask for "the" method of some id and the first one approved wins.
 */
export type DidDocumentEditMethod = { id: string; relationships?: VerificationRelationship[]; mode?: "replace" | "ifAbsent"; [property: string]: unknown };

export type DidDocumentEdit = {
  remove: string[];
  verificationMethods: DidDocumentEditMethod[];
  services: DidDocumentService[];
  removeEndpoints?: DidDocumentEndpointRemoval[];
};

/**
 * What identifies an endpoint within its service: a string endpoint is its own URI, a map
 * endpoint is identified by its `uri`. An endpoint with neither has no identity and is
 * never merged into -- it is kept untouched where it already is.
 */
export function endpointIdentity(endpoint: unknown): string | undefined {
  if (typeof endpoint === "string") return endpoint;
  if (endpoint && typeof endpoint === "object" && !Array.isArray(endpoint) && typeof (endpoint as { uri?: unknown }).uri === "string") return (endpoint as { uri: string }).uri;
  return undefined;
}

const endpointList = (endpoint: unknown): unknown[] => endpoint === undefined ? [] : Array.isArray(endpoint) ? endpoint : [endpoint];

/** A single endpoint is stored as itself, several as a set -- the shape a service had before it was ever merged. */
const endpointValue = (endpoints: unknown[]): unknown => endpoints.length === 1 ? endpoints[0] : endpoints;

const sameJson = (left: unknown, right: unknown): boolean => JSON.stringify(left) === JSON.stringify(right);

/** True when every property of `match` is present, with an equal value, on the endpoint (a string endpoint has only `uri`). */
function endpointMatches(endpoint: unknown, match: Record<string, unknown>): boolean {
  const properties: Record<string, unknown> = typeof endpoint === "string" ? { uri: endpoint } : endpoint && typeof endpoint === "object" ? endpoint as Record<string, unknown> : {};
  const keys = Object.keys(match);
  return keys.length > 0 && keys.every(key => key in properties && sameJson(properties[key], match[key]));
}

/** `existing` endpoints plus `incoming`: an incoming endpoint replaces the existing one with the same identity, else is appended. */
export function mergeServiceEndpoints(existing: unknown, incoming: unknown): unknown {
  const merged = [...endpointList(existing)];
  for (const endpoint of endpointList(incoming)) {
    const identity = endpointIdentity(endpoint);
    const index = identity === undefined ? -1 : merged.findIndex(value => endpointIdentity(value) === identity);
    if (index < 0) merged.push(endpoint); else merged[index] = endpoint;
  }
  return endpointValue(merged);
}

/** A copy of `state` with the edit applied: removals first (whole entries, then endpoints), then add-or-replace (or merge) by id. */
export function withDidDocumentEdit(state: any, edit: DidDocumentEdit): any {
  const next = JSON.parse(JSON.stringify(state));
  const isRemoved = (id: unknown) => edit.remove.some(removed => sameDidDocumentReference(state.id, id, removed));
  const methods = (Array.isArray(next.verificationMethod) ? next.verificationMethod : []).filter((value: any) => !isRemoved(value.id));
  // Every relationship loses its references to a removed method.
  const relationships = new Map<VerificationRelationship, unknown[]>(VERIFICATION_RELATIONSHIPS.map(name => [name, (Array.isArray(next[name]) ? next[name] : []).filter((reference: unknown) => !isRemoved(typeof reference === "object" && reference ? (reference as { id?: unknown }).id : reference))]));
  for (const { relationships: requested, mode, ...method } of edit.verificationMethods) {
    const index = methods.findIndex((value: any) => sameDidDocumentReference(state.id, value.id, method.id));
    if (mode === "ifAbsent" && index >= 0) continue;
    if (index < 0) methods.push(method); else methods[index] = method;
    // The method is referenced from exactly the relationships asked for.
    for (const [name, references] of relationships) {
      const kept = references.filter(reference => !sameDidDocumentReference(state.id, reference, method.id));
      if ((requested ?? ["keyAgreement"]).includes(name)) kept.push(method.id);
      relationships.set(name, kept);
    }
  }
  next.verificationMethod = methods;
  // A relationship the document had stays (possibly empty); one it lacked appears only when something references it.
  for (const [name, references] of relationships) if (references.length || Array.isArray(state[name])) next[name] = references;
  let services = (Array.isArray(next.service) ? next.service : []).filter((value: any) => !isRemoved(value.id));
  for (const removal of edit.removeEndpoints ?? []) {
    services = services.flatMap((service: any) => {
      if (!sameDidDocumentReference(state.id, service.id, removal.serviceId)) return [service];
      const kept = endpointList(service.serviceEndpoint).filter(endpoint => !endpointMatches(endpoint, removal.match));
      return kept.length ? [{ ...service, serviceEndpoint: endpointValue(kept) }] : [];
    });
  }
  for (const { endpointMode, ...service } of edit.services) {
    const index = services.findIndex((value: any) => sameDidDocumentReference(state.id, value.id, service.id));
    // A service of another type is not the same service: merging only extends one of the same type.
    const merging = endpointMode === "merge" && index >= 0 && services[index].type === service.type;
    if (index < 0) services.push(service);
    else services[index] = merging ? { ...service, serviceEndpoint: mergeServiceEndpoints(services[index].serviceEndpoint, service.serviceEndpoint) } : service;
  }
  next.service = services;
  return next;
}

/** Checks how one verification method of an edit request is to be added; throws when it is not usable. */
export function assertVerificationMethodEdit(method: { relationships?: unknown; mode?: unknown }): void {
  if (method.mode !== undefined && method.mode !== "replace" && method.mode !== "ifAbsent") throw new Error("A DID verification method mode is invalid.");
  if (method.relationships === undefined) return;
  const values = method.relationships;
  if (!Array.isArray(values) || !values.length || new Set(values).size !== values.length || !values.every(value => (VERIFICATION_RELATIONSHIPS as readonly unknown[]).includes(value))) throw new Error("A DID verification method's relationships are invalid.");
}

/** Throws when the edit would replace or remove any of `protectedIds` (methods the
 * document's controller keeps for itself, such as its own Root key). */
export function assertEditSparesMethods(edit: Pick<DidDocumentEdit, "remove" | "verificationMethods">, did: string, protectedIds: readonly string[]): void {
  const touches = (id: unknown) => protectedIds.some(protectedId => sameDidDocumentReference(did, id, protectedId));
  if (edit.verificationMethods.some(method => touches(method.id)) || edit.remove.some(touches)) throw new Error("The DID document edit may not replace or remove a key its controller keeps.");
}

/** Checks the endpoint-addressing fields of one service of an edit request; throws when they are not usable. */
export function assertServiceEndpointMode(service: { endpointMode?: unknown; serviceEndpoint?: unknown }): void {
  if (service.endpointMode !== undefined && service.endpointMode !== "replace" && service.endpointMode !== "merge") throw new Error("A DID service endpoint mode is invalid.");
  // Merging matches endpoints by identity, so every endpoint to merge has to have one.
  if (service.endpointMode === "merge" && !endpointList(service.serviceEndpoint).every(endpoint => endpointIdentity(endpoint) !== undefined)) throw new Error("A DID service endpoint to merge has no uri.");
}

/** Checks the `removeEndpoints` list of an edit request; throws when it is not usable. */
export function assertEndpointRemovals(removals: unknown, validServiceId: (id: unknown) => boolean): void {
  if (!Array.isArray(removals) || removals.length > 64) throw new Error("The DID service endpoint removals are invalid.");
  for (const removal of removals) {
    const fields = removal && typeof removal === "object" && !Array.isArray(removal) ? removal as Record<string, unknown> : undefined;
    const match = fields?.match && typeof fields.match === "object" && !Array.isArray(fields.match) ? fields.match as Record<string, unknown> : undefined;
    if (!fields || Object.keys(fields).sort().join(",") !== "match,serviceId" || !match || !validServiceId(fields.serviceId) || !Object.keys(match).length || Object.keys(match).length > 8) throw new Error("A DID service endpoint removal is invalid.");
  }
}
