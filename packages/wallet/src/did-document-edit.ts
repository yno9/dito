/**
 * Applying an approved `urn:did-core:document-edit:v1` authorization detail to a DID
 * document. The result is committed as a signed did:webvh log entry; that entry is the only
 * place the edit is published (there is no separate routing.json resource).
 */

/** Same DID URL, whether written relative ("#key-1") or absolute ("did:...#key-1"). */
export function sameDidDocumentReference(did: string, left: unknown, right: unknown): boolean {
  const absolute = (value: unknown) => typeof value === "string" && value.startsWith("#") ? `${did}${value}` : value;
  return absolute(left) === absolute(right);
}

export type DidDocumentEdit = {
  remove: string[];
  verificationMethods: { id: string }[];
  services: { id: string }[];
};

/** A copy of `state` with the edit applied: removals first, then add-or-replace by id. */
export function withDidDocumentEdit(state: any, edit: DidDocumentEdit): any {
  const next = JSON.parse(JSON.stringify(state));
  const isRemoved = (id: unknown) => edit.remove.some(removed => sameDidDocumentReference(state.id, id, removed));
  const methods = (Array.isArray(next.verificationMethod) ? next.verificationMethod : []).filter((value: any) => !isRemoved(value.id));
  for (const method of edit.verificationMethods) { const index = methods.findIndex((value: any) => sameDidDocumentReference(state.id, value.id, method.id)); if (index < 0) methods.push(method); else methods[index] = method; }
  next.verificationMethod = methods;
  const keyAgreement = (Array.isArray(next.keyAgreement) ? next.keyAgreement : []).filter((id: unknown) => !isRemoved(id));
  for (const method of edit.verificationMethods) if (!keyAgreement.some((id: unknown) => sameDidDocumentReference(state.id, id, method.id))) keyAgreement.push(method.id);
  if (keyAgreement.length) next.keyAgreement = keyAgreement;
  const services = (Array.isArray(next.service) ? next.service : []).filter((value: any) => !isRemoved(value.id));
  for (const service of edit.services) { const index = services.findIndex((value: any) => sameDidDocumentReference(state.id, value.id, service.id)); if (index < 0) services.push(service); else services[index] = service; }
  next.service = services;
  return next;
}
