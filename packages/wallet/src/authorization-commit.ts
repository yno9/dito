/**
 * The order of side effects when the user approves an OAuth/OID4VP request.
 *
 * Approving touches two worlds: the other side (the bridge issues a code, or the relying party
 * takes a direct_post) and this browser (grant card, device binding, app metadata). Nothing can
 * make both atomic, but the local half can be made to follow the remote half instead of
 * contradicting it: bookkeeping is written only after the other side accepted, and before the
 * page navigates away -- so a request that failed leaves no "Active" card behind.
 *
 *   accept()   remote, may fail -> nothing local has been written yet
 *   persist()  local; runs only once accept() succeeded; if it fails, the relying party is never
 *              told (an orphaned code just expires) and the error is shown
 *   navigate() hands the result to the relying party; leaves the page, so it is always last
 *
 * What cannot be known here: whether the relying party's *own* later checks pass (e.g. the PDS
 * verifying the DID document after the redirect). That needs a confirmation channel, not ordering.
 */
export interface AuthorizationDelivery<T> {
  accept(): Promise<T>;
  persist(accepted: T): Promise<void>;
  navigate(accepted: T): void;
}

export async function commitAuthorization<T>(delivery: AuthorizationDelivery<T>): Promise<void> {
  const accepted = await delivery.accept();
  await delivery.persist(accepted);
  delivery.navigate(accepted);
}
