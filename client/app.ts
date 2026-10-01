import {
  buildGenesis,
  controllerFromPrivate,
  createKeyAuthorizationCredentialWire,
  createDataIntegrityProof,
  createSelfIssuedIdToken,
  deriveWalletSecret,
  createIdentityMaterial,
  preparePortableImport,
  preparePreRotatedUpdate,
  rootFromMasterSeed,
  seedFromMnemonic,
  spareFromMasterSeed,
  verifyRequestObjectJws,
} from "../packages/wallet/src/did-webvh.ts";
import {
  createPasskeyProtector,
  clearLocalIdentityState,
  exportIdentityKeyringRecord,
  listStoredIdentities,
  listWalletDeviceBindings,
  listWalletOAuthGrants,
  readDidLogSnapshot,
  readPortableApplications,
  readStoredIdentity,
  restoreIdentityKeyringRecord,
  saveMasterStoredIdentity,
  savePasswordStoredIdentity,
  savePortableApplications,
  saveWalletDeviceBinding,
  saveWalletOAuthGrant,
  deleteWalletOAuthGrants,
  saveDidLogSnapshot,
  unlockMasterStoredIdentity,
  unlockPasswordStoredIdentity,
  updatePasswordStoredIdentityMetadata,
} from "./key-store.ts";
import { decryptIdentityContainer, encryptIdentityContainer } from "../packages/wallet/src/wallet-backup.ts";
import { initCcd } from "./ccd.ts";
import {
  githubErrorMessage,
  githubLogUrl,
  publishToGitHub,
  validateBeforePublish,
  verifyPublishedLog,
  verifyToken,
} from "../packages/wallet/src/github-host.ts";
import {
  CredentialRequiredError,
  hostForDid,
  isGitHubHostedDid as isGitHubHostedDidHost,
} from "../packages/wallet/src/host.ts";
import { verifyMasterOwnsLog } from "../packages/wallet/src/identity.ts";
import { WebvhHostingClient, currentParameters, parseLog as parseWebvhLog, resolveLog } from "../packages/webvh/src/index.ts";
import homeHeaderTemplate from "./pages/home-header.html";
import dashboardHeaderTemplate from "./pages/dashboard-header.html";
import footerTemplate from "./pages/footer.html";
import overlayTemplate from "./pages/overlays.html";
import creationTemplate from "./pages/creation.html";
import dashboardTemplate from "./pages/dashboard.html";
import aboutTemplate from "./pages/about.html";

const pageTemplates = new Map([
  ["/", creationTemplate],
  ["/about", aboutTemplate],
  ["/dashboard", dashboardTemplate],
]);
const pageFragments = new Map();
// Home vs dashboard headers are structurally different templates (not a
// single markup toggled with the .hidden class -- see renderRoute). Each
// one is parsed into its own detached DocumentFragment exactly once, at
// boot, before any addEventListener call below runs, so every header
// button gets its listener bound once and keeps it: switching routes moves
// nodes between headerRoot and the fragment they came from (same pattern as
// appRoot/pageFragments below), it never destroys and reparses markup.
const headerTemplates = new Map([
  ["home", homeHeaderTemplate],
  ["dashboard", dashboardHeaderTemplate],
]);
const headerFragments = new Map();

function query(selector) {
  const live = Document.prototype.querySelector.call(document, selector);
  if (live) return live;
  for (const fragment of pageFragments.values()) {
    const match = fragment.querySelector(selector);
    if (match) return match;
  }
  for (const fragment of headerFragments.values()) {
    const match = fragment.querySelector(selector);
    if (match) return match;
  }
  return null;
}

function queryAll(selector) {
  const matches = [...Document.prototype.querySelectorAll.call(document, selector)];
  for (const fragment of pageFragments.values()) matches.push(...fragment.querySelectorAll(selector));
  for (const fragment of headerFragments.values()) matches.push(...fragment.querySelectorAll(selector));
  return matches;
}

const headerRoot = query("#site-header");
const appRoot = query("#app");
const footerRoot = query("#site-footer");
if (!headerRoot || !appRoot || !footerRoot) throw new Error("application shell is missing");
footerRoot.innerHTML = footerTemplate;
appRoot.insertAdjacentHTML("beforebegin", overlayTemplate);
initCcd();
for (const [route, template] of pageTemplates) {
  const holder = document.createElement("template");
  holder.innerHTML = template;
  pageFragments.set(route, holder.content);
}
for (const [key, template] of headerTemplates) {
  const holder = document.createElement("template");
  holder.innerHTML = template;
  headerFragments.set(key, holder.content);
}
appRoot.append(pageFragments.get("/"));
let renderedHeader = "home";
headerRoot.append(headerFragments.get(renderedHeader));
headerRoot.classList.add("home-header-root");

// Network activity indicator (the bar in both header templates). A
// self-contained snippet, deliberately independent of every other piece of
// app logic here: it doesn't know or care which feature made a request, it
// just patches the two actual network primitives (fetch, XMLHttpRequest)
// once, globally, at the platform level. Any current or future call site --
// this file's own fetch() calls, a library, anything -- gets picked up
// automatically; there is no per-call-site "remember to flag this one too"
// step to forget.
(() => {
  let pending = 0;
  let hideTimer;
  const bar = () => document.getElementById("network-activity-bar");
  const domainLabel = () => document.getElementById("network-activity-domain");
  // Best-effort only: an invalid/relative-without-base or opaque request
  // target (e.g. a Request object built from another Request) just leaves
  // the label showing whatever it last showed, rather than throwing.
  const hostnameOf = url => {
    try { return new URL(url, location.href).hostname; } catch { return undefined; }
  };
  const begin = url => {
    pending += 1;
    clearTimeout(hideTimer);
    bar()?.classList.add("active");
    // Whichever request most recently started wins the label when several
    // overlap -- simple, and matches what a person actually watching it
    // would expect to see change. Text is set before the fade-in class, in
    // the same tick -- there's nothing to fade FROM (opacity is already 0
    // when idle), so there's no old hostname visible mid-transition.
    const hostname = hostnameOf(url);
    const label = domainLabel();
    if (hostname && label) label.textContent = hostname;
    label?.classList.add("active");
  };
  const end = () => {
    pending = Math.max(0, pending - 1);
    if (pending > 0) return;
    // A real request this app makes (e.g. the Alias availability check)
    // can resolve in well under 100ms -- switching the bar back to gray
    // the instant it settles left no time for even one animation frame to
    // paint in between, so it looked like the color never changed at all.
    // Hold the active state briefly past the last request's end so a fast
    // round trip is as visible as a slow one.
    hideTimer = setTimeout(() => {
      bar()?.classList.remove("active");
      // The text itself is left in place, not cleared -- it just fades to
      // opacity:0 (see .network-activity-domain's transition), the same
      // way the bar is left gray rather than removed from the page.
      domainLabel()?.classList.remove("active");
    }, 400);
  };

  const nativeFetch = window.fetch.bind(window);
  window.fetch = (...args) => {
    const [input] = args;
    const url = typeof input === "string" ? input : input instanceof Request ? input.url : String(input);
    begin(url);
    return nativeFetch(...args).finally(end);
  };

  // Nothing in this app uses XMLHttpRequest directly today, but a browser
  // extension, a future dependency, or code added later might -- catching
  // it here too is what makes this "any network call", not "any fetch()
  // call this file happens to make".
  const nativeOpen = XMLHttpRequest.prototype.open;
  const nativeSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.addEventListener("loadend", end, { once: true });
    this._networkActivityUrl = url;
    return nativeOpen.call(this, method, url, ...rest);
  };
  XMLHttpRequest.prototype.send = function (...args) {
    begin(this._networkActivityUrl);
    return nativeSend.apply(this, args);
  };
})();

let renderedRoute = "/";

function locationRoute() {
  const raw = location.protocol === "file:" ? location.hash.slice(1) : location.pathname;
  const route = `/${raw.replace(/^\/+|\/+$/g, "")}`;
  return pageTemplates.has(route) ? route : "/";
}

function renderRoute() {
  const requestedRoute = locationRoute();
  let route = requestedRoute;
  const hasIdentity = Boolean(loaded || storedIdentityRecord);
  // An authorization request does not imply that the person already has an
  // identity. A fresh Wallet must land on account creation; the dedicated
  // /load page is an explicit recovery/import action, not the default login
  // fallback. A locally stored identity still goes to the dashboard where
  // it can be unlocked and approved.
  if (walletAuthorization) route = hasIdentity ? "/dashboard" : "/";
  if (hasIdentity && route === "/") route = "/dashboard";
  if (!hasIdentity && route === "/dashboard") route = "/";
  if (route !== requestedRoute && location.pathname !== "/authorize") {
    const target = location.protocol === "file:" ? `#${route}` : route;
    history.replaceState(null, "", target);
  }
  document.querySelector("header.site-header")?.classList.toggle("on-about", route === "/about");

  // Switch header by route: move nodes between headerRoot and their
  // detached fragment (see headerFragments above), same as the appRoot/
  // pageFragments swap just below -- never innerHTML, which would reparse
  // fresh nodes and drop every listener bound at boot.
  const targetHeader = route === "/dashboard" ? "dashboard" : "home";
  if (targetHeader !== renderedHeader) {
    headerFragments.get(renderedHeader).append(...headerRoot.childNodes);
    headerRoot.append(headerFragments.get(targetHeader));
    renderedHeader = targetHeader;
  }
  // home-header-root now governs look/behavior for both routes (sticky,
  // shrinks welcome->normal off scroll -- see its own comment in
  // styles.css); site-header is an additive marker for dashboard's own
  // extra context-bar behavior (the #context-window fade-in/pointer-events
  // rules, and hiding the brand while a context view is open), not a
  // separate visual base anymore.
  headerRoot.classList.add("home-header-root");
  headerRoot.classList.toggle("site-header", targetHeader === "dashboard");

  if (route !== renderedRoute) {
    pageFragments.get(renderedRoute).append(...appRoot.childNodes);
    appRoot.append(pageFragments.get(route));
    renderedRoute = route;
  }
  // Leaving home with Load open: close the card and keep phrase restore
  if (route !== "/" && query("#create-load-form").classList.contains("creation-load-mode")) {
    setCreationLoadMode(false);
  }
  if (route === "/" || route === "/dashboard") {
    selectTab("home");
    if (route === "/") {
      updateIdentityOptionsVisibility();
      maybeBeginCreateDraft();
      restoreHomePassphrase();
    }
  }
}

function navigate(route, { replace = false } = {}) {
  if (location.protocol === "file:") {
    const hash = `#${route}`;
    if (replace) history.replaceState(null, "", hash);
    else location.hash = hash;
    renderRoute();
    return;
  }
  history[replace ? "replaceState" : "pushState"](null, "", route);
  renderRoute();
}

const API = globalThis.DID_API ?? (location.hostname === "localhost" ? "http://localhost:8787" : "https://api.did.md");
const DOMAIN = "did.md";
const AUTO_LOCK_MS = 24 * 60 * 60_000;
const OAUTH_ISSUER = API;
const DEVICE_CAPABILITY_GRANT_MS = 31 * 24 * 60 * 60_000;
const WALLET_SESSION_KEY = "did-md-wallet-last-passkey-identity";
const DID_DOCUMENT_EDIT_DETAIL = "urn:did-core:document-edit:v1";
const KEY_AUTHORIZATION_DETAIL = "urn:did.md:key-authorization:v1";
const DERIVED_SECRET_DETAIL = "urn:did.md:derived-secret:v1";
// A bare `?alias` (no value needed) pre-enables the Alias toggle on the
// creation screen -- for a relying party (e.g. biset) redirecting here
// whose users are expected to want a memorable did.md hostname, or for
// linking directly to https://app.did.md/?alias. Captured once, here, at
// module load: further down, boot scrubs location.search off any page
// other than /authorize shortly after load (to remove a just-submitted
// Create/Load form's username/password from the address bar), and reading
// it fresh from an async continuation risks losing the race against that.
// It carries no authority -- the identity created still needs a did:webvh
// SCID/Root key regardless, and the toggle can always be switched back off
// by hand.
const requestedAliasFromUrl = (() => {
  try { return new URLSearchParams(location.search).has("alias"); } catch { return false; }
})();
let draft = null;
let draftBeingCreated = false;
let creationLoadUrlTimer = null;
let creationLoadUrlController = null;
let creationAliasTimer = null;
let creationAliasController = null;
let loaded = null;
let pending = null;
// True right after Rotate key succeeds, until the user leaves and returns
// to the Keys tab -- see the [data-application-tab] click listener below.
// Drives #rotate-key's own "Rotated" state instead of a one-off toast/panel
// message, since the whole point of the atomic flow is that there's
// nothing left to review.
let justRotated = false;
// True after Rotate key fails for any reason (offline, a server error,
// this identity not being hosted on did.md, ...) -- there's no retry
// button anymore (see publishPreparedEntry), so the failure is reported
// the same way success is: replacing #key-status's own message, not a
// one-off panel/toast. Cleared by the next Rotate key click or by leaving
// and returning to the Keys tab, same as justRotated.
let rotateKeyFailed = false;
let autoLockTimer = null;
let walletAuthorization = null;
// A deliberate action taken while locked (approving an authorization,
// switching to Credentials, removing a service/key, opening keyring.json...)
// is resumed exactly once after this tab successfully unlocks. Closing the
// prompt cancels it. See withUnlock().
let applicationActionAfterUnlock = null;
let currentTab = "home";
let currentApplicationTab = "apps";
let loadedIdentityDataAvailable = false;
let storedIdentityRecord = null;
let connectionRenderGeneration = 0;
// Public DID Document state remains renderable while private Master material
// is locked. It is populated only from the verified did.jsonl history.
let publicApplicationState = null;
let portableApplications = [];
let identityFilesView = null;
let sensitiveFileTimer = null;
// The current renderIdentityFiles() call's own show() closure -- #files-back
// is static markup (bound once, below), not re-created per render like the
// file entries are, so it needs a stable way to reach whichever show() is
// currently live.
let identityFilesShow = null;

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function setSignedInStatus(username) {
  const target = query("#wallet-login-status");
  target.textContent = username ? `Signed in · ${username}` : "";
  target.dataset.state = username ? "in" : "out";
}

// The public identity summary belongs to the overview only. The other pages
// deliberately contain just the one task named in their heading.
function updateLoadedIdentityVisibility() {
  const showIdentity = currentTab === "home" && loadedIdentityDataAvailable;
  query("#loaded-identity").classList.toggle("hidden", !showIdentity);
}

// Overview intentionally has just two states. Forms for creating and loading
// remain exclusively on the Identity page.
function updateOverviewState() {
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  query("#overview-null").classList.toggle("hidden", Boolean(did));
  query("#overview-loaded").classList.toggle("hidden", !did || loadedIdentityDataAvailable);
  if (did) {
    const host = didHost(did);
    query("#overview-loaded-title").textContent = host?.endsWith(`.${DOMAIN}`) ? host : "Identity loaded";
    renderDidValue(query("#overview-loaded-did"), did);
  }
}

function updateIdentityOptionsVisibility() {
  const hasIdentity = Boolean(loaded || storedIdentityRecord);
  query("#create-form-area").classList.toggle("hidden", hasIdentity || !draft);
  query("#nav-unload").classList.toggle("hidden", !hasIdentity);
  query("#header-load-toggle").classList.toggle("hidden", hasIdentity);
  // The Apps/Docs/Keys/Files tabs have nothing to show before an identity
  // exists -- keep them out of the way during creation/loading.
  query(".application-tabs").classList.toggle("hidden", !hasIdentity);
}

/** Loads the current DID document for this tab's active identity. Reads only
 * public documents (did.json) -- no unlock, no private key, no passkey. */
function fieldGroup(heading, entries) {
  const group = document.createElement("div");
  group.className = "field-group";
  const details = document.createElement("dl");
  details.className = "fields";
  for (const [label, value] of entries) details.append(fact(label, value));
  if (heading) {
    const title = document.createElement("h4");
    title.textContent = heading;
    group.append(title);
  }
  group.append(details);
  return group;
}

function linkFact(label, href) {
  const fragment = document.createDocumentFragment();
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  const link = document.createElement("a");
  link.href = href;
  link.target = "_blank";
  link.rel = "noreferrer";
  link.textContent = href;
  description.append(link);
  fragment.append(term, description);
  return fragment;
}

// The DID/username are already known locally (no identity this browser
// hasn't verified gets into `loaded`/`storedIdentityRecord` in the first
// place), so this always renders them immediately. The live did.json fetch
// only adds an optional enhancement -- the canonical webvh form and a
// display name -- and never hides the row if it fails; Connect/Disconnect
// are exactly the actions where the host is momentarily unreachable, and an
// error message shown over this row must not vanish because of that.
async function renderLoadedIdentity() {
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  // A provisional (not-yet-connected) identity, or one hosted somewhere
  // other than *.did.md, has no did.md username to show as "name.did.md" --
  // fall back to the DID's own host segment (e.g. "ex.alias" for a fresh,
  // never-hosted identity) rather than its SCID, so this always reads as an
  // alias-shaped name instead of a raw hash. Either way, an identity being
  // loaded at all (not whether it happens to be hosted) is what should make
  // this row exist.
  const username = did && didMdUsername(did);
  const displayName = username ? `${username}.${DOMAIN}` : did && didHost(did);
  loadedIdentityDataAvailable = Boolean(did && displayName);
  // Toggle visibility from the locally-known data immediately -- never wait
  // on the network fetch below, whose only job is an optional enhancement
  // (see the note on that fetch). Waiting on it here is what silently hid
  // every message shown on this row until the fetch settled (or hung).
  updateLoadedIdentityVisibility();
  updateOverviewState();
  updateIdentityOptionsVisibility();
  if (did && displayName) {
    query("#loaded-identity-name").textContent = displayName;
    renderDidLine(query("#identity-did"), query("#identity-did-alias"), did);
    query("#identity-did-copy").dataset.did = did;
    query("#loaded-identity-summary").replaceChildren();
    updateIdentityHostRow();
    if (!username) return;
    try {
      const response = await fetch(endpoint(did, "did.json"), { cache: "no-store" });
      if (response.ok) {
        const state = await response.json();
        const webvhDid = Array.isArray(state.alsoKnownAs) ? state.alsoKnownAs.find(id => id.startsWith("did:webvh:")) : null;
        if (webvhDid) {
          renderDidLine(query("#identity-did"), query("#identity-did-alias"), webvhDid);
          query("#identity-did-copy").dataset.did = webvhDid;
        }
        if (state.name) query("#loaded-identity-summary").append(fact("Name", state.name));
      }
    } catch { /* the row already shows the local DID; the live extras are optional */ }
  }
}

/** Restores the "loaded" overview/identity state from the browser's
 * persisted identity record, independent of whether this tab has the
 * password-derived Master unlocked. Only keyring.json stays gated behind a
 * password prompt; the DID and its public log are shown immediately. */
async function restoreStoredIdentityRecord() {
  storedIdentityRecord = (await listStoredIdentities())[0] ?? null;
  // Home's ?/load buttons stay hidden (see html.identity-pending in
  // styles.css) until this resolves -- renderRoute() below runs once,
  // synchronously, before this async IndexedDB read can possibly have
  // settled, always rendering "home" first regardless of what's actually
  // stored; a page that turns out to have a stored identity then
  // immediately swaps to the dashboard header, flashing the home header's
  // own buttons for one frame first. This class is the same fix either
  // way that redirect goes, not specific to any one route.
  document.documentElement.classList.remove("identity-pending");
  renderSync();
  void renderLoadedIdentity();
  void refreshIdentityViews();
  void updateConnectionStatus();
  maybeBeginCreateDraft();
  if (!storedIdentityRecord || loaded) return;
  const keyringPath = containerPath(storedIdentityRecord.did, "keyring.json");
  // A provisional genesis record has no host to fetch from; its log was
  // cached locally when it was first loaded. For a hosted record, prefer the
  // live log, but a disconnected/unreachable host is a normal, supported
  // state (see updateConnectionStatus) -- not the identity being gone -- so
  // fall back to the last snapshot saved locally (kept up to date by
  // connectHostedData) rather than dropping did.jsonl from the Files view
  // entirely.
  const didJsonl = isProvisionalDid(storedIdentityRecord.did)
    ? (await readDidLogSnapshot(storedIdentityRecord.username))?.didJsonl
    : await fetchCompleteDidLog(storedIdentityRecord).catch(() => readDidLogSnapshot(storedIdentityRecord.username).then(snapshot => snapshot?.didJsonl));
  const metadataFiles = await metadataContainerFiles(storedIdentityRecord.did);
  const metadataPaths = Object.keys(metadataFiles);
  try {
    if (!didJsonl) throw new Error("No cached DID log snapshot for this identity.");
    const entries = parseLog(didJsonl);
    publicApplicationState = entries.at(-1)?.state ?? null;
    renderServicesList();
    renderApplicationKeysList();
    const didLogPath = containerPath(storedIdentityRecord.did, "did.jsonl");
    renderIdentityFiles({
      manifest: { identities: [{ keyringPath }], contents: [didLogPath, keyringPath, ...metadataPaths] },
      files: { [didLogPath]: didJsonl, [keyringPath]: null, ...metadataFiles },
    });
  } catch {
    // Nothing usable either live or cached -- keep the Files view (and the
    // menu's Unload entry) available with keyring.json only, rather than
    // hiding it entirely.
    renderIdentityFiles({
      manifest: { identities: [{ keyringPath }], contents: [keyringPath, ...metadataPaths] },
      files: { [keyringPath]: null, ...metadataFiles },
    });
  }
}

function rememberPasskeyWalletSession() {
  try {
    if (loaded?.record?.protection === "passkey") localStorage.setItem(WALLET_SESSION_KEY, loaded.username);
    else localStorage.removeItem(WALLET_SESSION_KEY);
  } catch { /* Private browsing may block localStorage; Wallet still works in this tab. */ }
}

function forgetPasskeyWalletSession() {
  try { localStorage.removeItem(WALLET_SESSION_KEY); } catch { /* no-op */ }
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlBytes(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${label} must be base64url.`);
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  let binary;
  try { binary = atob(padded); } catch { throw new Error(`${label} must be base64url.`); }
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function sha256Base64url(value) {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

function p256Jwk(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "crv,kty,x,y"
    || value.kty !== "EC" || value.crv !== "P-256" || base64urlBytes(value.x, "DPoP x").length !== 32 || base64urlBytes(value.y, "DPoP y").length !== 32) {
    throw new Error("The client supplied an invalid P-256 DPoP public key.");
  }
  return { kty: "EC", crv: "P-256", x: value.x, y: value.y };
}

function detailObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid.`);
  return value;
}

function detailKeys(value, keys, label) {
  if (Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) throw new Error(`${label} has unexpected fields.`);
}

function oauthAuthorizationDetails(value) {
  if (value === null) return [];
  if (typeof value !== "string" || value.length < 2 || value.length > 16_384) throw new Error("The OAuth authorization details are invalid.");
  let details;
  try { details = JSON.parse(value); } catch { throw new Error("The OAuth authorization details are invalid."); }
  if (!Array.isArray(details) || !details.length || details.length > 16) throw new Error("The OAuth authorization details are invalid.");
  for (const [index, detail] of details.entries()) {
    const object = detailObject(detail, `Authorization detail ${index + 1}`);
    if (typeof object.type !== "string" || !/^[A-Za-z][A-Za-z0-9:._/-]{0,127}$/.test(object.type)) throw new Error("The OAuth authorization details are invalid.");
  }
  return details;
}

function didDocumentEditDetail(details, did) {
  const matches = details.filter(detail => detail.type === DID_DOCUMENT_EDIT_DETAIL);
  if (!matches.length) return undefined;
  if (matches.length !== 1) throw new Error("The DID document edit request is duplicated.");
  const detail = detailObject(matches[0], "The DID document edit request");
  const detailShape = ["type", "services", "verificationMethods", "remove", ...(detail.serviceKeyBindings === undefined ? [] : ["serviceKeyBindings"])];
  detailKeys(detail, detailShape, "The DID document edit request");
  if (!Array.isArray(detail.services) || !Array.isArray(detail.verificationMethods) || !Array.isArray(detail.remove)
    || detail.services.length > 64 || detail.verificationMethods.length > 64 || detail.remove.length > 128) throw new Error("The DID document edit request is invalid.");
  // DID Core permits a fragment-only relative DID URL (for example
  // `#didcomm`) for resources in this same DID Document.
  const validId = id => typeof id === "string" && (/^#[^\s#]+$/.test(id)
    || ((did ? id.startsWith(`${did}#`) : id.startsWith("did:webvh:")) && id.includes("#") && !/[\s#]/.test(id.slice(id.indexOf("#") + 1))));
  // DID Core allows serviceEndpoint to be a string, a map, or a set of
  // strings and/or maps -- accept all three shapes, not just the first two.
  const validEndpoint = endpoint => typeof endpoint === "string" || (!!endpoint && typeof endpoint === "object" && !Array.isArray(endpoint));
  for (const value of detail.services) {
    const service = detailObject(value, "DID service"); detailKeys(service, ["id", "type", "serviceEndpoint"], "DID service");
    const endpointValid = Array.isArray(service.serviceEndpoint)
      ? service.serviceEndpoint.length > 0 && service.serviceEndpoint.length <= 8 && service.serviceEndpoint.every(validEndpoint)
      : validEndpoint(service.serviceEndpoint);
    if (!validId(service.id) || typeof service.type !== "string" || !service.type.trim() || !endpointValid) throw new Error("A DID service is invalid.");
  }
  // controller is force-set to the Wallet's own loaded DID below, never
  // trusted from the relying party's request -- a verification method
  // published into THIS identity's own DID Document must be controlled by
  // THIS identity, regardless of what a relying party (which doesn't
  // necessarily know the DID yet when it builds this request) claims.
  detail.verificationMethods = detail.verificationMethods.map(value => {
    const method = detailObject(value, "DID verification method"); detailKeys(method, ["id", "type", "controller", "publicKeyMultibase"], "DID verification method");
    if (!validId(method.id) || typeof method.type !== "string" || !method.type.trim() || typeof method.controller !== "string" || typeof method.publicKeyMultibase !== "string") throw new Error("A DID verification method is invalid.");
    return { ...method, controller: did };
  });
  if (detail.serviceKeyBindings !== undefined) {
    if (!Array.isArray(detail.serviceKeyBindings) || detail.serviceKeyBindings.length > detail.services.length) throw new Error("The DID service/key bindings are invalid.");
    const serviceIds = new Set(detail.services.map(service => service.id));
    const keyIds = new Set(detail.verificationMethods.map(method => method.id));
    const seenServices = new Set();
    for (const value of detail.serviceKeyBindings) {
      const binding = detailObject(value, "DID service/key binding");
      detailKeys(binding, ["serviceId", "keyIds"], "DID service/key binding");
      if (!serviceIds.has(binding.serviceId) || seenServices.has(binding.serviceId) || !Array.isArray(binding.keyIds)
        || binding.keyIds.some(id => !keyIds.has(id)) || new Set(binding.keyIds).size !== binding.keyIds.length) throw new Error("The DID service/key bindings are invalid.");
      seenServices.add(binding.serviceId);
    }
  }
  if (detail.remove.some(id => !validId(id)) || new Set([...detail.services.map(x => x.id), ...detail.verificationMethods.map(x => x.id), ...detail.remove]).size !== detail.services.length + detail.verificationMethods.length + detail.remove.length) throw new Error("The DID document edit contains duplicate or invalid ids.");
  return detail;
}

function keyAuthorizationDetail(details) {
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
    || detail.purposes.some(value => typeof value !== "string" || !value.trim() || value.length > 64)) throw new Error("The key authorization request is invalid.");
  return detail;
}

// A relying party's own devices sometimes need to agree on a value (e.g. a
// storage locator) without that value ever being published anywhere public.
// Rather than trust an RP-supplied secret (which would need transporting
// over the very channel it's trying to keep private), the Wallet derives it
// itself from the identity's Root private key and hands back only the
// result -- see deriveWalletSecret in did-webvh.ts. purpose/context are
// domain-separation labels the RP supplies; several distinct requests may
// appear in one authorization, so (unlike the "exactly one" detail types
// above) this collects every match.
function derivedSecretDetails(details) {
  const matches = details.filter(detail => detail.type === DERIVED_SECRET_DETAIL);
  if (matches.length > 8) throw new Error("Too many derived secret requests.");
  const seen = new Set();
  return matches.map(value => {
    const detail = detailObject(value, "The derived secret request");
    const shape = ["type", "purpose", ...(detail.context === undefined ? [] : ["context"])];
    detailKeys(detail, shape, "The derived secret request");
    if (typeof detail.purpose !== "string" || !/^[A-Za-z][A-Za-z0-9:._-]{0,127}$/.test(detail.purpose)) throw new Error("The derived secret purpose is invalid.");
    if (detail.context !== undefined && (typeof detail.context !== "string" || !detail.context.trim() || detail.context.length > 2048)) throw new Error("The derived secret context is invalid.");
    const key = `${detail.purpose} ${detail.context ?? ""}`;
    if (seen.has(key)) throw new Error("The derived secret requests are duplicated.");
    seen.add(key);
    return detail;
  });
}

async function p256Jkt(key) {
  return sha256Base64url(JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y }));
}

function walletTimestamp(afterMs = 0) { return new Date(Date.now() + afterMs).toISOString(); }

// #context-toast (now on both headers -- see its own comment in
// home-header.html) has two independent triggers sharing one element:
// hovering/focusing any [data-toast] element (a tooltip) and an action's own
// result (showActionToast, called from output() below for what used to be
// two separate DOM targets, #wallet-result and #loaded-identity-message --
// the footer and an overlay on the did-line respectively, picked between
// depending on whether an identity/its did-line existed yet). A single
// header-scale toast now exists on every route regardless, so there's no
// longer a "does the target exist yet" problem to solve by picking between
// two elements. Hover wins while it's active -- a tooltip is transient
// attention the user is actively giving something else, so it should never
// be silently replaced; the action toast (if any) resumes for whatever's
// left of its own 60s window once the hover ends, rather than being lost.
let hoverToastActive = false;
let actionToast = null; // { message, error } | null -- whatever's currently "live"
let actionToastTimer = null;

// The Authorize card and the system-message toast are both bottom sheets, and
// two at once cover each other. So the card is treated as the system-message
// surface while it is open: text messages are shown inside it (its own
// #wallet-authorize-message line) and the toast sheet stays closed; when the
// card closes, that line is cleared and messages use the toast again.
function authorizeCardOpen() {
  const panel = query("#wallet-authorize-panel");
  return Boolean(panel && !panel.classList.contains("hidden"));
}

function setAuthorizeMessage(message, error) {
  const line = query("#wallet-authorize-message");
  if (!line) return;
  line.textContent = message ?? "";
  line.classList.toggle("hidden", !message);
  line.classList.toggle("error", Boolean(message) && Boolean(error));
}

// What the toast is currently telling the user (null when nothing), so a
// message that is up when the Authorize card opens can move into the card.
let shownToast = null;

function paintContextToast(message, error) {
  // Lives directly under <body>, not in a header template: a header ancestor
  // with a transform/filter would make "fixed" relative to it, not the
  // viewport. Templates re-render per route, so keep exactly one, hoisted.
  const [toast, ...stale] = queryAll("#context-toast");
  if (!toast) return;
  for (const extra of stale) extra.remove();
  if (toast.parentElement !== document.body) document.body.appendChild(toast);
  // Freshly moved/inserted: commit the off-screen start state first, or the
  // is-open below lands in the same frame and skips the slide.
  void toast.offsetHeight;
  if (!toast.firstElementChild) {
    // Bell that turns into an X on hover (same slot, so the width never
    // changes); clicking it closes the toast.
    toast.innerHTML = `<button type="button" class="context-toast-close" aria-label="Dismiss">
      <svg class="bell" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
      <svg class="x" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button><span class="context-toast-text"></span>`;
    toast.querySelector(".context-toast-close").addEventListener("click", dismissActionToast);
  }
  shownToast = message ? { message, error: Boolean(error) } : null;
  if (authorizeCardOpen()) {
    setAuthorizeMessage(message, error);
    toast.classList.remove("is-open");
    return;
  }
  if (message) {
    toast.querySelector(".context-toast-text").textContent = message;
    toast.classList.toggle("error", Boolean(error));
  }
  toast.classList.toggle("is-open", Boolean(message));
}

function showActionToast(message, error = false) {
  if (actionToastTimer) clearTimeout(actionToastTimer);
  actionToastTimer = null;
  actionToast = message ? { message, error } : null;
  if (!hoverToastActive) paintContextToast(message, error);
  if (message) {
    actionToastTimer = setTimeout(() => {
      actionToast = null;
      actionToastTimer = null;
      if (!hoverToastActive) paintContextToast("", false);
    }, 60000);
  }
}

// Outside click or Escape dismisses the toast right away; clicks on the
// toast itself do nothing.
function dismissActionToast() {
  // While the Authorize card is the open sheet, its message belongs to the card:
  // clicking the card (or anywhere else on the page) must not wipe it. It goes
  // when the card closes, when a new message replaces it, or after 60 s.
  if (authorizeCardOpen()) return;
  if (!actionToast && !hoverToastActive) return;
  if (actionToastTimer) clearTimeout(actionToastTimer);
  actionToastTimer = null;
  actionToast = null;
  hoverToastActive = false;
  paintContextToast("", false);
}
document.addEventListener("pointerdown", event => {
  if (event.target.closest?.("#context-toast")) return;
  dismissActionToast();
});
document.addEventListener("keydown", event => { if (event.key === "Escape") dismissActionToast(); });

function showContextToast(message) {
  hoverToastActive = true;
  paintContextToast(message, false);
}
function hideContextToast() {
  hoverToastActive = false;
  if (actionToast) paintContextToast(actionToast.message, actionToast.error);
  else paintContextToast("", false);
}

// Every other id (the per-panel ones: #services-result, ...) is untouched --
// this only intercepts the ids that now mean "the bottom toast": the two
// historical dashboard ids plus the home page's #create-result. #keys-result stays a panel message on
// purpose: "A DID Document update is already prepared" etc. are about the
// Key rotation card's own current state, not a one-off action result --
// they belong inside it, not flashing past in the toast. It's also exempt
// from the auto-clear below: unlike a toast-style action result, it
// describes whatever the Key rotation card is currently showing, so it
// should stay until the next action replaces or clears it, not vanish out
// from under a card the user may still be reading.
const outputClearTimers = new WeakMap();
function output(id, message, error = false) {
  if (id === "#wallet-result" || id === "#loaded-identity-message" || id === "#create-result") {
    showActionToast(message, error);
    return;
  }
  const el = query(id);
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("hidden", !message);
  el.classList.toggle("error", Boolean(error));
  el.classList.toggle("success", !error && Boolean(message));
  const previousTimer = outputClearTimers.get(el);
  if (previousTimer) clearTimeout(previousTimer);
  if (!message || id === "#keys-result") { outputClearTimers.delete(el); return; }
  outputClearTimers.set(el, setTimeout(() => {
    el.textContent = "";
    el.classList.add("hidden");
    el.classList.remove("error", "success");
    outputClearTimers.delete(el);
  }, 8000));
}

/** Most action buttons share one shape: disable while running, always
 * re-enable, and on failure show the error in a result panel -- typed out at
 * two dozen call sites before this, with room for the shape to drift between
 * them. `target` may be a selector or an element (for one built dynamically,
 * e.g. a per-row Remove button). `resultTarget` may be a selector or a
 * function of no args (for a panel that depends on which tab is open). */
/** Trash glyph for rows generated at runtime (e.g. a service card's remove
 * control). */
function trashIcon() {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(SVG_NS, "svg");
  for (const [attribute, value] of [
    ["class", "trash-icon"], ["viewBox", "0 0 24 24"], ["width", "18"], ["height", "18"],
    ["fill", "none"], ["stroke", "currentColor"], ["stroke-width", "2"],
    ["stroke-linecap", "round"], ["stroke-linejoin", "round"], ["aria-hidden", "true"],
  ]) svg.setAttribute(attribute, value);
  const polyline = document.createElementNS(SVG_NS, "polyline");
  polyline.setAttribute("points", "3 6 5 6 21 6");
  svg.append(polyline);
  for (const d of [
    "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6",
    "M10 11v6",
    "M14 11v6",
    "M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2",
  ]) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

function onClick(target, resultTarget, handler) {
  const button = typeof target === "string" ? query(target) : target;
  // `button` may not be an actual <button> (some are plain text elements
  // with role="button" -- see #identity-alias-edit), which has no
  // .disabled property to guard re-entrancy with -- fall back to a class
  // that CSS blocks pointer-events on.
  const setBusy = busy => {
    if ("disabled" in button) button.disabled = busy;
    else button.classList.toggle("is-busy", busy);
  };
  button.addEventListener("click", async () => {
    setBusy(true);
    try {
      await handler(button);
    } catch (error) {
      const target = typeof resultTarget === "function" ? resultTarget() : resultTarget;
      output(target, errorMessage(error), true);
    } finally {
      setBusy(false);
    }
  });
}

// The Credential Management API's explicit save signal: unlike a form
// submission followed by navigation (unreliable in a single-page app), this
// tells the browser -- and any password manager extension hooking the same
// API -- to offer saving this credential right now, no navigation needed.
async function offerToSaveLocalPassword(id, password) {
  if (!window.PasswordCredential || !navigator.credentials?.store) return;
  try {
    await navigator.credentials.store(new PasswordCredential({ id, password, name: "did.md identity" }));
  } catch { /* not supported, blocked, or declined; not fatal */ }
}

// Container paths like "identities/<username>/did.jsonl" are shown to the
// user as just "did.jsonl"; the full path only matters for looking the file
// up in the container's manifest.
function basename(path) {
  return typeof path === "string" ? path.split("/").pop() : path;
}

function clearIdentityFiles() {
  if (sensitiveFileTimer) clearTimeout(sensitiveFileTimer);
  sensitiveFileTimer = null;
  identityFilesView = null;
  query("#identity-file-list").replaceChildren();
  query("#identity-file-content").textContent = "";
  query("#identity-file-display").classList.add("hidden");
  query("#identity-keyring-password").classList.add("hidden");
  query("#identity-keyring-password-input").value = "";
  query("#identity-keyring-passkey").classList.add("hidden");
}

// True when the identity currently shown in the files viewer -- whether
// already persisted (storedIdentityRecord) or still an in-tab draft that has
// not been loaded yet -- is passkey-protected rather than password-protected.
function keyringIsPasskeyProtected() {
  return storedIdentityRecord?.protection === "passkey" || (!storedIdentityRecord && !!draft?.protector);
}

function keyringJson(masterSeed) {
  return {
    type: "bip39-slip10-ed25519",
    masterEntropy: base64url(masterSeed),
    derivationProfile: "did.md/master-ed25519-v1",
    applications: portableApplications,
  };
}

// Files' own card header is a drilldown breadcrumb, not a static title:
// "loaded/" + Export/Unload by default; otherwise whichever detail view is
// current -- "loaded/{basename}" (an open file, including while its
// keyring.json password/passkey prompt is waiting -- opening that prompt
// already counts as "entering" the file), "Unload this identity?"
// (setUnloadView), or "Export" (setExportView) -- + Back. #identity-file-list
// (the tree itself) hides opposite whichever of #identity-file-display/
// #files-unload-body/#files-export-body is showing, since the open detail
// view is this same card's own content, not a second area alongside the
// listing. Unload/export win the label over an open file if somehow more
// than one is active (setUnloadView/setExportView each prevent that by
// closing the other two first, but this only has to decide what to show,
// not enforce exclusivity).
function updateFilesHeader() {
  const name = identityFilesView?.selected;
  const label = unloadViewActive ? "Unload this identity?"
    : exportViewActive ? "Export"
    : (name ? `loaded/${basename(name)}` : null);
  query("#files-tree-path").textContent = label ?? "loaded/";
  query("#files-back-actions").classList.toggle("hidden", !label);
  query("#identity-file-list").classList.toggle("hidden", Boolean(label));
  query("#files-unload-body")?.classList.toggle("hidden", !unloadViewActive);
  query("#files-export-body")?.classList.toggle("hidden", !exportViewActive);
  updateFilesActionsRow();
}

// #files-actions (Export/Unload) has three independent reasons to hide -- a
// file is open, or the Unload/Export detail view is showing (all above) --
// each used to toggle it unconditionally off its own single condition, so
// whichever ran second stomped the others' "hidden" (e.g. opening
// keyring.json's unlock prompt ran applyContextViewVisibility via
// setCommandMode, which unhid Export/Unload again despite a file still being
// open). ORed into one place instead.
function updateFilesActionsRow() {
  const fileOpen = Boolean(identityFilesView?.selected);
  query("#files-actions")?.classList.toggle("hidden", fileOpen || unloadViewActive || exportViewActive);
}

// <- means "leave whichever detail view is open" -- Unload/Export's own view
// if one of those is showing, otherwise close the open file (show()'s own
// toggle-off branch, keyed on re-passing its current selection).
query("#files-back").addEventListener("click", () => {
  if (unloadViewActive) { setUnloadView(false); return; }
  if (exportViewActive) { setExportView(false); return; }
  identityFilesShow?.(identityFilesView?.selected);
});

/** Shows the logical files inside the decrypted portable container. The
 * encrypted outer JWE is deliberately not presented as a file tab. */
function renderIdentityFiles(container) {
  const list = query("#identity-file-list");
  const display = query("#identity-file-display");
  const field = query("#identity-file-content");
  const files = container?.files;
  const contents = container?.manifest?.contents;
  if (!files || typeof files !== "object" || !Array.isArray(contents)) {
    clearIdentityFiles();
    return;
  }
  const names = contents.filter(name => typeof name === "string" && Object.hasOwn(files, name));
  if (!names.length) {
    clearIdentityFiles();
    return;
  }
  const keyringPath = container.manifest?.identities?.[0]?.keyringPath;
  // A rebuild (unlocking, a background refresh) must not drop the file the user has open.
  const previouslyOpen = identityFilesView?.selected;
  identityFilesView = { files, names, keyringPath, selected: null };
  const show = (name, { open = false } = {}) => {
    // File links are accordion triggers: pressing the already-open item
    // closes the surface and clears its selection, including a keyring
    // password/passkey prompt that may be waiting for input. `open` skips that
    // toggle: the unlock-then-show resume below runs with the selection already recorded.
    if (!open && identityFilesView.selected === name) {
      identityFilesView.selected = null;
      updateFilesHeader();
      if (sensitiveFileTimer) clearTimeout(sensitiveFileTimer);
      sensitiveFileTimer = null;
      for (const button of list.querySelectorAll("[data-file]")) button.classList.remove("active");
      field.textContent = "";
      display.classList.add("hidden");
      query("#identity-keyring-password").classList.add("hidden");
      query("#identity-keyring-passkey").classList.add("hidden");
      return;
    }
    // keyring.json needs the Master seed decrypted. Open the unlock prompt
    // first and defer actually displaying this file until it succeeds --
    // showing it now (the tab-switch/content-population further down) would
    // flash the file view into an empty state right before the prompt
    // appears. The selection itself IS recorded now, though (not just
    // visually applied): submitUnlockMnemonic reads identityFilesView.selected
    // to know which tab to land back on once unlocked.
    if (name === keyringPath && storedIdentityRecord && !loaded) {
      identityFilesView.selected = name;
      updateFilesHeader();
      void withUnlock(() => show(name, { open: true }));
      return;
    }
    identityFilesView.selected = name;
    updateFilesHeader();
    for (const button of list.querySelectorAll("[data-file]")) button.classList.toggle("active", button.dataset.file === name);
    if (sensitiveFileTimer) clearTimeout(sensitiveFileTimer);
    sensitiveFileTimer = null;
    field.textContent = "";
    display.classList.add("hidden");
    query("#identity-keyring-password-input").value = "";
    if (name === keyringPath) {
      if (storedIdentityRecord) {
        // withUnlock guarantees `loaded` here -- a persisted identity's own
        // unlock state is this tab's single source of truth, so reuse it
        // instead of asking for the password/passkey a second time.
        query("#identity-keyring-password").classList.add("hidden");
        query("#identity-keyring-passkey").classList.add("hidden");
        displayKeyringJsonTemporarily(loaded.masterSeed);
        return;
      }
      const passkeyProtected = keyringIsPasskeyProtected();
      query("#identity-keyring-password").classList.toggle("hidden", passkeyProtected);
      query("#identity-keyring-passkey").classList.toggle("hidden", !passkeyProtected);
      if (passkeyProtected) query("#identity-keyring-passkey-unlock").focus();
      else query("#identity-keyring-password-input").focus();
      return;
    }
    query("#identity-keyring-password").classList.add("hidden");
    query("#identity-keyring-passkey").classList.add("hidden");
    const value = files[name];
    field.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
    display.classList.remove("hidden");
  };
  identityFilesShow = show;
  updateFilesHeader();
  list.replaceChildren();
  names.forEach((name, index) => {
    // A filename is data, not a command -- plain text with a click affordance
    // (role="button"), not <button>. Same reasoning as #identity-alias-edit.
    const open = document.createElement("span");
    open.setAttribute("role", "button");
    open.tabIndex = 0;
    open.className = "files-tree-entry";
    open.dataset.file = name;
    open.title = name;
    const connector = document.createElement("span");
    connector.className = "files-tree-connector";
    connector.setAttribute("aria-hidden", "true");
    connector.textContent = index === names.length - 1 ? "└ " : "├ ";
    open.append(connector, document.createTextNode(basename(name)));
    open.addEventListener("click", () => show(name));
    list.append(open);
  });
  // keyring.json only comes back once unlocked; while locked, reopening it would just raise the prompt again.
  if (previouslyOpen && names.includes(previouslyOpen) && (previouslyOpen !== keyringPath || loaded)) show(previouslyOpen, { open: true });
  else { updateFilesHeader(); display.classList.add("hidden"); field.textContent = ""; }
  // The Files tab (#files-manager)'s own visibility is derived from the
  // application-tab selection (see selectApplicationTab), not from this
  // function -- it only ever populates content, never shows/hides the pane
  // itself, so a background refresh here can't pop the tab open on its own.
}

function displayKeyringJsonTemporarily(masterSeed) {
  const keyring = keyringJson(masterSeed);
  closeKeyringPasswordPrompt();
  const display = query("#identity-file-display");
  const field = query("#identity-file-content");
  display.classList.remove("hidden");
  field.textContent = JSON.stringify(keyring, null, 2);
  output("#loaded-identity-message", "keyring.json is visible for 60 seconds.");
  sensitiveFileTimer = setTimeout(() => {
    field.textContent = "";
    display.classList.add("hidden");
    output("#loaded-identity-message", "keyring.json was hidden.");
  }, 60_000);
}

function closeKeyringPasswordPrompt() {
  query("#identity-keyring-password").classList.add("hidden");
  query("#identity-keyring-password-input").value = "";
  query("#identity-keyring-passkey").classList.add("hidden");
}

query("#identity-keyring-password-cancel").addEventListener("click", closeKeyringPasswordPrompt);
query("#identity-keyring-passkey-cancel").addEventListener("click", closeKeyringPasswordPrompt);
// Click-outside-to-close for the menu view: any click that actually landed
// on one of its own controls (a menu item, empty space, the hamburger
// itself) already flips menuViewActive to false via its own handler before
// the event bubbles up here (or stops propagation, for the hamburger), so
// this only ever fires -- and only ever does something -- for a genuine
// click elsewhere on the page.
document.addEventListener("click", () => {
  if (menuViewActive) setMenuView(false);
});

// Hover/focus help for [data-toast] elements is pure CSS now (a speech
// bubble above the element, drawn from the attribute -- see "identity card"
// in styles.css); #context-toast only carries action results.

onClick("#identity-keyring-passkey-unlock", "#loaded-identity-message", async () => {
  let masterSeed;
  try {
    if (!identityFilesView?.keyringPath || identityFilesView.selected !== identityFilesView.keyringPath) throw new Error("Select keyring.json first.");
    if (draft?.protector && draft.material?.masterSeed) {
      masterSeed = new Uint8Array(draft.material.masterSeed);
    } else {
      throw new Error("This identity is not passkey-protected.");
    }
    displayKeyringJsonTemporarily(masterSeed);
  } finally {
    wipe(masterSeed);
  }
});

query("#identity-keyring-password").addEventListener("submit", async event => {
  event.preventDefault();
  const submit = event.currentTarget.querySelector("button[type=submit]");
  submit.disabled = true;
  let masterSeed;
  try {
    if (!identityFilesView?.keyringPath || identityFilesView.selected !== identityFilesView.keyringPath) throw new Error("Select keyring.json first.");
    const password = query("#identity-keyring-password-input").value;
    if (draft?.material?.masterSeed && password === draft.password) {
      masterSeed = new Uint8Array(draft.material.masterSeed);
    } else {
      throw new Error("Incorrect password.");
    }
    displayKeyringJsonTemporarily(masterSeed);
  } catch (error) {
    output("#loaded-identity-message", errorMessage(error), true);
  } finally {
    wipe(masterSeed);
    submit.disabled = false;
  }
});

function fact(label, value, valueClass = "") {
  const fragment = document.createDocumentFragment();
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  if (value instanceof Node) description.append(value);
  else description.textContent = value;
  if (valueClass) description.className = valueClass;
  fragment.append(term, description);
  return fragment;
}

function encryptedMetadataPanel(entries) {
  const panel = document.createElement("section");
  panel.className = "encrypted-metadata";
  const heading = document.createElement("h5");
  heading.textContent = "Encrypted keyring metadata";
  const details = document.createElement("dl");
  details.className = "fields";
  for (const [label, value] of entries) details.append(fact(label, value));
  panel.append(heading, details);
  return panel;
}

function grantDate(value) {
  const time = Date.parse(value);
  return Number.isNaN(time) ? value : new Date(time).toLocaleString();
}

// Scope as tags (same look as the Authorize card).
function scopeTags(scopes) {
  const box = document.createElement("span");
  box.className = "scope-tags";
  box.append(...scopes.map(scope => { const tag = document.createElement("code"); tag.textContent = scope; return tag; }));
  return box;
}

// The card heading: the name given when approving (else what the app calls itself, else its
// host), with a pencil to rename it. The name is browser-local, stored with the grant.
function appNameHeading(grants, bindingsByDevice, clientName) {
  const heading = document.createElement("h4");
  heading.className = "device-card-name";
  const fallback = didHost(clientName) ?? clientName;
  const stored = grants.find(grant => grant.label)?.label
    ?? grants.map(grant => bindingsByDevice.get(`${grant.did}\n${grant.deviceJkt}`)?.label).find(Boolean);
  const text = document.createElement("span");
  text.textContent = stored ?? fallback;
  const input = document.createElement("input");
  input.className = "hidden";
  input.maxLength = 160;
  input.setAttribute("aria-label", "App name (stored only in this browser)");
  for (const [name, value] of [["autocomplete", "off"], ["data-1p-ignore", ""], ["data-lpignore", "true"], ["data-bwignore", ""], ["data-form-type", "other"], ["data-protonpass-ignore", "true"]]) input.setAttribute(name, value);
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "wallet-authorize-edit";
  edit.setAttribute("aria-label", "Rename");
  edit.innerHTML = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"></path></svg>`;
  edit.addEventListener("mousedown", event => event.preventDefault());
  let editing = false;
  const finish = async save => {
    if (!editing) return;
    editing = false;
    const label = input.value.trim() || fallback;
    input.classList.add("hidden");
    text.classList.remove("hidden");
    if (!save || label === text.textContent) return;
    try {
      for (const grant of grants) {
        await saveWalletOAuthGrant({ ...grant, label });
        const binding = bindingsByDevice.get(`${grant.did}\n${grant.deviceJkt}`);
        if (binding) await saveWalletDeviceBinding({ ...binding, label });
      }
      text.textContent = label;
    } catch (error) {
      output("#loaded-identity-message", `Could not rename: ${errorMessage(error)}`, true);
    }
  };
  edit.addEventListener("click", () => {
    if (editing) { void finish(true); return; }
    editing = true;
    input.value = text.textContent;
    text.classList.add("hidden");
    input.classList.remove("hidden");
    input.focus();
    input.select();
  });
  input.addEventListener("keydown", event => {
    if (event.key === "Enter") { event.preventDefault(); void finish(true); }
    else if (event.key === "Escape") { event.stopPropagation(); void finish(false); }
  });
  input.addEventListener("blur", () => void finish(true));
  heading.append(text, input, edit);
  return heading;
}

async function renderWalletGrants() {
  const target = query("#wallet-grant-list");
  if (!target) return;
  target.replaceChildren();
  try {
    const activeDid = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
    const [allOauthGrants, allDeviceBindings] = await Promise.all([listWalletOAuthGrants(), listWalletDeviceBindings()]);
    // There is one local identity. Filter defensively so an old browser
    // database created by a previous app version cannot leak its labels.
    const oauthGrants = activeDid ? allOauthGrants.filter(grant => grant.did === activeDid) : [];
    const deviceBindings = activeDid ? allDeviceBindings.filter(binding => binding.did === activeDid) : [];
    if (!oauthGrants.length) return;
    const bindingsByDevice = new Map(deviceBindings.map(binding => [`${binding.did}\n${binding.deviceJkt}`, binding]));
    // One card per app (clientId). saveWalletOAuthGrant already keeps at
    // most one stored grant per (did, clientId, deviceJkt), so what
    // remains to group here is genuinely different devices/sessions of the
    // same app -- not repeat approvals from the same one.
    const byClient = new Map();
    for (const grant of oauthGrants) {
      // Apps behind one relying party (Forgejo and Outline behind one bridge) share a clientId; appKey splits them.
      const key = `${grant.clientId}\n${grant.appKey ?? ""}`;
      const forClient = byClient.get(key) ?? [];
      forClient.push(grant);
      byClient.set(key, forClient);
    }
    for (const grants of byClient.values()) {
      const [{ clientName }] = grants;
      const card = document.createElement("div");
      card.className = "record-card device-card";
      // There is no revocation (a capability is short-lived and expires by itself): the trash
      // icon only removes the record kept in this browser.
      const headingRow = document.createElement("div");
      headingRow.className = "record-card-heading";
      const forget = document.createElement("span");
      forget.className = "identity-name-copy";
      forget.setAttribute("role", "button");
      forget.tabIndex = 0;
      forget.setAttribute("aria-label", "Forget this app");
      forget.title = "Removes this record from this browser. It does not revoke access; the session expires on its own.";
      forget.append(trashIcon());
      const forgetApp = async () => {
        try {
          await deleteWalletOAuthGrants(grants.map(grant => grant.id));
          await renderWalletGrants();
        } catch (error) { output("#loaded-identity-message", `Could not forget: ${errorMessage(error)}`, true); }
      };
      // The trash icon asks "Remove? [yes]" in its place; anything else (Esc, a click elsewhere) puts the icon back.
      const confirmRow = document.createElement("span");
      confirmRow.className = "record-card-confirm hidden";
      const ask = document.createElement("span");
      ask.textContent = "Remove?";
      const yes = document.createElement("button");
      yes.type = "button";
      yes.className = "link-like";
      yes.textContent = "yes";
      confirmRow.append(ask, yes);
      const setConfirming = confirming => {
        forget.classList.toggle("hidden", confirming);
        confirmRow.classList.toggle("hidden", !confirming);
        if (confirming) yes.focus();
        else forget.focus();
      };
      forget.addEventListener("click", () => setConfirming(true));
      forget.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setConfirming(true); } });
      yes.addEventListener("click", () => void forgetApp());
      confirmRow.addEventListener("keydown", event => { if (event.key === "Escape") { event.stopPropagation(); setConfirming(false); } });
      confirmRow.addEventListener("focusout", event => {
        if (!confirmRow.contains(event.relatedTarget)) { forget.classList.remove("hidden"); confirmRow.classList.add("hidden"); }
      });
      headingRow.append(appNameHeading(grants, bindingsByDevice, clientName), forget, confirmRow);
      card.append(headingRow);
      // Where the app lives, as its relying party asserted (the vouching RP is the Via row below).
      const appKey = grants.find(grant => grant.appKey)?.appKey;
      if (appKey) {
        const source = document.createElement("p");
        source.className = "hint app-card-source";
        source.textContent = appKey;
        card.append(source);
      }
      for (const grant of grants) {
        const binding = bindingsByDevice.get(`${grant.did}\n${grant.deviceJkt}`);
        // Both are stored under the same capability id (see saveWalletOAuthGrant
        // / saveApplicationAuthorizationMetadata) -- correlating by id, not
        // deviceJkt, also works for a non-DPoP grant, which has no device key
        // to correlate by at all.
        const applicationReferences = portableApplications.filter(application => application.id === grant.id);
        const usedServices = [...new Set(applicationReferences.flatMap(application => (application.services ?? []).map(service => service.id)))];
        const usedKeys = [...new Set(applicationReferences.flatMap(application => application.keyIds))];
        // The app's name is the card's heading; a per-device heading only earns its place when
        // the same app has several devices/sessions to tell apart.
        const device = fieldGroup(grants.length > 1 ? (binding?.label ?? (grant.deviceJkt ? "Device" : "Via")) : null, [
          ["Scope", scopeTags(grant.scope)],
          ...(binding?.didCommKeyId ? [["DIDComm key", binding.didCommKeyId]] : []),
          [grant.deviceJkt ? "Device thumbprint" : "Via", grant.deviceJkt ?? grant.clientName],
          ["Capability ID", grant.id],
        ]);
        const meta = document.createElement("p");
        meta.className = "storage-state sealed";
        meta.textContent = grant.importedAt ? `Imported audit record · this browser has no DPoP key` : `Active until ${grantDate(grant.expiresAt)}`;
        device.insertBefore(meta, device.querySelector(".fields"));
        if (usedServices.length || usedKeys.length) device.append(encryptedMetadataPanel([
          ["Uses services", usedServices.length ? usedServices.join("\n") : "None"],
          ["Uses keys", usedKeys.length ? usedKeys.join("\n") : "None"],
        ]));
        card.append(device);
      }
      target.append(card);
    }
  } catch (error) {
    const message = document.createElement("p");
    message.className = "hint";
    message.textContent = `Could not read session capability metadata: ${errorMessage(error)}`;
    target.append(message);
  }
}

function walletDeviceBindingId(did, deviceJkt) {
  return `device:${did}:${deviceJkt}`;
}

function requestedDeviceLabel(fallback) {
  const input = query("#wallet-authorize-device-label");
  const label = input?.value.trim() ?? "";
  if (label.length > 160) throw new Error("Device label must be at most 160 characters.");
  return label || fallback;
}

async function saveAuthorizedDeviceBinding({ did, deviceJkt, clientName, didCommKeyId }) {
  await saveWalletDeviceBinding({
    v: 1,
    id: walletDeviceBindingId(did, deviceJkt),
    did,
    deviceJkt,
    label: requestedDeviceLabel(clientName),
    clientName,
    ...(didCommKeyId ? { didCommKeyId } : {}),
    createdAt: new Date().toISOString(),
  });
}

async function saveApplicationAuthorizationMetadata({ capability, edit, appKey }) {
  if (!loaded?.record) return;
  const applications = await readPortableApplications(loaded.record, loaded.masterSeed);
  const application = {
    v: 1,
    id: capability.id,
    clientId: capability.audience,
    clientName: walletAuthorization.clientName,
    ...(capability.deviceJkt ? { deviceJkt: capability.deviceJkt } : {}),
    ...(appKey ? { appKey } : {}),
    serviceIds: edit?.services?.map(service => service.id) ?? [],
    keyIds: edit?.verificationMethods?.map(method => method.id) ?? [],
    services: edit?.serviceKeyBindings?.map(binding => ({ id: binding.serviceId, keyIds: [...binding.keyIds] })) ?? [],
    createdAt: capability.issuedAt,
  };
  // Same replace-by-(clientId, deviceJkt) semantics as saveWalletOAuthGrant:
  // re-authorizing the same app from the same device supersedes its
  // previous metadata record instead of leaving it behind under its old
  // (now orphaned) capability.id -- filtering only by id never matched,
  // since every approval mints a fresh capability.id.
  const survivors = applications.filter(item => !(item.clientId === application.clientId && item.deviceJkt === application.deviceJkt && item.appKey === application.appKey));
  loaded.record = await savePortableApplications(loaded.record, loaded.masterSeed, [...survivors, application]);
  portableApplications = [...survivors, application];
}

function scidFromDid(did) {
  const match = /^did:webvh:([^:]+):/.exec(did);
  if (!match) throw new Error("Could not derive an SCID filename from this DID.");
  return match[1];
}

// Shows the method prefix followed by the {scid} segment. The host remains
// omitted here since the full DID is carried (for password-manager pairing)
// in the offscreen username field.
function renderDidWithScid(element, did) {
  let scid;
  try { scid = scidFromDid(did); } catch { renderDidValue(element, did); return; }
  const suffix = did.slice(`did:webvh:${scid}:`.length);
  const prefix = document.createElement("span");
  prefix.className = "did-prefix";
  prefix.textContent = "did:webvh:";
  const span = document.createElement("span");
  span.className = "did-scid";
  span.textContent = scid;
  const suffixSpan = document.createElement("span");
  suffixSpan.className = "did-suffix";
  suffixSpan.textContent = `:${suffix}`;
  element.replaceChildren(prefix, span, suffixSpan);
  element.dataset.defaultSuffix = suffix;
  element.title = did;
}

function renderDidValue(element, did) {
  element.textContent = did;
  element.title = did;
}

// Truncates "did:webvh:{scid}" from the right to whatever room is left in
// the did-line row once its plain, unshrinkable neighbors (the copy icon,
// the ":" and the alias) are accounted for. The room is measured from the
// row itself, not from headElement's own box: headElement is a plain
// inline-block sized to its *current* text, so measuring itself would be
// circular -- once shortened, it forgets how much wider it is allowed to
// grow back to when the window widens again. Measures with a canvas (not
// just character-counting) so this holds for any font. Re-fits live via
// ResizeObserver on the row.
let didHeadMeasureContext = null;
let didHeadResizeObserver = null;

function fitDidHead(headElement) {
  const full = headElement._didHeadFull;
  if (full == null) return;
  const row = headElement.closest(".identity-did-row");
  const copyButton = headElement.closest("#identity-did-copy");
  const icon = copyButton.querySelector(".copy-icon");
  const colon = row.querySelector('.identity-did[aria-hidden="true"]');
  const alias = row.querySelector(".identity-did-alias");
  const buttonStyle = getComputedStyle(copyButton);
  const reserved = (icon?.getBoundingClientRect().width ?? 0)
    + parseFloat(buttonStyle.columnGap || buttonStyle.gap || "0")
    + parseFloat(buttonStyle.paddingLeft) + parseFloat(buttonStyle.paddingRight)
    + (colon?.getBoundingClientRect().width ?? 0)
    + (alias?.getBoundingClientRect().width ?? 0);
  const available = row.clientWidth - reserved;
  if (available <= 0) { headElement.textContent = ""; headElement.style.maxWidth = "0px"; return; }
  didHeadMeasureContext ??= document.createElement("canvas").getContext("2d");
  const style = getComputedStyle(headElement);
  didHeadMeasureContext.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
  if (didHeadMeasureContext.measureText(full).width <= available) {
    headElement.style.maxWidth = "";
    headElement.textContent = full;
    return;
  }
  const ellipsis = "…";
  let low = 0, high = full.length;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (didHeadMeasureContext.measureText(`${full.slice(0, mid)}${ellipsis}`).width <= available) low = mid;
    else high = mid - 1;
  }
  headElement.style.maxWidth = `${available}px`;
  headElement.textContent = `${full.slice(0, low)}${ellipsis}`;
}

// Splits "did:webvh:{scid}:{alias}" across the three independently
// clickable/plain pieces that make up the did-line (see dashboard.html):
// headElement gets "did:webvh:{scid}" (copy target, truncated by
// fitDidHead), the ":" between them is static markup owned by neither span,
// and aliasElement gets "{alias}" alone (its own click target -- opens the
// hosted did.jsonl -- so it must never be truncated away by the head).
function renderDidLine(headElement, aliasElement, did) {
  const match = /^(did:webvh:[^:]+):(.+)$/.exec(did);
  if (!match) { renderDidValue(headElement, did); aliasElement.textContent = ""; return; }
  const [, head, alias] = match;
  headElement._didHeadFull = head;
  headElement.title = did;
  aliasElement.textContent = alias;
  const row = headElement.closest(".identity-did-row");
  didHeadResizeObserver ??= new ResizeObserver(entries => {
    for (const entry of entries) fitDidHead(headElement);
  });
  didHeadResizeObserver.observe(row);
  fitDidHead(headElement);
}

// The SCID is this identity's only permanent identifier -- the domain
// segment of a did:webvh DID changes (genesis -> a real host, or one
// host to another), so nothing is keyed by it. Local storage is always keyed
// by a hash of the SCID, unrelated to whatever host currently serves it.
async function storageKeyForDid(did) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(scidFromDid(did))));
  return [...digest].map(byte => byte.toString(16).padStart(2, "0")).join("").slice(0, 48);
}

// This identity's did.md subdomain, derived from its current DID -- or null
// if it is not (or not yet) hosted on did.md.
function didMdUsername(did) {
  const match = new RegExp(`^did:webvh:[^:]+:([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\\.${DOMAIN.replace(/\./g, "\\.")}$`).exec(did);
  return match ? match[1] : null;
}

function downloadWalletBackup(contents, did) {
  const blob = new Blob([contents], { type: "application/jose" });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = `${scidFromDid(did)}.jwe`;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(href), 1000);
}

// Container paths are keyed by the SCID, which is the identity: no username,
// and unchanged when the DID moves between hosts.
function containerPath(did, name) {
  return `identities/${scidFromDid(did)}/${name}`;
}

/** Containers v1/v2 keyed their files by a did.md username; read-only, so old exports still recover. */
function legacyContainerPath(username, name) {
  return `identities/${username}/${name}`;
}

async function fetchCompleteDidLog(record) {
  const response = await fetch(hostLogUrl(record.did), { cache: "no-store" });
  if (!response.ok) throw new Error(`Could not read the complete DID log for ${record.did}.`);
  const didJsonl = await response.text();
  if (didJsonl.length > 16 * 1024 * 1024) throw new Error(`The DID log for ${record.did} exceeds the container limit.`);
  const entries = parseLog(didJsonl);
  const latest = entries.at(-1);
  if (!latest?.state || latest.state.id !== record.did || latest.versionId !== record.generation) {
    throw new Error(`The public DID log for ${record.did} no longer matches this local keyring. Load it and publish or refresh before exporting.`);
  }
  return didJsonl;
}

// The container's two non-secret metadata parts, shared between the real
// export (createIdentityContainer) and the Files tab's live "loaded/" tree
// (restoreStoredIdentityRecord, activateLoadedIdentity) -- both need to
// agree on what's actually in a container, not just the export path.
async function metadataContainerFiles(did) {
  const [allOauth, allDeviceBindings] = await Promise.all([listWalletOAuthGrants(), listWalletDeviceBindings()]);
  return {
    "metadata/device-bindings.json": allDeviceBindings.filter(binding => binding.did === did).map(binding => ({ ...binding })),
    "metadata/grants.json": { oauth: allOauth.filter(grant => grant.did === did).map(grant => ({ ...grant })) },
  };
}

/** Current portable identity container v2. The keyring is direct portable
 * material inside the outer JWE, never a did.md IndexedDB vault ciphertext. */
async function createIdentityContainer(masterSeed) {
  const activeUsername = storedIdentityRecord?.username;
  if (!activeUsername) throw new Error("Load an identity before exporting its container.");
  const activeRecord = await readStoredIdentity(activeUsername);
  if (!activeRecord) throw new Error("The signed-in identity has no local keyring.");
  if (![4, 5].includes(activeRecord.v) || masterSeed?.length !== 32) throw new Error("A Master-derived local identity is required for portable export.");
  const root = await rootFromMasterSeed(masterSeed);
  if (root.multikey !== activeRecord.rootKey) throw new Error("The supplied Master does not match this local identity.");
  // A container is for the identity that is currently signed in. Other
  // IndexedDB records may be independent identities and must not affect its
  // export or make an unrelated stale public log block recovery -- see
  // metadataContainerFiles' own did-scoped filtering.
  const applications = await readPortableApplications(activeRecord, masterSeed);
  const didJsonl = await fetchCompleteDidLog(activeRecord);
  const files = await metadataContainerFiles(activeRecord.did);
  const didLogPath = containerPath(activeRecord.did, "did.jsonl");
  const keyringPath = containerPath(activeRecord.did, "keyring.json");
  files[didLogPath] = didJsonl;
  files[keyringPath] = {
    type: "bip39-slip10-ed25519",
    masterEntropy: base64url(masterSeed),
    derivationProfile: "did.md/master-ed25519-v1",
    applications,
  };
  const identities = [{
    did: activeRecord.did,
    rootKey: root.multikey,
    generation: activeRecord.generation,
    didLogPath,
    keyringPath,
    derivationProfile: "did.md/master-ed25519-v1",
  }];
  const container = {
    format: "did.md/identity-container",
    version: 3,
    manifest: {
      format: "did.md/identity-container",
      version: 3,
      createdAt: new Date().toISOString(),
      identities,
      contents: [...identities.flatMap(identity => [identity.didLogPath, identity.keyringPath]), "metadata/device-bindings.json", "metadata/grants.json"],
    },
    files,
  };
  wipe(root.privateKey);
  return container;
}

function containerString(value, label, maximum = 4096) {
  if (typeof value !== "string" || !value || value.length > maximum) throw new Error(`Identity container ${label} is invalid.`);
  return value;
}

/** Reads the first container version, whose keyring was a did.md local vault
 * record. Retained solely so users can recover existing exports. */
function checkedIdentityContainerV1(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.format !== "did.md/identity-container" || value.version !== 1
    || !value.manifest || typeof value.manifest !== "object" || Array.isArray(value.manifest)
    || value.manifest.format !== "did.md/identity-container" || value.manifest.version !== 1
    || !Array.isArray(value.manifest.identities) || value.manifest.identities.length !== 1
    || !value.files || typeof value.files !== "object" || Array.isArray(value.files)) {
    throw new Error("This is not a supported did.md identity container.");
  }
  const identities = value.manifest.identities.map(identity => {
    if (!identity || typeof identity !== "object" || Array.isArray(identity)) throw new Error("Identity container manifest is invalid.");
    const username = containerString(identity.username, "username", 64);
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(username)) throw new Error("Identity container username is invalid.");
    const did = containerString(identity.did, "DID");
    const generation = containerString(identity.generation, "generation", 512);
    const didLogPath = containerString(identity.didLogPath, "DID log path", 256);
    const keyringPath = containerString(identity.keyringPath, "keyring path", 256);
    if (didLogPath !== legacyContainerPath(username, "did.jsonl") || keyringPath !== legacyContainerPath(username, "keyring.json")) {
      throw new Error("Identity container paths are invalid.");
    }
    const didJsonl = value.files[didLogPath];
    if (typeof didJsonl !== "string" || didJsonl.length > 16 * 1024 * 1024) throw new Error("Identity container DID log is invalid.");
    const entries = parseLog(didJsonl);
    const latest = entries.at(-1);
    if (!latest?.state || latest.state.id !== did || latest.versionId !== generation) throw new Error("Identity container DID log does not match its manifest.");
    return { username, did, generation, didJsonl, keyring: value.files[keyringPath] };
  });
  const deviceBindings = value.files["metadata/device-bindings.json"];
  const grants = value.files["metadata/grants.json"];
  if (!Array.isArray(deviceBindings) || !grants || typeof grants !== "object" || Array.isArray(grants)
    || !Array.isArray(grants.oauth)
    || deviceBindings.length > 1024 || grants.oauth.length > 4096) {
    throw new Error("Identity container metadata is invalid.");
  }
  return { version: 1, identities, deviceBindings, oauth: grants.oauth };
}

/** v2 is platform-independent: the outer JWE contains direct BIP39 entropy
 * and the documented SLIP-0010 profile, not any browser storage envelope. */
function checkedIdentityContainer(value) {
  if (value?.version === 1) return checkedIdentityContainerV1(value);
  const version = value?.version;
  if (!value || typeof value !== "object" || Array.isArray(value) || value.format !== "did.md/identity-container" || (version !== 2 && version !== 3)
    || !value.manifest || typeof value.manifest !== "object" || Array.isArray(value.manifest)
    || value.manifest.format !== "did.md/identity-container" || value.manifest.version !== version
    || !Array.isArray(value.manifest.identities) || value.manifest.identities.length !== 1
    || !value.files || typeof value.files !== "object" || Array.isArray(value.files)) {
    throw new Error("This is not a supported did.md identity container.");
  }
  const identities = value.manifest.identities.map(identity => {
    if (!identity || typeof identity !== "object" || Array.isArray(identity)) throw new Error("Identity container manifest is invalid.");
    // v2 keyed its files by a did.md username; v3 by the SCID and has no username at all.
    let username;
    if (version === 2) {
      username = containerString(identity.username, "username", 64);
      if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(username)) throw new Error("Identity container username is invalid.");
    }
    const did = containerString(identity.did, "DID");
    const rootKey = containerString(identity.rootKey, "Root Key");
    const generation = containerString(identity.generation, "generation", 512);
    const didLogPath = containerString(identity.didLogPath, "DID log path", 256);
    const keyringPath = containerString(identity.keyringPath, "keyring path", 256);
    const expectedLog = version === 2 ? legacyContainerPath(username, "did.jsonl") : containerPath(did, "did.jsonl");
    const expectedKeyring = version === 2 ? legacyContainerPath(username, "keyring.json") : containerPath(did, "keyring.json");
    if (identity.derivationProfile !== "did.md/master-ed25519-v1" || didLogPath !== expectedLog || keyringPath !== expectedKeyring) {
      throw new Error("Identity container paths or derivation profile are invalid.");
    }
    const didJsonl = value.files[didLogPath];
    if (typeof didJsonl !== "string" || didJsonl.length > 16 * 1024 * 1024) throw new Error("Identity container DID log is invalid.");
    const entries = parseLog(didJsonl);
    const latest = entries.at(-1);
    if (!latest?.state || latest.state.id !== did || latest.versionId !== generation) throw new Error("Identity container DID log does not match its manifest.");
    const keyring = value.files[keyringPath];
    if (!keyring || typeof keyring !== "object" || Array.isArray(keyring) || keyring.type !== "bip39-slip10-ed25519" || keyring.derivationProfile !== "did.md/master-ed25519-v1") {
      throw new Error("Identity container keyring is invalid.");
    }
    const masterSeed = base64urlBytes(keyring.masterEntropy, "Master entropy");
    if (masterSeed.length !== 32) throw new Error("Identity container Master entropy must be 32 bytes.");
    const applications = keyring.applications === undefined ? [] : keyring.applications;
    if (!Array.isArray(applications) || applications.length > 1024) throw new Error("Identity container application metadata is invalid.");
    return { username, did, rootKey, generation, didJsonl, entries, masterSeed, applications };
  });
  const deviceBindings = value.files["metadata/device-bindings.json"];
  const grants = value.files["metadata/grants.json"];
  if (!Array.isArray(deviceBindings) || !grants || typeof grants !== "object" || Array.isArray(grants)
    || !Array.isArray(grants.oauth)
    || deviceBindings.length > 1024 || grants.oauth.length > 4096) {
    throw new Error("Identity container metadata is invalid.");
  }
  return { version, identities, deviceBindings, oauth: grants.oauth };
}

async function importIdentityContainer(contents, masterSeed, protection) {
  const container = await decryptIdentityContainer(contents, masterSeed);
  const parsed = checkedIdentityContainer(container);
  const importedAt = new Date().toISOString();
  const identity = parsed.identities[0];
  // Local storage is keyed by a hash of the SCID; v1/v2 carried a username that was that key (or, in old exports, a handle).
  const storageKey = identity.username ?? await storageKeyForDid(identity.did);
  let record;
  if (parsed.version === 1) {
    // Validate the encrypted local record before replacing anything.
    record = exportIdentityKeyringRecord(identity.keyring);
  } else {
    let root;
    try {
      root = await rootFromMasterSeed(identity.masterSeed);
      if (root.multikey !== identity.rootKey || !identity.entries[0]?.parameters?.updateKeys?.includes(root.multikey)) {
        throw new Error("Identity container Master entropy does not match the DID log.");
      }
    } finally {
      wipe(root?.privateKey);
    }
  }
  // A container is now the explicit replacement boundary: first validate it,
  // then remove the preceding identity as a complete local unit.
  clearLoadedIdentitySession();
  await clearBrowserIdentityState();
  if (parsed.version === 1) {
    await restoreIdentityKeyringRecord(record);
  } else {
    try {
      let savedRecord;
      if (protection?.protector) {
        savedRecord = await saveMasterStoredIdentity({ username: storageKey, did: identity.did, rootKey: identity.rootKey, generation: identity.generation, masterSeed: identity.masterSeed, protector: protection.protector });
      } else {
        savedRecord = await savePasswordStoredIdentity({ username: storageKey, did: identity.did, rootKey: identity.rootKey, generation: identity.generation, masterSeed: identity.masterSeed, password: protection?.password });
      }
      if (identity.applications.length) await savePortableApplications(savedRecord, identity.masterSeed, identity.applications);
    } finally {
      wipe(identity.masterSeed);
    }
  }
  await saveDidLogSnapshot({ username: storageKey, did: identity.did, generation: identity.generation, didJsonl: identity.didJsonl, savedAt: importedAt });
  // Device keys themselves are deliberately absent. These are display-only
  // audit records and identify that they cannot restore a live session.
  await Promise.all([
    ...parsed.deviceBindings.map(binding => saveWalletDeviceBinding(binding)),
    ...parsed.oauth.map(grant => saveWalletOAuthGrant({ ...grant, importedAt })),
  ]);
  renderIdentityFiles(container);
  await refreshIdentityViews();
  void renderLoadedIdentity();
  return { ...parsed, restoredKeyrings: 1 };
}

async function refreshIdentityViews() {
  await renderWalletGrants();
}

function endpoint(did, file = "did.jsonl") {
  const username = didMdUsername(did);
  if (!username) throw new Error("This identity is not hosted on did.md.");
  return `https://${username}.${DOMAIN}/.well-known/${file}`;
}

/** Public DID-log URL for any host (did.md or GitHub). Prefer this for GETs. */
function hostLogUrl(did) {
  return hostForDid(did).logUrl(did);
}

// Same idea as endpoint(), for a resource served at the host's root instead
// of under .well-known (e.g. routing.json).
function rootResource(did, file) {
  const username = didMdUsername(did);
  if (!username) throw new Error("This identity is not hosted on did.md.");
  return `https://${username}.${DOMAIN}/${file}`;
}

// The did:webvh log mechanics (parse, validate, parameters) are didwebvh-ts's,
// through packages/webvh.
function parseLog(text) {
  if (!text.endsWith("\n")) throw new Error("Public log was not found.");
  return parseWebvhLog(text);
}

function rootIsPublished(state, rootKey) {
  return Array.isArray(state.verificationMethod)
    && state.verificationMethod.some(method => method && method.publicKeyMultibase === rootKey);
}

async function publish(url, method, body) {
  const response = await fetch(url, { method, headers: { "content-type": "text/jsonl" }, body });
  if (!response.ok) throw new Error(await response.text() || `Publication failed (${response.status})`);
  return response;
}

function sameDidDocumentReference(did, left, right) {
  const absolute = value => typeof value === "string" && value.startsWith("#") ? `${did}${value}` : value;
  return absolute(left) === absolute(right);
}

function withRoutingInDidDocument(state, edit) {
  const next = JSON.parse(JSON.stringify(state));
  const isRemoved = id => edit.remove.some(removed => sameDidDocumentReference(state.id, id, removed));
  const methods = (Array.isArray(next.verificationMethod) ? next.verificationMethod : []).filter(value => !isRemoved(value.id));
  for (const method of edit.verificationMethods) { const index = methods.findIndex(value => sameDidDocumentReference(state.id, value.id, method.id)); if (index < 0) methods.push(method); else methods[index] = method; }
  next.verificationMethod = methods;
  const keyAgreement = (Array.isArray(next.keyAgreement) ? next.keyAgreement : []).filter(id => !isRemoved(id));
  for (const method of edit.verificationMethods) if (!keyAgreement.some(id => sameDidDocumentReference(state.id, id, method.id))) keyAgreement.push(method.id);
  if (keyAgreement.length) next.keyAgreement = keyAgreement;
  const services = (Array.isArray(next.service) ? next.service : []).filter(value => !isRemoved(value.id));
  for (const service of edit.services) { const index = services.findIndex(value => sameDidDocumentReference(state.id, value.id, service.id)); if (index < 0) services.push(service); else services[index] = service; }
  next.service = services;
  return next;
}

/** A routing change is also a did:webvh state change during this temporary
 * compatibility mode. The Wallet, never the host, creates the signed entry. */
async function publishRoutingDidUpdate(state) {
  if (!loaded) throw new Error("Load an identity first.");
  const prepared = await preparePreRotatedUpdate({
    entries: loaded.entries, state, masterSeed: loaded.masterSeed, currentSpareIndex: loaded.currentSpareIndex,
  });
  const nextEntries = [...loaded.entries, prepared.entry];
  const published = await publishEntriesToCurrentHost(
    nextEntries,
    `Publish routing ${prepared.entry.versionId}`,
    "append",
    () => publishRoutingDidUpdate(state),
  );
  if (published !== "published") return;
  loaded.entries = nextEntries;
  loaded.parameters = currentParameters(loaded.entries);
  loaded.sign = await spareFromMasterSeed(loaded.masterSeed, loaded.currentSpareIndex);
  loaded.currentSpareIndex = prepared.nextSpareIndex;
  await persistMasterMetadata();
  updateKeyStatus();
}

async function publishRoutingResource(did, routing, created = new Date().toISOString()) {
  if (!loaded) throw new Error("Load an identity first.");
  const proof = await createDataIntegrityProof(routing, {
    privateKey: loaded.sign.privateKey,
    verificationMethod: `did:key:${loaded.sign.multikey}#${loaded.sign.multikey}`,
    proofPurpose: "assertionMethod", created,
  });
  const response = await fetch(rootResource(did, "routing.json"), {
    method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...routing, proof }),
  });
  if (!response.ok) throw new Error(`Could not publish routing metadata (${response.status}): ${await response.text()}`);
}

function currentMasterPath() {
  return `m/1'/${loaded.currentSpareIndex}'`;
}

function localKeyCard(name, state, path, multikey) {
  const card = document.createElement("article");
  card.className = "record-card local-key-card";
  const heading = document.createElement("h4");
  heading.textContent = name;
  const details = document.createElement("dl");
  details.className = "fields";
  details.append(
    fact("State", state),
    fact("Derivation", path),
    fact("Public multikey", multikey, "multikey-value"),
  );
  card.append(heading, details);
  return card;
}

// Fire-and-forget (called as `void renderLocalKeyMaterial()` from
// updateKeyStatus(), which itself can legitimately run twice in a row for
// one action -- e.g. Rotate key's own success path, once inside
// publishPreparedEntry() and once from the click handler's finally). Two
// overlapping calls would otherwise both clear #local-key-material-list up
// front, then both append after their own await, doubling every card. This
// token makes only the most recently started call actually render.
let localKeyMaterialToken = 0;
async function renderLocalKeyMaterial() {
  const list = query("#local-key-material-list");
  if (!list) return;
  const token = ++localKeyMaterialToken;
  list.replaceChildren();
  if (!loaded) return;
  const session = loaded;
  const rotationCount = Math.max(0, session.entries.length - 1);
  const signPath = rotationCount === 0 ? "m/0'" : `m/1'/${session.currentSpareIndex - 1}'`;
  let spare;
  try {
    // Derive only long enough to display its public multikey.  The next
    // private key is never retained by this view.
    spare = await spareFromMasterSeed(session.masterSeed, session.currentSpareIndex);
    if (loaded !== session || token !== localKeyMaterialToken) return;
    const rotationState = rotationCount === 0
      ? "Genesis — no rotation published"
      : `Activated by rotation ${rotationCount} · ${session.entries.at(-1).versionTime}`;
    list.append(
      localKeyCard("Root key", "Permanent key for authentication", "m/0'", session.root.multikey),
      localKeyCard("Sign key", rotationState, signPath, session.sign.multikey),
      localKeyCard("Spare key", "Committed for the next update", `m/1'/${session.currentSpareIndex}'`, spare.multikey),
    );
  } finally {
    wipe(spare?.privateKey);
  }
}

// endpoint()/rootResource() throw "This identity is not hosted on did.md."
// deep inside publish -- but whether that's true is knowable up front from
// the DID itself, so Rotate key checks it before ever letting the user
// click into that failure (see updateKeyStatus() below).
function isHostedOnDidMd() {
  return Boolean(didMdUsername(loaded.entries.at(-1).state.id));
}

// Reflects justRotated (see its own declaration) and isHostedOnDidMd() --
// kept separate from updateKeyStatus() so a rotation's own two internal
// calls to updateKeyStatus() (once inside publishPreparedEntry(), same as
// any other publish) don't reset the button back to "Rotate key" the
// moment they run.
function updateRotateKeyButton() {
  const button = query("#rotate-key");
  if (justRotated) {
    button.textContent = "Rotated";
    button.disabled = true;
    return;
  }
  button.textContent = "Rotate key";
  button.disabled = !isHostedOnDidMd();
}

function updateKeyStatus() {
  const target = query("#key-status");
  const enablePasskey = query("#enable-passkey");
  if (!isHostedOnDidMd() || rotateKeyFailed) {
    // Not a one-off action result (like #keys-result's own errors) -- this
    // identity's current state, same standing as the normal message below,
    // so it replaces that message rather than flashing past in a panel.
    target.textContent = "Identity should be published for key rotation.";
  } else {
    const rotationCount = Math.max(0, loaded.entries.length - 1);
    const currentSignPath = rotationCount === 0 ? "m/0'" : `m/1'/${loaded.currentSpareIndex - 1}'`;
    const strong = text => { const el = document.createElement("strong"); el.textContent = text; return el; };
    target.replaceChildren(
      "The next Sign key (Spare key), ",
      strong(currentMasterPath()),
      ", is derived from your Passphrase. Key rotation will activate it and deactivate the current Sign key, ",
      strong(currentSignPath),
      ".",
    );
  }
  enablePasskey.classList.toggle("hidden", loaded.record?.protection === "passkey" || loaded.record?.v === 5);
  enablePasskey.textContent = "Store Passphrase with a passkey";
  updateRotateKeyButton();
  void renderLocalKeyMaterial();
}

let lastCreatePhrase = "";

function showDraftPhrase() {
  const field = query("#master-mnemonic");
  const phrase = draft?.material?.masterMnemonic || lastCreatePhrase;
  if (field && phrase) {
    lastCreatePhrase = phrase;
    field.value = phrase;
    // Starts masked (type stays "password") rather than touching the
    // attribute to show it in plain text immediately -- toggled via the
    // eye button instead. No attribute churn right after the field is
    // detected is part of what gets password managers to recognize it.
    field.type = "password";
    field.placeholder = "Passphrase";
    field.dispatchEvent(new Event("input", { bubbles: true }));
  }
  query("#master-mnemonic-display")?.classList.add("hidden");
  field?.classList.remove("passphrase-field-covered");
  query("#master-mnemonic-copy-hint")?.classList.remove("hidden");
  query("#master-mnemonic-copy-feedback")?.classList.add("hidden");
  query("#master-mnemonic-eye-slash")?.classList.remove("hidden");
  query(".passphrase-copy-btn")?.classList.remove("hidden");
  query("#create-form-area")?.classList.remove("hidden");
}

function restoreHomePassphrase() {
  const field = query("#master-mnemonic");
  const homeSlot = query("#master-mnemonic-wrap");
  if (field && homeSlot && field.parentElement !== homeSlot) {
    homeSlot.prepend(field);
    field.style.height = "";
  }
  if (draft?.material?.masterMnemonic || lastCreatePhrase) {
    showDraftPhrase();
    return true;
  }
  return false;
}

function wipeCreateMaterial(material) {
  wipe(material?.masterSeed);
  wipe(material?.root?.privateKey);
  wipe(material?.sign?.privateKey);
  wipe(material?.nextSpare?.privateKey);
}


async function fetchIdentityLog(storageKey, did, logUrl) {
  let text;
  if (isProvisionalDid(did)) {
    // genesis has no host to fetch from -- its genesis entry is the
    // locally loaded data saved when it was created.
    text = (await readDidLogSnapshot(storageKey))?.didJsonl;
    if (!text) throw new Error("This identity has no locally loaded log.");
  } else {
    try {
      const response = await fetch(logUrl ?? hostLogUrl(did), { cache: "no-store" });
      if (!response.ok) throw new Error(await response.text());
      text = await response.text();
    } catch (error) {
      // The host may simply be disconnected right now -- a normal, supported
      // state (see updateConnectionStatus) -- rather than the identity being
      // gone for good. Fall back to the last log snapshot saved locally
      // (kept up to date by connectHostedData) instead of making an
      // identity permanently ununlockable whenever its host is unreachable.
      const snapshot = await readDidLogSnapshot(storageKey);
      if (!snapshot?.didJsonl) throw error;
      text = snapshot.didJsonl;
    }
  }
  const entries = parseLog(text);
  await resolveLog(entries);
  const parameters = currentParameters(entries);
  if (!Array.isArray(parameters.nextKeyHashes) || parameters.nextKeyHashes.length !== 1) {
    throw new Error("This identity does not satisfy permanent pre-rotation invariants.");
  }
  return { entries, parameters };
}

async function loadMasterIdentity(username, did, record, masterSeed, logUrl) {
  const { entries, parameters } = await fetchIdentityLog(username, did, logUrl);
  // The whole log is validated and the seed checked against it (root key,
  // pre-rotation commitment, current sign key) by packages/wallet.
  const { root, sign, currentSpareIndex } = await verifyMasterOwnsLog(entries, masterSeed);
  loaded = { username, record, masterSeed, root, sign, currentSpareIndex, entries, parameters };
}

function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

function discardPending() {
  if (!pending) return;
  wipe(pending.nextSpare?.privateKey);
  pending = null;
}

function discardLoadedIdentity() {
  if (!loaded) return;
  wipe(loaded.masterSeed);
  wipe(loaded.secrets?.masterSeed);
  wipe(loaded.secrets?.signPrivateKey);
  wipe(loaded.root?.privateKey);
  wipe(loaded.sign?.privateKey);
  loaded = null;
  portableApplications = [];
}

function clearLoadedIdentitySession() {
  if (autoLockTimer) clearTimeout(autoLockTimer);
  autoLockTimer = null;
  discardPending();
  discardLoadedIdentity();
  query("#key-editor").classList.add("hidden");
  clearIdentityFiles();
}

/** Keep persistent browser state aligned with the identity currently opened.
 * A replacement happens only after its DID log and controller material have
 * been verified. */
async function clearBrowserIdentityState() {
  await clearLocalIdentityState();
  forgetPasskeyWalletSession();
}

async function keepOnlyLoadedIdentityRecord() {
  const record = loaded?.record;
  const records = await listStoredIdentities();
  const alreadyOnlyThisRecord = record
    && records.length === 1
    && records[0].username === record.username
    && records[0].rootKey === record.rootKey;
  if (alreadyOnlyThisRecord || (!record && records.length === 0)) return;
  // Retain the current identity's non-secret descriptions while deleting
  // every trace of the older identities. A cleanup should not make the
  // current user's authorized-device labels disappear.
  const [snapshot, oauth, deviceBindings] = record ? await Promise.all([
    readDidLogSnapshot(record.username), listWalletOAuthGrants(), listWalletDeviceBindings(),
  ]) : [undefined, [], []];
  await clearBrowserIdentityState();
  if (!record) return;
  await restoreIdentityKeyringRecord(exportIdentityKeyringRecord(record));
  if (snapshot?.did === record.did) await saveDidLogSnapshot(snapshot);
  await Promise.all([
    ...oauth.filter(grant => grant.did === record.did).map(grant => saveWalletOAuthGrant(grant)),
    ...deviceBindings.filter(binding => binding.did === record.did).map(binding => saveWalletDeviceBinding(binding)),
  ]);
}

function armAutoLock() {
  if (autoLockTimer) clearTimeout(autoLockTimer);
  autoLockTimer = loaded ? setTimeout(() => logoutWallet("Private key material was cleared after 24 hours of inactivity.", false), AUTO_LOCK_MS) : null;
}

function updateNavVisibility() {
  const activeUsername = storedIdentityRecord?.username ?? loaded?.username;
  const signedIn = Boolean(activeUsername);
  query("#nav-logout").classList.toggle("hidden", !signedIn);
  // activeUsername is the internal storage key (a SHA-256 hash of the SCID),
  // not anything meant for display -- show the did.md handle it resolves to
  // instead, falling back to the raw DID when this identity isn't hosted here.
  const currentDid = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  const displayName = signedIn ? (didMdUsername(currentDid) ?? currentDid ?? activeUsername) : null;
  setSignedInStatus(displayName);
  updateLoadedIdentityVisibility();
  updateLockToggleVisibility();
}

function updateLockToggleVisibility() {
  const button = query("#lock-toggle");
  const hasIdentity = Boolean(loaded || storedIdentityRecord);
  button.classList.toggle("hidden", !hasIdentity);
  if (!hasIdentity) {
    closeLockUnlockForm();
    return;
  }
  const locked = !loaded;
  button.dataset.locked = String(locked);
  button.setAttribute("aria-label", locked ? "Locked. Click to unlock." : "Unlocked. Click to lock.");
  query("#lock-toggle-shackle").setAttribute("d", locked ? "M8 11V7a4 4 0 0 1 8 0v4" : "M8 11V7a4 4 0 0 1 7.5-1.5");
  if (!locked) closeLockUnlockForm();
}

async function activateLoadedIdentity() {
  discardPending();
  storedIdentityRecord = loaded.record ?? null;
  publicApplicationState = loaded.entries.at(-1)?.state ?? null;
  query("#key-editor").classList.remove("hidden");
  // Built from the entries already held in memory, not fetched -- this stays
  // correct even for a host that is currently disconnected (network 404).
  const didLogPath = containerPath(loaded.entries.at(-1).state.id, "did.jsonl");
  const keyringPath = containerPath(loaded.entries.at(-1).state.id, "keyring.json");
  const didJsonl = `${loaded.entries.map(entry => JSON.stringify(entry)).join("\n")}\n`;
  const metadataFiles = await metadataContainerFiles(loaded.entries.at(-1).state.id);
  renderIdentityFiles({
    manifest: { identities: [{ keyringPath }], contents: [didLogPath, keyringPath, ...Object.keys(metadataFiles)] },
    files: { [didLogPath]: didJsonl, [keyringPath]: null, ...metadataFiles },
  });
  renderSync();
  rememberPasskeyWalletSession();
  armAutoLock();
  void renderAsync();
  if (walletAuthorization) selectTab("home");
}

function isProvisionalDid(did) {
  return typeof did === "string" && did.endsWith(":ex.alias");
}

// Key rotation needs the Sign key decrypted in memory. Any identity that is
// loaded (has a local record, provisional or hosted) can be unlocked: the
// genesis/log data it needs already lives in this browser.
function updateKeysUnlockVisibility() {
  const canUnlock = !loaded && storedIdentityRecord;
  query("#keys-empty").classList.toggle("hidden", Boolean(loaded || canUnlock));
}

// "Connected" means this host currently serves the identity's did.jsonl.
// Disconnecting removes it from the host (the did:webvh spec treats this as
// a legitimate way to signal deactivation) without touching the local copy,
// so it can be reconnected -- to the same host -- later. Works from a
// `storedIdentityRecord` alone (no in-tab unlock needed) so it also shows up
// right after a cold reload.
// The single source of truth for "is this identity currently served by its
// host" -- set by updateConnectionStatus's own fetch, not re-derived from
// the DID itself: a non-provisional DID (one that already points at a real
// domain) can still be disconnected if that host no longer serves it.
function isHostedConnected() {
  return query("#connection-dot").dataset.state === "connected";
}

// Post-operation hint. GitHub Pages CDN can keep serving the previous
// did.jsonl (or a 404) for a minute after a commit; without this the
// status-dot lagged badly behind what the user just did (found live
// 2026-09-29). While the hint is fresh, prefer it over a stale fetch.
let connectionHint = null; // { live: boolean, until: number }
const CONNECTION_HINT_MS = 45_000;
const GITHUB_PAGES_LAG_NOTE = " It may take a few minutes for the change to be reflected.";
let connectionResyncTimer = null;

function hintConnection(live: boolean) {
  connectionHint = { live, until: Date.now() + CONNECTION_HINT_MS };
  applyConnectionState(live);
  scheduleConnectionResync();
}

/** Re-check a few times after publish/remove so the dot settles without a
 *  manual reload once the CDN catches up (or the hint expires). */
function scheduleConnectionResync() {
  if (connectionResyncTimer) clearTimeout(connectionResyncTimer);
  let attempts = 0;
  const tick = async () => {
    attempts += 1;
    await updateConnectionStatus();
    if (attempts < 6) connectionResyncTimer = setTimeout(tick, 4000);
    else connectionResyncTimer = null;
  };
  connectionResyncTimer = setTimeout(tick, 1500);
}

function applyConnectionState(connected) {
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  const connectionState = connected ? "connected" : "disconnected";
  // Update every live instance (queryAll -- query() would miss a second node
  // if a fragment copy ever coexists with the rendered one).
  const dots = queryAll("#connection-dot");
  if (!dots.length) return;
  for (const dot of dots) {
    dot.dataset.state = connectionState;
    if (did && isGitHubHostedDid(did)) {
      // GitHub remove = delete the DID files only (repository stays).
      dot.setAttribute("aria-label", connected ? "Remove from GitHub (keep the site)" : "Republish to GitHub");
      dot.dataset.toast = connected ? "remove DID files from github" : "republish to github";
    } else {
      dot.setAttribute("aria-label", connected ? "Remove from server" : "Publish to server");
      dot.dataset.toast = connected ? "remove from server" : "publish to server";
    }
  }
  const alias = query("#identity-did-alias");
  if (alias) alias.dataset.state = connectionState;
  // Keep Connect reachable. Only hide it when this identity is *connected to
  // a did.md server* -- GitHub-hosted "connected" only means the Pages log is
  // live, and the user still needs Edit alias / Connect to move hosts.
  const onDidMd = Boolean(did && didMdUsername(did));
  query("#context-connect-menu")?.classList.toggle("hidden", connected && onDidMd);
  applyContextViewVisibility();
  if (connected && onDidMd && !aliasEditActive) closeConnectForm();
  updateIdentityHostRow();
}

async function updateConnectionStatus() {
  const renderGeneration = ++connectionRenderGeneration;
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  query("#connection-empty").classList.toggle("hidden", Boolean(did));
  if (!did) return;
  // Paint the known-good post-op state immediately; fetch only reconciles
  // after it returns (and can lose to the hint below).
  if (connectionHint && Date.now() < connectionHint.until) {
    applyConnectionState(connectionHint.live);
  }
  const provisional = isProvisionalDid(did);
  let connected = false;
  if (!provisional) {
    // Host-agnostic: asks the adapter (did.md API or GitHub Pages) whether
    // the log is currently served. A GitHub-hosted identity must show as
    // connected when its Pages URL is live -- the old endpoint() call threw
    // for *.github.io and left the status-dot permanently gray.
    try { connected = await hostForDid(did).isLive(did); } catch { connected = false; }
  }
  // A fresh post-publish/remove hint wins over a stale CDN answer.
  if (connectionHint && Date.now() < connectionHint.until) {
    connected = connectionHint.live;
  } else {
    connectionHint = null;
  }
  if (renderGeneration !== connectionRenderGeneration) return;
  applyConnectionState(connected);
}

// ---- host on your github (PLAN-github-host) ------------------------------
// The 3rd identity row. GitHub-hosted state is derived from the DID itself
// (`<login>.github.io`) -- no extra stored field and no token anywhere.
// Host transport lives in host.ts / github-host.ts.

function isGitHubHostedDid(did) {
  return isGitHubHostedDidHost(did);
}

function updateIdentityHostRow() {
  // Icon-only control (right of Edit alias). data-state/toast/aria-label
  // carry the host/republish/remove affordance -- no 3rd row anymore.
  const button = query("#identity-host-github");
  if (!button) return;
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  const onGithub = Boolean(did && isGitHubHostedDid(did));
  // "hosted" must mean the files are actually being served -- not merely
  // that the DID string points at *.github.io. After Remove, the DID still
  // names that host but the log is gone (found live 2026-09-29).
  const live = onGithub && isHostedConnected();
  if (live) {
    button.dataset.state = "hosted";
    button.dataset.toast = "remove DID files from github";
    button.setAttribute("aria-label", "Remove DID from GitHub (keep the site)");
    return;
  }
  button.dataset.state = "unhosted";
  if (onGithub) {
    button.dataset.toast = "republish to github";
    button.setAttribute("aria-label", "Republish to GitHub");
    return;
  }
  button.dataset.toast = "host on your github";
  button.setAttribute("aria-label", "Host on your github");
}

// PAT lives in memory while the dialog is open / publishing. Optional
// persistence (checkbox "Remember this token") writes it to localStorage
// so republish/remove skip the prompt (asked 2026-09-29). Never sent to
// did.md. wipeGitHubPat() clears the in-memory copy only.
const GITHUB_PAT_STORAGE_KEY = "did-md-github-pat";
let githubPatInMemory = null;
// Set when Docs/Keys (or routing) needs a GitHub write and no PAT is in
// memory: the PAT dialog runs this instead of the initial host flow.
let pendingGitHubPublish = null;
// "host" = move/republish from the host icon; "update" = finish a Docs/Keys write.
let githubHostCardIntent = "host";

function loadStoredGitHubPat() {
  try {
    return localStorage.getItem(GITHUB_PAT_STORAGE_KEY);
  } catch {
    return null;
  }
}

function saveStoredGitHubPat(token) {
  try {
    localStorage.setItem(GITHUB_PAT_STORAGE_KEY, token);
  } catch { /* Private browsing -- stay session-only. */ }
}

function clearStoredGitHubPat() {
  try {
    localStorage.removeItem(GITHUB_PAT_STORAGE_KEY);
  } catch { /* ignore */ }
}

function currentGitHubPat() {
  return githubPatInMemory || loadStoredGitHubPat();
}

function setGitHubProgress(steps, activeIndex, errorIndex = -1) {
  const list = query("#github-host-progress");
  if (!list) return;
  list.replaceChildren(...steps.map((step, index) => {
    const item = document.createElement("li");
    item.textContent = step.label;
    item.dataset.state = index === errorIndex ? "error" : index < activeIndex ? "done" : index === activeIndex ? "active" : "pending";
    return item;
  }));
}

function wipeGitHubPat() {
  githubPatInMemory = null;
  const input = query("#github-pat-input");
  if (input) input.value = "";
}

function closeGitHubHostCard() {
  wipeGitHubPat();
  query("#github-host-result").textContent = "";
  query("#github-host-progress").replaceChildren();
  closeModalCard();
}

function openGitHubHostCard(options = {}) {
  // Intent is always explicit when it matters. `pendingGitHubPublish` alone
  // must NOT flip a "remove" dialog into a generic update -- found live
  // 2026-09-29: Remove fell through to publishIdentityToGitHub.
  let intent = "host";
  if (options.intent === "remove" || options.intent === "update" || options.intent === "host") {
    intent = options.intent;
  } else if (pendingGitHubPublish) {
    intent = "update";
  }
  githubHostCardIntent = intent;
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  if (!did) {
    showContextToast("Load an identity first.");
    return;
  }
  if (intent === "host") {
    const parameters = loaded?.parameters ?? (loaded?.entries ? currentParameters(loaded.entries) : null);
    // preparePortableImport requires portable:true and no active witnesses.
    if (parameters && parameters.portable === false) {
      showContextToast("This identity is not portable.");
      return;
    }
    if (parameters && parameters.witness && Object.keys(parameters.witness).length) {
      showContextToast("Identities with active witnesses cannot move yet.");
      return;
    }
  }
  const hosted = isGitHubHostedDid(did);
  if (intent === "update") {
    query("#github-host-title").textContent = "Publish update to GitHub";
    query("#github-host-publish").textContent = "Publish update";
    query("#github-host-result").textContent = "A classic PAT is required to commit this change to your GitHub repository. It is never stored.";
  } else if (intent === "remove") {
    query("#github-host-title").textContent = "Remove did:web from GitHub";
    query("#github-host-publish").textContent = "Remove";
  } else {
    query("#github-host-title").textContent = hosted ? "Republish to your GitHub" : "Host on your GitHub";
    query("#github-host-publish").textContent = hosted ? "Republish" : "Publish";
    query("#github-host-result").textContent = "";
  }
  query("#github-host-progress").replaceChildren();
  query("#github-host-recheck").classList.add("hidden");
  // Seed the PAT field from a remembered token and show Forget only when
  // one is stored.
  const storedPat = loadStoredGitHubPat();
  const remember = query("#github-pat-remember");
  if (remember) remember.checked = Boolean(storedPat);
  // Remove: "Remove token from browser" (unchecked = keep the saved token)
  // takes the place of the save option and the Forget link.
  const removing = intent === "remove";
  query("#github-pat-remember-row")?.classList.toggle("hidden", removing);
  query("#github-pat-remove-row")?.classList.toggle("hidden", !removing);
  query("#github-pat-remove-token").checked = false;
  if (storedPat && !query("#github-pat-input")?.value) {
    query("#github-pat-input").value = storedPat;
  }
  openModalCard("github-host-card");
  query("#github-pat-input")?.focus();
}

// Progress labels shown during Publish (plan §2.4).
const GITHUB_PUBLISH_STEPS = [
  { key: "verify-token", label: "Verify token" },
  { key: "validate", label: "Validate DID log locally" },
  { key: "ensure-repo", label: "Ensure repository" },
  { key: "commit", label: "Commit did.jsonl + did.json + .nojekyll" },
  { key: "enable-pages", label: "Enable GitHub Pages" },
  { key: "wait-build", label: "Wait for Pages build" },
  { key: "wait-publish", label: "Wait for public URL" },
  { key: "verify-published", label: "Verify published DID log" },
  { key: "verify-mirror", label: "Verify did.json mirror" },
  { key: "done", label: "Done" },
];

async function publishIdentityToGitHub(token) {
  const currentDid = loaded.entries.at(-1).state.id;
  const hostedHere = isGitHubHostedDid(currentDid);
  const previousDid = hostedHere ? null : currentDid;
  const previousSign = previousDid ? loaded.sign : null;

  let entries = loaded.entries;
  let move = null;
  if (!hostedHere) {
    // Portability move to <login>.github.io. login is taken from the PAT
    // (GET /user) before any write; publishToGitHub repeats the same check.
    const { login } = await verifyToken(token);
    move = await preparePortableImport({
      entries: loaded.entries,
      username: login,
      domain: "github.io",
      masterSeed: loaded.masterSeed,
    });
    entries = [...loaded.entries, move.entry];
    // Local gate first -- never hand a bad log to Octokit.
    await validateBeforePublish(entries, githubLogUrl(login));
  }

  const stepIndex = new Map(GITHUB_PUBLISH_STEPS.map((step, index) => [step.key, index]));
  const result = await publishToGitHub({
    token,
    entries,
    message: move
      ? `Publish did:webvh ${move.entry.versionId} (portability move)`
      : `Republish did:webvh ${entries.at(-1).versionId}`,
    onProgress: key => {
      const index = stepIndex.get(key);
      if (index !== undefined) setGitHubProgress(GITHUB_PUBLISH_STEPS, index);
    },
    // Pages build + public URL can take a couple of minutes.
    timeoutMs: 180_000,
    intervalMs: 4000,
  });

  // Local state only after GitHub accepted the full log (same rule as
  // connectHostedData): a failed publish must not leave `loaded` pointing
  // at an entry that was never published.
  if (move) {
    loaded.entries = entries;
    loaded.parameters = currentParameters(entries);
    loaded.sign = await spareFromMasterSeed(loaded.masterSeed, loaded.currentSpareIndex);
    loaded.currentSpareIndex = move.nextSpareIndex;
    await persistMasterMetadata();
    await saveDidLogSnapshot({
      username: loaded.username,
      did: loaded.entries.at(-1).state.id,
      generation: loaded.entries.at(-1).versionId,
      didJsonl: `${loaded.entries.map(entry => JSON.stringify(entry)).join("\n")}\n`,
      savedAt: new Date().toISOString(),
    });
    publicApplicationState = loaded.entries.at(-1).state;
    await refreshIdentityViews();
  }

  setGitHubProgress(GITHUB_PUBLISH_STEPS, GITHUB_PUBLISH_STEPS.length - 1);

  // Plan §7-1: after GitHub publish + resolution check, remove the old
  // *.did.md alias (best-effort). Failure keeps GitHub and reports it.
  let cleanupNote = "";
  if (previousDid && previousSign) {
    try {
      await disconnectHostedDataAt(previousDid, previousSign);
    } catch (error) {
      cleanupNote = ` Published on GitHub, but the previous alias could not be removed: ${errorMessage(error)}`;
    }
  }

  void renderLoadedIdentity();
  // Dot flips immediately; CDN may lag so the hint sticks for a while.
  hintConnection(true);
  await updateConnectionStatus();
  updateIdentityHostRow();

  const published = `Published as ${result.did} at ${result.publicUrl}.${cleanupNote}${GITHUB_PAGES_LAG_NOTE}`;
  query("#github-host-result").textContent = published;
  query("#github-host-result").classList.add("success");
  if (!result.verifiedLive) {
    output("#loaded-identity-message", `${published} Pages may still be building — reopen this card and press Recheck if the URL is not live yet.`);
    query("#github-host-recheck").classList.remove("hidden");
    query("#github-host-result").textContent = `${published} Pages is still building — press Recheck in a minute if the URL is not live yet.`;
  } else {
    output("#loaded-identity-message", published);
    query("#github-host-recheck").classList.add("hidden");
  }
  // Token is done -- drop it immediately, even if the dialog stays open.
  wipeGitHubPat();
  return result;
}

query("#identity-host-github").addEventListener("click", () => {
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  // Live on GitHub -> Remove dialog. Otherwise (never hosted, or files
  // gone) -> host/republish dialog.
  if (did && isGitHubHostedDid(did) && isHostedConnected()) {
    openGitHubHostCard({ intent: "remove" });
    return;
  }
  openGitHubHostCard();
});


// Recheck only re-reads the public URL -- no token, no writes. Shown when
// publish finished but Pages has not started serving the log yet.
query("#github-host-recheck").addEventListener("click", async () => {
  const button = query("#github-host-recheck");
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  const host = did && didHost(did);
  if (!host) {
    output("#github-host-result", "No published host to recheck.", true);
    return;
  }
  button.disabled = true;
  try {
    const publicUrl = `https://${host}/.well-known/did.jsonl`;
    const expectedVersionId = loaded?.entries?.at(-1)?.versionId ?? storedIdentityRecord?.generation;
    const response = await fetch(`${publicUrl}?_=${Date.now()}`, { cache: "no-store" });
    if (!response.ok) {
      hintConnection(false);
      output("#github-host-result", "Not live yet. GitHub Pages can take a few minutes — try Recheck again shortly.", true);
      return;
    }
    const body = await response.text();
    await verifyPublishedLog(body, publicUrl, expectedVersionId);
    hintConnection(true);
    query("#github-host-recheck").classList.add("hidden");
    const message = `Confirmed at ${publicUrl}.`;
    query("#github-host-result").textContent = message;
    query("#github-host-result").classList.add("success");
    output("#loaded-identity-message", message);
    updateIdentityHostRow();
  } catch (error) {
    output("#github-host-result", /version/i.test(errorMessage(error))
      ? "The URL is up but does not serve this identity's log yet. Recheck in a few minutes."
      : errorMessage(error), true);
  } finally {
    button.disabled = false;
  }
});

query("#github-host-publish").addEventListener("click", async () => {
  const button = query("#github-host-publish");
  const input = query("#github-pat-input");
  const token = (input?.value ?? "").trim() || currentGitHubPat();
  if (!token) {
    output("#github-host-result", "Paste a classic PAT with the repo scope first.", true);
    return;
  }
  githubPatInMemory = token;
  // Remember only when the user opted in (or already had a saved token and
  // left the box checked).
  const remember = query("#github-pat-remember");
  if (githubHostCardIntent !== "remove" && remember?.checked) saveStoredGitHubPat(token);
  button.disabled = true;
  try {
    await withUnlock(async () => {
      try {
        // Intent decides the action. NEVER fall through from remove/update
        // into publishIdentityToGitHub (found live 2026-09-29: Remove ran
        // the full publish pipeline and re-created the files it was meant
        // to delete).
        if (githubHostCardIntent === "remove") {
          const resume = pendingGitHubPublish ?? (() => disconnectHostedData());
          pendingGitHubPublish = null;
          query("#github-host-progress").replaceChildren();
          try {
            await resume();
            hintConnection(false);
            if (query("#github-pat-remove-token").checked) clearStoredGitHubPat();
            output("#loaded-identity-message", `DID files removed from GitHub.${GITHUB_PAGES_LAG_NOTE}`);
          } finally {
            // Always dismiss -- a stuck modal/scrim is what blocked Edit &
            // Connect after the first host (found live 2026-09-29).
            closeGitHubHostCard();
          }
        } else if (githubHostCardIntent === "update") {
          if (!pendingGitHubPublish) throw new Error("Nothing to publish. Try the action again.");
          const resume = pendingGitHubPublish;
          pendingGitHubPublish = null;
          query("#github-host-progress").replaceChildren();
          try {
            await resume();
            hintConnection(true);
            output("#loaded-identity-message", `Update published to GitHub.${GITHUB_PAGES_LAG_NOTE}`);
          } finally {
            closeGitHubHostCard();
          }
        } else {
          try {
            await publishIdentityToGitHub(githubPatInMemory);
          } finally {
            // Publish is done -- dismiss the dialog (asked for 2026-09-29).
            // Result/Recheck are in the toast; reopen via the host row.
            closeGitHubHostCard();
          }
        }
        void renderLoadedIdentity();
        await updateConnectionStatus();
      } catch (error) {
        const message = /Canceled/.test(errorMessage(error)) ? "Canceled." : githubErrorMessage(error);
        // Mark whichever step was active as the failure point (publish only).
        const list = query("#github-host-progress");
        const activeIndex = [...list.children].findIndex(child => child.dataset.state === "active");
        if (activeIndex >= 0) setGitHubProgress(GITHUB_PUBLISH_STEPS, activeIndex, activeIndex);
        output("#github-host-result", message, true);
        output("#loaded-identity-message", message, true);
      } finally {
        wipeGitHubPat();
      }
    });
  } finally {
    button.disabled = false;
  }
});

query("#github-pat-input")?.addEventListener("keydown", event => {
  if (event.key === "Enter") {
    event.preventDefault();
    query("#github-host-publish")?.click();
  }
});

// Whichever of the Context Window's six mutually-exclusive main-line views
// (its default action buttons, the menu, the command line, the Connect/edit
// form, the Unload confirmation) is current -- re-applied after
// updateConnectionStatus so a refresh while one is open doesn't silently
// switch it back to the default actions view. Activating any one of these
// resets the rest to false (see each setter below) -- there is no notion of
// a "parent" state to return to. Connect and Unload live in the menu view
// now (see #context-menu-view) -- Unload gets its own view here (sharing
// .context-icon on the left with the default actions row); Connect has no
// view of its own here, it opens #context-connect-form. Files/Export have
// moved out of the Context Window entirely, onto their own "Files"
// application tab (see #files-manager in dashboard.html) -- a persistent
// tab, not a transient view of this row, so it needs none of this.
let aliasEditActive = false;
let commandModeActive = false;
let unloadViewActive = false;
let exportViewActive = false;
let menuViewActive = false;

// The Context Window's one persistent left-side icon -- swaps with whatever
// context is current: "file" for the default actions/menu view/Unload,
// "unlock" while the command line is asking for the Passphrase, "profile"
// while editing/connecting the did:webvh alias, "search" once the command
// line itself is actually showing (typed input), entered either from the
// default view or the menu view.
function setContextIcon(context) {
  query("#context-icon-logo").classList.toggle("hidden", context !== "logo");
  query("#context-icon-file").classList.toggle("hidden", context !== "file");
  query("#context-icon-unlock").classList.toggle("hidden", context !== "unlock");
  query("#context-icon-profile").classList.toggle("hidden", context !== "profile");
  query("#context-server-toggle").classList.toggle("hidden", context !== "server");
  query("#context-icon-search").classList.toggle("hidden", context !== "search");
}

function applyContextViewVisibility() {
  // Unload no longer has a header-side view at all -- its confirmation
  // renders entirely in the Files tab's own card (#files-unload-body in
  // dashboard.html, toggled via updateFilesHeader() in setUnloadView()), so
  // unloadViewActive deliberately doesn't touch any of this function's
  // header state. The header looks and behaves exactly as it does in its
  // own default idle state the whole time Unload is open.
  const showConnectForm = aliasEditActive;
  const showCommand = !showConnectForm && commandModeActive;
  const showMenu = !showConnectForm && !showCommand && menuViewActive;
  const showActions = !showConnectForm && !showCommand && !showMenu;
  query("#context-actions-view").classList.toggle("hidden", !showActions);
  query("#context-menu-view").classList.toggle("hidden", !showMenu);
  query("#context-command-view").classList.toggle("hidden", !showCommand);
  query("#context-connect-form").classList.toggle("hidden", !showConnectForm);
  updateFilesActionsRow();
  query("#context-connect-toggle").classList.toggle("hidden", !showConnectForm);
  // The menu button belongs to the default actions view only -- hidden in
  // every other Context Window view (menu, command line, Connect form).
  query("#context-menu-button").classList.toggle("hidden", !showActions);

  // Contextual actions (right column) vs hamburger menu toggle
  const showContextActions = showCommand || showConnectForm || showMenu;
  query("#context-actions").classList.toggle("hidden", !showContextActions);
  // Header-wide state: "contextual" while the Context Window is in one of
  // its non-default views (menu, command line, Connect form) -- vs.
  // "non-contextual" (the default) the rest of the time. See .contextual in
  // styles.css for what currently keys off it (hiding the header's centered
  // brand, and pulling .panel up into the space it leaves behind).
  headerRoot.classList.toggle("contextual", !showActions);

  // Show specific contextual action buttons based on view
  query("#context-command-submit").classList.toggle("hidden", !showCommand);
  query("#context-connect-toggle").classList.toggle("hidden", !showConnectForm);
  query("#context-connect-status").classList.toggle("hidden", !showConnectForm);
  query("#context-menu-close").classList.toggle("hidden", !showMenu);
  const unlocking = showCommand && commandModeContext === "unlock";
  // The search icon belongs to the command line itself (typed input showing,
  // whether opened from the default view or the menu view) -- not to the
  // menu view's item list.
  const searching = showCommand && commandModeContext === "menu";
  // Context icon switching:
  // - "logo" (no context) → default, actions view
  // - "file" → menu view, command mode (non-unlock, non-menu)
  // - "unlock" → command mode asking for passphrase
  // - "profile" → connect/alias edit form
  // - "search" → command line showing, opened from the default or menu view
  let icon: "logo" | "file" | "unlock" | "profile" | "search" | "server" = "logo";
  if (showConnectForm) icon = "server";
  else if (unlocking) icon = "unlock";
  else if (searching) icon = "search";
  else if (showCommand || showMenu) icon = "file";
  setContextIcon(icon);
}

function setMenuView(active) {
  menuViewActive = active;
  if (active) { aliasEditActive = false; commandModeActive = false; unloadViewActive = false; }
  applyContextViewVisibility();
  query("#context-menu-button").setAttribute("aria-expanded", String(active));
}

function setUnloadView(active) {
  unloadViewActive = active;
  if (active) {
    aliasEditActive = false; commandModeActive = false; menuViewActive = false;
    exportViewActive = false;
    // The Files card can only show one detail view at a time (see
    // updateFilesHeader()) -- close an open file first rather than leaving
    // it selected-but-hidden underneath the confirmation.
    if (identityFilesView?.selected) identityFilesShow?.(identityFilesView.selected);
  }
  applyContextViewVisibility();
  query("#context-menu-button").setAttribute("aria-expanded", "false");
  updateFilesHeader();
  if (active) {
    // The confirmation itself renders in the Files tab's own card
    // (#files-unload-body), not the header -- switch there so it's actually
    // visible regardless of which tab, or which of the two entry points
    // (header menu vs. the Files tab's own Unload button), this was opened
    // from.
    selectApplicationTab("files");
    query("#unload-disconnect-host").checked = true;
    query("#unload-disconnect-host").closest("label").classList.toggle("hidden", !isHostedConnected());
  }
}

// Same drilldown pattern as setUnloadView, for Export -- see
// #wallet-backup-export's own click handler, which calls this once the
// download itself has actually happened (not before), so the two are always
// in sync: this view showing means the download already fired.
function setExportView(active) {
  exportViewActive = active;
  if (active) {
    aliasEditActive = false; commandModeActive = false; menuViewActive = false;
    unloadViewActive = false;
    if (identityFilesView?.selected) identityFilesShow?.(identityFilesView.selected);
  }
  applyContextViewVisibility();
  query("#context-menu-button").setAttribute("aria-expanded", "false");
  updateFilesHeader();
  if (active) selectApplicationTab("files");
}

// Typing a command in the Context Window's default-state empty space -- the
// same card the menu view's Connect/Unload buttons live in, just its
// blank-line mode instead of its button-row mode.
// Empty -> a quiet [esc] to back out; anything typed -> the same return icon
// used to confirm elsewhere, since there's now something to actually submit.
// Shared by every "input mode" field (the Context Window's command line, the
// header's unlock field, ...): a quiet esc icon while empty (click or Escape
// backs out), swapped for the normal return/confirm icon once something is
// typed (click or Enter submits it). Each caller still wires its own
// click/keydown/submit handling -- some are a real <form>, some aren't --
// this only keeps the two icons and the button's label in sync with content.
function syncInputModeIcons(field, escIcon, enterIcon, button, labels) {
  const empty = !field.value.trim();
  escIcon.classList.toggle("hidden", !empty);
  enterIcon.classList.toggle("hidden", empty);
  if (button && labels) button.setAttribute("aria-label", empty ? labels.esc : labels.enter);
}

// Shared by every debounced-availability-check field (the creation page's
// Alias field, the dashboard's Alias/Connect field): a quiet spinner while
// the check is in flight, a green check once it succeeds, a muted x once it
// fails, hidden while there's nothing to check. state is one of "idle",
// "checking", "available", "unavailable".
function setAliasStatusIcon(icon, state, label) {
  if (!state || state === "idle") {
    icon.classList.add("hidden");
    delete icon.dataset.state;
    icon.setAttribute("aria-label", label ?? "Availability unknown");
    return;
  }
  icon.classList.remove("hidden");
  icon.dataset.state = state;
  icon.setAttribute("aria-label", label ?? state);
}

function updateContextCommandButton() {
  const unlocking = commandModeContext === "unlock";
  syncInputModeIcons(
    query("#context-command-input"),
    query("#context-command-icon-esc"),
    query("#context-command-icon-return"),
    query("#context-command-submit"),
    unlocking ? { esc: "Cancel", enter: "Unlock" } : { esc: "Back", enter: "Run command" },
  );
}

// "menu" is the mini CLI (files/export/unload/connect/disconnect), entered
// either from the default idle view or the hamburger's menu view -- both
// carry the search icon (see the `searching` check in
// applyContextViewVisibility); "unlock" repurposes the exact same
// field+button for the Recovery phrase prompt -- requiring unlock just
// means entering input mode with an "unlock" context instead of typing a
// command. See withUnlock/openLockUnlockForm. "commands" is only the
// pre-reset/idle value of this variable, never itself passed to
// setCommandMode.
let commandModeContext = "commands";

function setCommandMode(active, context = "commands") {
  commandModeActive = active;
  commandModeContext = active ? context : "commands";
  if (active) { aliasEditActive = false; menuViewActive = false; }
  applyContextViewVisibility();
  const field = query("#context-command-input");
  field.value = "";
  const unlocking = context === "unlock";
  field.type = unlocking ? "password" : "text";
  field.placeholder = unlocking
    ? "Passphrase"
    : "files · export · unload · connect <host> · disconnect";
  field.autocomplete = unlocking ? "current-password" : "off";
  updateContextCommandButton();
  if (!active) return;
  field.focus();
  // Restart the shake animation even if it's already mid-run (e.g. a locked
  // action is attempted again while the field is already open).
  if (unlocking) {
    const submit = query("#context-command-submit");
    submit.classList.remove("shake");
    void submit.offsetWidth;
    submit.classList.add("shake");
  }
}

function cancelCommandMode() {
  if (commandModeContext === "unlock") applicationActionAfterUnlock = null;
  setCommandMode(false);
}

async function submitCommandModeInput(raw) {
  if (commandModeContext === "unlock") { await submitUnlockMnemonic(raw); return; }
  await runContextCommand(raw);
}

async function runContextCommand(raw) {
  const trimmed = typeof raw === "string" ? raw.trim() : "";
  if (!trimmed) { setCommandMode(false); return; }
  const [name, ...rest] = trimmed.toLowerCase().split(/\s+/);
  const arg = rest.join(" ");
  switch (name) {
    case "files":
      setCommandMode(false);
      selectApplicationTab("files");
      return;
    case "export":
      setCommandMode(false);
      query("#wallet-backup-export").click();
      return;
    case "unload":
      setCommandMode(false);
      setUnloadView(true);
      return;
    case "disconnect":
      setCommandMode(false);
      query("#connection-dot").click();
      return;
    case "connect": {
      if (!arg) { output("#loaded-identity-message", "Usage: connect <host>", true); return; }
      const host = await checkConnectTarget(arg);
      if (!host) { output("#loaded-identity-message", "That location is taken or the server did not respond (it must host did:webvh logs).", true); return; }
      setCommandMode(false);
      void withUnlock(async () => {
        try { await connectHostedData(host); }
        catch (error) { output("#loaded-identity-message", errorMessage(error), true); }
      });
      return;
    }
    default:
      output("#loaded-identity-message", `Unknown command: ${name}`, true);
  }
}

// The default (idle) view is empty -- see dashboard-header.html -- so a
// click anywhere in it goes straight to the search field, same "menu"
// context (and search icon) as opening it via the hamburger's menu view
// and then clicking its own empty space. There is no bare "type a command"
// entry point anymore; every path into the command line now carries the
// search icon.
query("#context-actions-view").addEventListener("click", () => {
  setCommandMode(true, "menu");
});
query("#context-command-submit").addEventListener("click", () => {
  const value = query("#context-command-input").value;
  if (!value.trim()) { cancelCommandMode(); return; }
  void submitCommandModeInput(value);
});
// A password manager's autofill can't dispatch a real Enter keydown, so
// waiting on that leaves the field filled but not submitted until the user
// separately clicks Unlock -- submit the instant a complete 24-word
// Passphrase is present instead, the same trigger whether it was typed or
// autofilled.
function looksLikeCompleteMnemonic(value) {
  return /^(?:\S+\s+){23}\S+$/.test(value.trim());
}
query("#context-command-input").addEventListener("input", () => {
  updateContextCommandButton();
  const field = query("#context-command-input");
  if (commandModeContext === "unlock" && looksLikeCompleteMnemonic(field.value)) void submitCommandModeInput(field.value);
});
query("#context-command-input").addEventListener("keydown", event => {
  if (event.key === "Enter") {
    const value = event.target.value;
    if (!value.trim()) { cancelCommandMode(); return; }
    void submitCommandModeInput(value);
    return;
  }
  if (event.key === "Escape") cancelCommandMode();
});

// Opens the Connect form -- always blank, even to rename an already-hosted
// alias, so the same Connect flow doubles as "set a new alias" either way.
function setAliasEditMode(active) {
  aliasEditActive = active;
  if (active) { commandModeActive = false; menuViewActive = false; }
  applyContextViewVisibility();
  if (!active) { closeConnectForm(); return; }
  const field = query("#context-connect-url");
  field.value = "";
  setConnectServerMode(true);
  setConnectCheckState("idle");
  syncConnectIcons();
  field.focus();
}

query("#identity-alias-edit").addEventListener("click", () => {
  setAliasEditMode(!aliasEditActive);
});

function openHostedDidLog() {
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  if (!did || isProvisionalDid(did)) return;
  // Cache-bust: GitHub Pages edge keeps serving a deleted did.jsonl for a
  // while. The plain URL lies after Remove (found live 2026-09-29); a
  // unique query forces the real origin answer (usually 404).
  const url = hostLogUrl(did);
  window.open(`${url}?_=${Date.now()}`, "_blank", "noopener");
}

// Doubles as the remove/republish control -- see updateConnectionStatus for
// how its aria-label/data-toast/data-state track which action this is.
query("#connection-dot").addEventListener("click", () => {
  // Never published: there is no host yet, so the alias has to be chosen
  // first -- same as pressing Edit alias.
  const did = loaded?.entries?.at(-1)?.state?.id ?? storedIdentityRecord?.did;
  if (did && isProvisionalDid(did) && !isHostedConnected()) {
    setAliasEditMode(true);
    return;
  }
  void withUnlock(async () => {
    try {
      // Same remove / republish toggle for every host. GitHub's remove
      // deletes only the DID files (repo stays) and may prompt for a PAT.
      if (isHostedConnected()) await disconnectHostedData();
      else await republishHostedData();
    }
    catch (error) { output("#loaded-identity-message", error instanceof Error ? error.message : String(error)); }
  });
});
query("#identity-alias-link").addEventListener("click", openHostedDidLog);

// The host segment of a did:webvh identifier -- did:webvh:<scid>:<host>.
// Unlike didMdUsername() this makes no assumption about DOMAIN, since it is
// also used to compare against an arbitrary Server URL the user typed in.
function didHost(did) {
  const match = typeof did === "string" ? /^did:webvh:[^:]+:(.+)$/.exec(did) : null;
  return match ? match[1] : null;
}

function normalizeServerUrl(raw) {
  const trimmed = typeof raw === "string" ? raw.trim() : "";
  if (!trimmed) return null;
  try { return new URL(/^https?:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`); }
  catch { return null; }
}

// The Server URL field takes the full publication host (<username>.<domain>,
// e.g. "myname.did.md") -- loaded.username/storedIdentityRecord.username is
// NOT that: for a provisional (never-connected) identity it's an internal
// IndexedDB storage key (a hash of the DID), not a real did.md subdomain, so
// it must never be used to build a hostname.
// Rejects anything that isn't plausibly a real hostname (letters/digits/
// hyphens between dots) before a caller ever fetches it -- e.g. a stray
// space mid-edit (browsers percent-encode it rather than rejecting the
// URL outright, so it would otherwise reach the network as a real,
// doomed-to-fail request: found live, see #context-connect-toggle's own
// comment on the race that caused).
function splitHostedTarget(host) {
  if (typeof host !== "string" || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(host)) return null;
  const dot = host.indexOf(".");
  if (dot <= 0 || dot === host.length - 1) return null;
  return { username: host.slice(0, dot), domain: host.slice(dot + 1) };
}

// Confirms the typed Server URL is reachable and speaks the did.md API
// before Connect is allowed to run. api.did.md only answers cross-origin
// fetches from app.did.md/client.did.md (see server/server.ts's cors()), so an
// arbitrary third-party host will usually fail here with a CORS error.
// idle/checking/ok/error drives both the Connect button's own dim-until-
// valid enter icon (see #context-connect-toggle[data-state="ok"] in the
// CSS) and the status icon to its left -- the same spinner/check/x used by
// the creation page's own Alias availability check (see setAliasStatusIcon).
const connectCheckIconState = { idle: "idle", checking: "checking", ok: "available", error: "unavailable" };
function setConnectCheckState(state) {
  query("#context-connect-toggle").dataset.state = state;
  setAliasStatusIcon(query("#context-connect-status"), connectCheckIconState[state]);
}

let connectCheckToken = 0;
async function checkConnectTarget(rawUrl) {
  const token = ++connectCheckToken;
  const url = normalizeServerUrl(rawUrl);
  if (!url || !splitHostedTarget(url.host)) { setConnectCheckState("idle"); return null; }
  setConnectCheckState("checking");
  try {
    // Any host that speaks the did:webvh Hosting Protocol (SPEC-webvh-hosting.md)
    // will do -- did.md or a third party. "Ready" = the location is reachable
    // and free (its did.jsonl is a 404); a taken or unreachable one is not.
    const probe = await new WebvhHostingClient().probe(url.host);
    if (token !== connectCheckToken) return null;
    if (probe.available !== true) { setConnectCheckState("error"); return null; }
    setConnectCheckState("ok");
    return url.host;
  } catch {
    if (token === connectCheckToken) setConnectCheckState("error");
    return null;
  }
}

// Edit-alias field. Server mode (default): the field holds just a did.md
// username and ".did.md" trails it (drawn by #connect-suffix, not part of the
// value). Custom mode: the field holds a full host; a faint ".domain.com"
// hint trails it until the first "." is typed.
let connectServerMode = true;

function connectTargetRaw() {
  const typed = query("#context-connect-url").value.trim();
  if (!typed) return "";
  return connectServerMode ? `${typed}.${DOMAIN}` : typed;
}

function renderConnectSuffix() {
  const field = query("#context-connect-url");
  const typed = field.value;
  query("#connect-suffix-mirror").textContent = typed || field.placeholder;
  query(".connect-prefix").classList.toggle("collapsed", !connectServerMode);
  query("#connect-prefix-text").classList.toggle("invisible", !connectServerMode || Boolean(typed));
  const ghost = query("#connect-suffix-ghost");
  if (connectServerMode) {
    ghost.textContent = `.${DOMAIN}`;
    ghost.classList.toggle("faint", !typed);
  } else {
    ghost.textContent = typed.includes(".") ? "" : ".domain.com";
    ghost.classList.add("faint");
  }
}

function setConnectServerMode(on) {
  connectServerMode = on;
  const toggle = query("#context-server-toggle");
  toggle.setAttribute("aria-pressed", String(on));
  const field = query("#context-connect-url");
  field.placeholder = "example";
  if (on) sanitizeConnectServerInput();
  renderConnectSuffix();
}

// Server mode only: a username, nothing else (a pasted/typed full
// "name.did.md" is reduced to "name").
function sanitizeConnectServerInput() {
  const field = query("#context-connect-url");
  if (!connectServerMode) return;
  const clean = field.value.toLowerCase().split(".")[0].replace(/[^a-z0-9-]/g, "");
  if (clean !== field.value) field.value = clean;
}

query("#context-server-toggle").addEventListener("click", () => {
  setConnectServerMode(!connectServerMode);
  syncConnectIcons();
  if (connectCheckTimer) clearTimeout(connectCheckTimer);
  connectCheckTimer = setTimeout(() => { void checkConnectTarget(connectTargetRaw()); }, 400);
  query("#context-connect-url").focus();
});

function closeConnectForm() {
  query("#context-connect-url").value = "";
  renderConnectSuffix();
  setConnectCheckState("idle");
}

// Publishes the currently loaded identity at `targetHost` (a full
// <username>.<domain> host, e.g. "myname.did.md"). If it is not already
// hosted there, this first signs the one additional did:webvh portability
// entry that moves it (see preparePortableImport) -- the existing entries
// are otherwise sent untouched, since PUT requires the prior log as a
// byte-for-byte prefix.
async function connectHostedData(targetHost) {
  const parsed = splitHostedTarget(targetHost);
  if (!parsed) throw new Error("Enter a full host, e.g. myname.did.md.");
  const currentDid = loaded.entries.at(-1).state.id;
  const isMove = isProvisionalDid(currentDid) || didHost(currentDid) !== targetHost;
  // Moving off an already-hosted alias (not just claiming one for the first
  // time) leaves a stale copy on the old host once this succeeds -- capture
  // its DID and the Sign key that's currently authorized *there* now, before
  // the move below rotates `loaded.sign` to the new generation.
  const previousDid = isMove && !isProvisionalDid(currentDid) ? currentDid : null;
  const previousSign = previousDid ? loaded.sign : null;
  let entries = loaded.entries;
  let move = null;
  if (isMove) {
    move = await preparePortableImport({
      entries: loaded.entries, username: parsed.username, domain: parsed.domain, masterSeed: loaded.masterSeed,
    });
    entries = [...loaded.entries, move.entry];
  }
  const body = `${entries.map(entry => JSON.stringify(entry)).join("\n")}\n`;
  // Only touch in-memory state once the host has actually accepted the full
  // log -- otherwise a failed PUT (e.g. a CORS error from a third-party
  // server) would leave `loaded` referring to an entry that was never
  // published, and every later network check against the real DID would
  // fail (see restoreStoredIdentityRecord's fallback for what that breaks).
  await publish(`https://${targetHost}/.well-known/did.jsonl`, "PUT", body);
  if (move) {
    loaded.entries = entries;
    loaded.parameters = currentParameters(entries);
    loaded.sign = await spareFromMasterSeed(loaded.masterSeed, loaded.currentSpareIndex);
    loaded.currentSpareIndex = move.nextSpareIndex;
  }
  await persistMasterMetadata();
  // Keeps unlocking possible from this browser even while the host is later
  // disconnected (fetchIdentityLog falls back to this snapshot when the live
  // fetch 404s) -- a disconnected host is an expected, supported state, not
  // the identity being gone.
  await saveDidLogSnapshot({
    username: loaded.username, did: loaded.entries.at(-1).state.id,
    generation: loaded.entries.at(-1).versionId,
    didJsonl: `${loaded.entries.map(entry => JSON.stringify(entry)).join("\n")}\n`,
    savedAt: new Date().toISOString(),
  });
  publicApplicationState = loaded.entries.at(-1).state;
  await refreshIdentityViews();
  void renderLoadedIdentity();
  await updateConnectionStatus();
  // The new host is now the source of truth for this identity, so the old
  // one is cleaned up last, on a best-effort basis -- there is no real
  // cross-server transaction to make this and the PUT above atomic, but
  // ordering it this way means a failure here never leaves the identity
  // unhosted, only an old, still-verifiable copy sitting on the previous
  // host until this is retried (via Disconnect) or it's cleaned up by hand.
  if (previousDid && previousSign) {
    try { await disconnectHostedDataAt(previousDid, previousSign); }
    catch (error) {
      output("#loaded-identity-message", `Connected as ${targetHost}, but the previous alias could not be removed: ${errorMessage(error)}`, true);
      return;
    }
  }
  output("#loaded-identity-message", `Connected as ${targetHost}.`);
  hintConnection(true);
}

function syncConnectIcons() {
  syncInputModeIcons(
    query("#context-connect-url"),
    query("#context-connect-icon-esc"),
    query("#context-connect-icon-enter"),
    query("#context-connect-toggle"),
    { esc: "Cancel", enter: "Save alias" },
  );
}

query("#context-connect-toggle").addEventListener("click", () => {
  // Cancel any pending debounced check (see the input listener below) --
  // otherwise it can still fire after this click's own checkConnectTarget()
  // already resolved, overwriting a fresh "ok" with a stale result checked
  // against whatever the field held a moment ago (found live: a
  // still-pending check against a mid-edit value with an extra space
  // clobbered the icon back to unavailable after the corrected host had
  // already come back ok).
  if (connectCheckTimer) { clearTimeout(connectCheckTimer); connectCheckTimer = null; }
  const raw = connectTargetRaw();
  // Empty field: same esc/enter convention as everywhere else -- this is
  // the Cancel action, not an attempt to connect to nothing.
  if (!raw.trim()) { setAliasEditMode(false); return; }
  const url = normalizeServerUrl(raw);
  if (!url) { output("#wallet-result", "Enter a server URL to connect to.", true); return; }
  void withUnlock(async () => {
    const host = await checkConnectTarget(raw);
    if (!host) {
      output("#loaded-identity-message", "That location is taken or the server did not respond (it must host did:webvh logs).", true);
      return;
    }
    try {
      await connectHostedData(host);
      setAliasEditMode(false);
    }
    catch (error) { output("#loaded-identity-message", errorMessage(error), true); }
  });
});

let connectCheckTimer = null;
query("#context-connect-url").addEventListener("input", event => {
  sanitizeConnectServerInput();
  renderConnectSuffix();
  syncConnectIcons();
  if (connectCheckTimer) clearTimeout(connectCheckTimer);
  const value = connectTargetRaw();
  // Emptied: clear the icon right away (and void any in-flight check) so it
  // never lingers over the re-shown "hosts" label.
  if (!value) { connectCheckToken++; setConnectCheckState("idle"); return; }
  connectCheckTimer = setTimeout(() => { void checkConnectTarget(value); }, 400);
});

// Not a <form> field (see .context-connect-form), so Enter/Escape do
// nothing on their own -- wire them to the same button the icon shows:
// Enter (or a click) always reaches the button's own click handler above,
// which itself branches on empty -> Cancel vs content -> attempt Connect;
// Escape always cancels outright, regardless of what's typed.
query("#context-connect-url").addEventListener("keydown", event => {
  if (event.key === "Enter") { query("#context-connect-toggle").click(); return; }
  if (event.key === "Escape") setAliasEditMode(false);
});

// Clicking outside the header's context window while one of its input modes
// (command line, alias/Connect field) is open acts like Escape.
document.addEventListener("pointerdown", event => {
  if (event.target.closest("#context-window")) return;
  if (commandModeActive) cancelCommandMode();
  else if (aliasEditActive) setAliasEditMode(false);
});

// Every place that changes `loaded`, `storedIdentityRecord`, or
// `walletAuthorization` must repaint the same set of panels, or a stale one
// silently lingers (this bit did.md more than once). Rather than each call
// site remembering which of the ~7 update/render functions apply to it,
// they all call this pair; every function here is idempotent, so calling
// one that doesn't need to change anything right now is harmless.
function renderSync() {
  updateOverviewState();
  updateIdentityOptionsVisibility();
  renderServicesList();
  renderApplicationKeysList();
  updateKeysUnlockVisibility();
  updateNavVisibility();
  renderWalletAuthorization();
  if (loaded) updateKeyStatus();
  renderRoute();
}

async function renderAsync() {
  await Promise.all([refreshIdentityViews(), renderLoadedIdentity(), updateConnectionStatus()]);
}

function closeMenu() {
  query("#nav-menu").classList.add("hidden");
  query("#menu-scrim").classList.add("hidden");
  query("#menu-toggle")?.setAttribute("aria-expanded", "false");
}

function toggleMenu() {
  const open = query("#nav-menu").classList.toggle("hidden") === false;
  query("#menu-scrim").classList.toggle("hidden", !open);
  query("#menu-toggle")?.setAttribute("aria-expanded", String(open));
}

function selectTab(tab) {
  if (!["home"].includes(tab)) tab = "home";
  currentTab = tab;
  queryAll("#nav-menu button[data-tab]").forEach(button => button.classList.toggle("active", button.dataset.tab === tab));
  queryAll("[data-panel]").forEach(panel => panel.classList.toggle("hidden", panel.dataset.panel !== tab));
  updateLoadedIdentityVisibility();
  closeMenu();
  maybeBeginCreateDraft();
}

// "docs" merges what used to be two separate tabs (Services, Passes/
// application keys) -- both are DID Document records, just different
// sections of it, so they now show stacked under one tab instead of
// splitting attention across two nearly-empty ones.
function selectApplicationTab(tab) {
  const panes = {
    apps: ["#application-devices-manager"],
    docs: ["#services-manager", "#application-keys-manager"],
    credentials: ["#credentials-manager"],
    files: ["#files-manager"],
  };
  if (!Object.hasOwn(panes, tab)) tab = "apps";
  currentApplicationTab = tab;
  queryAll("[data-application-tab]").forEach(button => {
    const selected = button.dataset.applicationTab === tab;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", String(selected));
  });
  for (const [name, selectors] of Object.entries(panes)) {
    for (const selector of selectors) query(selector)?.classList.toggle("hidden", name !== tab);
  }
}

// Land directly on the Create tab's result the first time this browser has
// nothing loaded yet, instead of showing an empty tab. Callable repeatedly
// (from selectTab and once restoreStoredIdentityRecord's async check
// resolves) since it is a no-op once a draft or a stored identity exists.
function maybeBeginCreateDraft() {
  if (currentTab === "home" && !loaded && !storedIdentityRecord && !draft) void beginCreateDraft();
}

async function migratePortableApplicationMetadata() {
  if (!loaded?.record) return;
  if (loaded.record.applicationMetadata) {
    portableApplications = await readPortableApplications(loaded.record, loaded.masterSeed);
    if (portableApplications.some(application => !application.services)) {
      const stateServices = Array.isArray(loaded.entries.at(-1).state.service) ? loaded.entries.at(-1).state.service : [];
      portableApplications = portableApplications.map(application => application.services ? application : ({
        ...application,
        services: application.serviceIds.map(id => {
          const service = stateServices.find(candidate => candidate.id === id);
          const bindsKnownDidCommKey = application.clientName.toLowerCase() === "biset" && service?.type === "DIDCommMessaging";
          return { id, keyIds: bindsKnownDidCommKey ? [...application.keyIds] : [] };
        }),
      }));
      loaded.record = await savePortableApplications(loaded.record, loaded.masterSeed, portableApplications);
    }
    return;
  }
  const [bindings, grants] = await Promise.all([listWalletDeviceBindings(), listWalletOAuthGrants()]);
  const ownBindings = bindings.filter(binding => binding.did === loaded.entries.at(-1).state.id);
  if (!ownBindings.length) return;
  const state = loaded.entries.at(-1).state;
  const services = Array.isArray(state.service) ? state.service : [];
  const applications = ownBindings.map(binding => {
    const grant = grants.find(item => item.did === binding.did && item.deviceJkt === binding.deviceJkt);
    const isBiset = (binding.clientName ?? grant?.clientName)?.toLowerCase() === "biset";
    return {
      v: 1,
      id: grant?.id ?? binding.id,
      clientId: grant?.clientId ?? "",
      clientName: binding.clientName ?? grant?.clientName ?? "Unknown application",
      deviceJkt: binding.deviceJkt,
      // Older records did not retain exact service associations. Biset's two
      // named service types are unambiguous; anything else stays unassigned.
      serviceIds: isBiset ? services.filter(service => service.type === "DIDCommMessaging" || service.type === "BisetMimiVaultRoom").map(service => service.id) : [],
      keyIds: binding.didCommKeyId ? [binding.didCommKeyId] : [],
      services: isBiset ? services.filter(service => service.type === "DIDCommMessaging" || service.type === "BisetMimiVaultRoom").map(service => ({
        id: service.id,
        keyIds: service.type === "DIDCommMessaging" && binding.didCommKeyId ? [binding.didCommKeyId] : [],
      })) : [],
      createdAt: binding.createdAt,
    };
  });
  loaded.record = await savePortableApplications(loaded.record, loaded.masterSeed, applications);
  portableApplications = applications;
}

async function unlockIdentity(username, enteredMaster, password = "") {
  if (loaded) {
    discardPending();
    discardLoadedIdentity();
  }
  const record = await readStoredIdentity(username);
  if (enteredMaster) {
    await loadMasterIdentity(username, record?.did, record?.v === 4 || record?.v === 5 ? record : undefined, seedFromMnemonic(enteredMaster, "Passphrase"));
    if (password) {
      // The public log and supplied Master have now been verified. Clearing
      // here (rather than before verification) prevents a failed attempt
      // from displacing the identity already stored in this browser.
      const existing = await listStoredIdentities();
      if (existing.some(item => item.username !== username)) await clearBrowserIdentityState();
      loaded.record = await savePasswordStoredIdentity({
        username, did: loaded.entries.at(-1).state.id, rootKey: loaded.root.multikey,
        generation: loaded.entries.at(-1).versionId, masterSeed: loaded.masterSeed, password,
        applicationMetadata: record?.applicationMetadata,
      });
    }
  } else if (record?.v === 5) {
    await loadMasterIdentity(username, record.did, record, await unlockPasswordStoredIdentity(record, password));
  } else if (record?.v === 4) {
    const unlocked = await unlockMasterStoredIdentity(record);
    await loadMasterIdentity(username, record.did, record, unlocked.masterSeed);
    loaded.passkeyProtector = unlocked.protector;
  } else {
    throw new Error("Enter the 24-word Passphrase. A password or passkey can be used only after it has been enabled for this browser.");
  }
  if (loaded.record && loaded.record.rootKey !== loaded.root.multikey) {
    // Do not preserve a stale envelope merely because it has the same local
    // username; a verified Master is the source of truth.
    loaded.record = undefined;
  }
  await migratePortableApplicationMetadata();
  // This also cleans up databases made by earlier versions which allowed
  // several identities to accumulate. It keeps the verified record only.
  await keepOnlyLoadedIdentityRecord();
  void activateLoadedIdentity();
  return loaded;
}

async function loadIdentity(username, enteredMaster, password = "") {
  try {
    await unlockIdentity(username, enteredMaster, password);
    output("#loaded-identity-message", `Loaded ${loaded.entries.at(-1).state.id} in this tab. It will auto-lock after 24 hours of inactivity.`);
  } catch (error) {
    output("#wallet-result", errorMessage(error), true);
  }
}

// The application's name as the person will see it: what it calls itself (via the RP's signed
// request), else its host, else its identifier. Editable; the edit is the device label saved with
// the grant.
function authorizeDefaultName() {
  const request = walletAuthorization;
  return request.clientDisplayName ?? request.clientDisplayHost ?? didHost(request.clientName) ?? request.clientName;
}

function showAuthorizeName() {
  const label = query("#wallet-authorize-device-label").value.trim() || authorizeDefaultName();
  query("#wallet-authorize-name").textContent = label;
  query("#wallet-authorize-title").textContent = label;
}

function setAuthorizeNameEditing(editing) {
  const input = query("#wallet-authorize-device-label");
  if (!editing && !input.value.trim() && walletAuthorization) input.value = authorizeDefaultName();
  query("#wallet-authorize-name").classList.toggle("hidden", editing);
  input.classList.toggle("hidden", !editing);
  if (editing) { input.focus(); input.select(); }
  else if (walletAuthorization) showAuthorizeName();
}

function renderWalletAuthorization() {
  const panel = query("#wallet-authorize-panel");
  if (!panel) return;
  const wasOpen = !panel.classList.contains("hidden");
  panel.classList.toggle("hidden", !walletAuthorization);
  if (wasOpen !== Boolean(walletAuthorization)) {
    // One bottom sheet at a time: opening moves a live message into the card,
    // closing drops the in-card line.
    if (walletAuthorization) {
      if (shownToast) paintContextToast(shownToast.message, shownToast.error);
      else setAuthorizeMessage("", false);
    } else {
      setAuthorizeMessage("", false);
      shownToast = null;
    }
  }
  if (!walletAuthorization) return;
  // clientName is a did:webvh identifier for a SIOPv2 relying party (its own
  // client_name never having been registered anywhere) -- show just its
  // host segment (e.g. "oidc-bridge.did.md") instead of the full DID, same
  // as elsewhere in this app. Non-DID client names (an OAuth client_name
  // string) pass through unchanged, since didHost returns null for those.

  query("#wallet-authorize-app").textContent = walletAuthorization.clientDisplayHost ?? "";
  const scopes = query("#wallet-authorize-scope");
  scopes.replaceChildren(...walletAuthorization.scope.map(scope => {
    const code = document.createElement("code"); code.textContent = scope; return code;
  }));
  const didCommLabel = query("#wallet-authorize-didcomm-label");
  const didComm = query("#wallet-authorize-didcomm");
  const edit = didDocumentEditDetail(walletAuthorization.authorizationDetails, walletAuthorization.did ?? loaded?.entries.at(-1).state.id ?? "");
  const changes = edit ? [
    ...edit.services.map(service => `Add or replace service: ${service.type} (${service.id}) → ${typeof service.serviceEndpoint === "string" ? service.serviceEndpoint : JSON.stringify(service.serviceEndpoint)}`),
    ...edit.verificationMethods.map(method => `Add or replace verification method: ${method.type} (${method.id})`),
    ...edit.remove.map(id => `Remove: ${id}`),
  ] : [];
  didCommLabel.textContent = "DID document changes";
  didCommLabel.classList.toggle("hidden", !changes.length);
  didComm.classList.toggle("hidden", !changes.length);
  if (changes.length) { const list = document.createElement("ul"); list.replaceChildren(...changes.map(change => { const item = document.createElement("li"); item.textContent = change; return item; })); didComm.replaceChildren(list); }
  const derivedLabel = query("#wallet-authorize-derived-label");
  const derived = query("#wallet-authorize-derived");
  const derivedRequests = derivedSecretDetails(walletAuthorization.authorizationDetails);
  derivedLabel.classList.toggle("hidden", !derivedRequests.length);
  derived.classList.toggle("hidden", !derivedRequests.length);
  if (derivedRequests.length) { const list = document.createElement("ul"); list.replaceChildren(...derivedRequests.map(request => { const item = document.createElement("li"); item.textContent = `Derive a private value from your Root key: ${request.purpose}`; return item; })); derived.replaceChildren(list); }
  // The device key if the application supplied one, otherwise the requesting application
  // itself (its full DID for a did:webvh client).
  query("#wallet-authorize-device").textContent = walletAuthorization.deviceJkt ?? walletAuthorization.clientName;
  const deviceLabel = query("#wallet-authorize-device-label");
  const requestKey = walletAuthorization.state ?? walletAuthorization.requestId ?? "";
  if (deviceLabel.dataset.requestKey !== requestKey) {
    deviceLabel.value = authorizeDefaultName();
    deviceLabel.dataset.requestKey = requestKey;
  }
  showAuthorizeName();
  // renderWalletAuthorization re-runs on every unrelated renderSync (tab
  // switches, unlock, etc.), not just when a genuinely new request arrives
  // -- reset the card to its collapsed/not-editing default only the first
  // time this particular request is rendered, the same guard deviceLabel's
  // own value reset above already uses.
  if (panel.dataset.requestKey !== requestKey) {
    setAuthorizeNameEditing(false);
    panel.dataset.requestKey = requestKey;
  }
  query("#wallet-authorize-expires").textContent = new Date(Date.now() + DEVICE_CAPABILITY_GRANT_MS).toLocaleString();
  const approve = query("#wallet-authorize-approve");
  const status = query("#wallet-authorize-status");
  if (!loaded && !storedIdentityRecord) {
    approve.disabled = true;
    status.textContent = "Create or load an identity before approving this application.";
  } else if (!loaded) {
    // Keep this actionable: approval is the natural place for a user to
    // discover that the tab auto-locked. Its click handler opens the same
    // header unlock prompt and shakes the lock icon.
    approve.disabled = false;
    status.textContent = "";
  } else if (walletAuthorization.did && loaded.entries.at(-1).state.id !== walletAuthorization.did) {
    approve.disabled = true;
    status.textContent = "A different identity is loaded in this tab. Load the identity requested above.";
  } else if (walletAuthorization.username && didMdUsername(loaded.entries.at(-1).state.id) !== walletAuthorization.username) {
    approve.disabled = true;
    status.textContent = "A different identity is loaded in this tab. Load the identity requested by this application.";
  } else {
    approve.disabled = false;
    status.textContent = "";
  }
  // Nothing to say when all is well (loaded, or locked and Approve will ask for the
  // passphrase): only problems get a line, and an empty one would leave a gap.
  status.classList.toggle("hidden", !status.textContent);
}

const PENDING_AUTHORIZE_SEARCH_KEY = "did-md-pending-authorize-search";

// #create-load-form's submit listener below finishes the "load an identity
// to satisfy a pending /authorize request" flow with a *native* GET
// submission, purely so a password manager sees a real navigation follow a
// password field. That reload silently drops location.search,
// which is the ONLY place the pending OAuth/OIDC request (client_id,
// redirect_uri, state, ...) lives -- with it gone, Approve looks like it
// needs a second click, when really the whole authorization request was
// lost and the user has to go back to the requesting application and start
// over. Stash it here before the reload and restore it at boot.
function stashPendingAuthorizeSearch() {
  if (location.pathname !== "/authorize" || !location.search) return;
  try { sessionStorage.setItem(PENDING_AUTHORIZE_SEARCH_KEY, location.search); } catch { /* best effort */ }
}

function restorePendingAuthorizeSearch() {
  if (location.pathname !== "/authorize") return;
  let search;
  try {
    search = sessionStorage.getItem(PENDING_AUTHORIZE_SEARCH_KEY);
    sessionStorage.removeItem(PENDING_AUTHORIZE_SEARCH_KEY);
  } catch { return; }
  // Not `|| location.search) return` (the reload this restores after
  // doesn't land with an empty query string): #create-load-form has no
  // `action`, so its own native GET submission lands back on /authorize
  // carrying ITS fields (username, password) as the new search, not
  // nothing -- bailing whenever *something* was already there left the
  // stashed OAuth/OIDC params (and the leaked create-form fields) sitting
  // untouched forever. A stash, once present, is always the authoritative
  // request to restore over whatever's currently there.
  if (search) history.replaceState(null, "", location.pathname + search + location.hash);
}

// A single authorization request shape for every relying party -- DPoP
// device clients (dpop_jkt present) and conventional ones (absent) alike.
// There is no more "kind: oauth" vs "kind: oidc" branch: whether the
// eventual capability document carries a deviceJkt, and whether an
// "openid"-scoped self-issued id_token is built, are just properties of
// this one parsed request (see approveAuthorization/setAliasStatusIcon-
// style unification elsewhere in this file for the same "one shape,
// no state-dependent branch" principle).
// PLAN6 §0.2: a relying party that authenticates itself via a did:webvh key
// (rather than DCR client_id/secret) sends a JAR (RFC 9101) request object
// instead of flat query parameters. The outer query string then carries
// only client_id/response_type/request -- everything security-relevant
// (redirect_uri, state, code_challenge, dcql_query, ...) lives inside the
// signed JWT, so an attacker tampering with the unsigned outer URL cannot
// change any of it. verifyRequestObjectJws resolves the RP's DID key from
// its own published did:webvh log and checks the signature; the redirect_uri
// is additionally checked against that same DID document's `service` array
// (PLAN6 §0.3bis) -- this is the entire trust basis, there is no separate
// RP registration for a DID-authenticated relying party.
// PLAN7: response_type may
// be "code" (unchanged -- oidc-bridge and any other DCR/JAR relying party
// that still wants the api.did.md code+token round trip) or
// "vp_token id_token" (the pure SIOPv2/OID4VP shape: this Wallet delivers
// the signed capability/id_token straight to the RP itself, by fragment or
// postMessage -- see oauthDeliver/approveAuthorization -- with no
// api.did.md call in between). code_challenge/PKCE only applies to the
// "code" shape: there is no code to protect from interception once the
// response is delivered directly, so it is omitted entirely for
// "vp_token id_token".
function validResponseType(value) { return value === "code" || value === "vp_token id_token"; }
async function jarAuthorizationParameters(clientId, jwt) {
  const { payload, rpDid, service } = await verifyRequestObjectJws(jwt);
  if (rpDid !== clientId) throw new Error("The authorization request client_id does not match its signer.");
  if (payload.client_id !== clientId || !validResponseType(payload.response_type)) throw new Error("The authorization request is invalid.");
  const usesCode = payload.response_type === "code";
  if (usesCode && (payload.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(payload.code_challenge ?? ""))) throw new Error("The authorization request is invalid.");
  if (!usesCode && (payload.code_challenge !== undefined || payload.code_challenge_method !== undefined)) throw new Error("The authorization request is invalid.");
  if (!/^[A-Za-z0-9._~-]{16,512}$/.test(payload.state ?? "")) throw new Error("The authorization request is invalid.");
  // PLAN8: response_mode=
  // direct_post lets a real backend RP (oidc-bridge) receive vp_token/
  // id_token via its own POST endpoint (response_uri) rather than biset's
  // fragment/postMessage (see oauthDeliver) -- the OID4VP-standard third
  // delivery channel PLAN7 §0.2 left unimplemented because biset has no
  // backend to POST to. Mutually exclusive with redirect_uri, per OID4VP:
  // accepting both would let a request smuggle an unpublished redirect
  // target past the "published in the RP's own DID document" check below.
  const directPost = payload.response_mode === "direct_post";
  if (payload.response_mode !== undefined && !directPost) throw new Error("The authorization request is invalid.");
  if (directPost && usesCode) throw new Error("The authorization request is invalid.");
  let redirect, responseUri;
  if (directPost) {
    if (payload.redirect_uri !== undefined) throw new Error("The authorization request is invalid.");
    try { responseUri = new URL(payload.response_uri ?? ""); } catch { throw new Error("The response URI is invalid."); }
    if (responseUri.protocol !== "https:" || responseUri.username || responseUri.password || responseUri.hash || responseUri.toString() !== payload.response_uri) throw new Error("The response URI is invalid.");
    if (!service.some(entry => entry && typeof entry === "object" && entry.serviceEndpoint === payload.response_uri)) throw new Error("The response URI is not published by the relying party's own DID document.");
  } else {
    if (payload.response_uri !== undefined) throw new Error("The authorization request is invalid.");
    try { redirect = new URL(payload.redirect_uri ?? ""); } catch { throw new Error("The redirect URI is invalid."); }
    if (redirect.protocol !== "https:" || redirect.username || redirect.password || redirect.hash || redirect.toString() !== payload.redirect_uri) throw new Error("The redirect URI is invalid.");
    if (!service.some(entry => entry && typeof entry === "object" && entry.serviceEndpoint === payload.redirect_uri)) throw new Error("The redirect URI is not published by the relying party's own DID document.");
  }
  const dcql = payload.dcql_query;
  const typeValues = dcql?.credentials?.[0]?.meta?.type_values?.[0];
  if (!Array.isArray(typeValues) || typeValues[0] !== "VerifiableCredential" || typeof typeValues[1] !== "string" || !/^[A-Za-z][A-Za-z0-9:._/-]{0,127}$/.test(typeValues[1])) throw new Error("The requested capability type is invalid.");
  if (payload.nonce !== undefined && typeof payload.nonce !== "string") throw new Error("The authorization request is invalid.");
  if (payload.dpop_jkt !== undefined && !/^[A-Za-z0-9_-]{43}$/.test(payload.dpop_jkt)) throw new Error("The DPoP thumbprint is invalid.");
  // scope is independent of dcql_query's capability type (that names the
  // capability *document* being requested; scope is what the resulting
  // access token/id_token are good for, e.g. "openid" gates id_token
  // issuance below in approveAuthorization) -- carried as the same
  // space-separated string the flat-query flow uses, just as a JWT claim
  // instead of a query parameter.
  const scope = [...new Set((payload.scope ?? "").split(" "))];
  if (!scope.length || scope.length > 16 || scope.some(item => !/^[A-Za-z][A-Za-z0-9:._/-]{0,95}$/.test(item))) throw new Error("The requested scope is invalid.");
  let username;
  if (payload.login_hint !== undefined) {
    const login = /^(?<username>[a-z0-9](?:[a-z0-9-]{0,61})?)\.did\.md$/.exec(payload.login_hint);
    if (!login) throw new Error("The login hint must be a did.md hostname.");
    username = login.groups.username;
  }
  // What the application calls itself (OID4VP client_metadata.client_name, inside the RP's signed request).
  const rawName = payload.client_metadata?.client_name;
  const clientDisplayName = typeof rawName === "string" && rawName.trim() && rawName.length <= 160 ? rawName.trim() : undefined;
  // The app's home as the RP asserts it (client_uri): only its host is kept, and only for https.
  let clientDisplayHost;
  try {
    const uri = new URL(payload.client_metadata?.client_uri ?? "");
    if (uri.protocol === "https:" && !uri.username && !uri.password && uri.host.length <= 160) clientDisplayHost = uri.host;
  } catch { /* absent or malformed: no domain shown */ }
  return {
    clientDisplayName, clientDisplayHost,
    clientId, responseType: payload.response_type, responseMode: directPost ? "direct_post" : undefined,
    codeChallenge: payload.code_challenge,
    deviceJkt: payload.dpop_jkt, loginHint: payload.login_hint, username,
    redirectUri: payload.redirect_uri, responseUri: payload.response_uri, state: payload.state, nonce: payload.nonce,
    scope, authorizationDetails: oauthAuthorizationDetails(payload.authorization_details ?? null),
    capabilityType: typeValues[1],
  };
}

async function oauthAuthorizationParameters() {
  if (location.pathname !== "/authorize") return null;
  const params = new URLSearchParams(location.search);
  const keys = [...params.keys()];
  if (params.get("client_id")?.startsWith("did:webvh:")) {
    const jarKeys = ["client_id", "request", "response_type"];
    if (keys.length !== jarKeys.length || keys.some(key => !jarKeys.includes(key)) || !validResponseType(params.get("response_type"))) throw new Error("The authorization request is invalid.");
    return jarAuthorizationParameters(params.get("client_id"), params.get("request"));
  }
  const usesCode = params.get("response_type") === "code";
  const required = ["client_id", "redirect_uri", "response_type", "scope", "state", ...(usesCode ? ["code_challenge", "code_challenge_method"] : [])];
  const optional = ["alias", "authorization_details", "capability_type", "dpop_jkt", "login_hint", "nonce"];
  if (keys.length < required.length || new Set(keys).size !== keys.length || keys.some(key => !required.includes(key) && !optional.includes(key))) throw new Error("The authorization request is invalid.");
  const value = Object.fromEntries([...required, ...optional].map(key => [key, params.get(key)]));
  if (!/^client_[A-Za-z0-9_-]{32,128}$/.test(value.client_id ?? "") || !validResponseType(value.response_type) || !/^[A-Za-z0-9._~-]{16,512}$/.test(value.state ?? "")) throw new Error("The authorization request is invalid.");
  if (usesCode && (value.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(value.code_challenge ?? ""))) throw new Error("The authorization request is invalid.");
  let redirect;
  try { redirect = new URL(value.redirect_uri ?? ""); } catch { throw new Error("The redirect URI is invalid."); }
  if ((redirect.protocol !== "https:" && !(redirect.protocol === "file:" && !redirect.host)) || redirect.username || redirect.password || redirect.hash || redirect.toString() !== value.redirect_uri) throw new Error("The redirect URI is invalid.");
  const scope = [...new Set((value.scope ?? "").split(" "))];
  if (!scope.length || scope.length > 16 || scope.some(item => !/^[A-Za-z][A-Za-z0-9:._/-]{0,95}$/.test(item))) throw new Error("The requested scope is invalid.");
  // dpop_jkt is optional: a conventional relying party (no device key of
  // its own) simply omits it, and the resulting capability document omits
  // deviceJkt too (see approveAuthorization).
  if (value.dpop_jkt !== null && !/^[A-Za-z0-9_-]{43}$/.test(value.dpop_jkt)) throw new Error("The DPoP thumbprint is invalid.");
  // login_hint is optional: when present it pins the consent screen to one
  // specific locally-loaded identity; when absent, whichever identity is
  // already loaded in this tab is used, same as it always was for OIDC.
  let username;
  if (value.login_hint !== null) {
    const login = /^(?<username>[a-z0-9](?:[a-z0-9-]{0,61})?)\.did\.md$/.exec(value.login_hint);
    if (!login) throw new Error("The login hint must be a did.md hostname.");
    username = login.groups.username;
  }
  const authorizationDetails = oauthAuthorizationDetails(value.authorization_details);
  // capability_type: the RP-owned name for the capability document this
  // authorization will produce (see PLAN2-capability-ownership.md). did.md
  // no longer decides this name -- a relying party that omits it gets the
  // long-standing default so existing registrations (oidc-bridge, and any
  // RP that only reads the id_token/access_token and never inspects the
  // capability document's type) keep working unchanged.
  if (value.capability_type !== null && !/^[A-Za-z][A-Za-z0-9:._/-]{0,127}$/.test(value.capability_type)) throw new Error("The requested capability type is invalid.");
  const capabilityType = value.capability_type ?? "did.md/DeviceCapability";
  // authorization_details belongs to the relying party.  Showing the
  // capability approval must not depend on an application-specific detail
  // parser succeeding; that parser runs only when the user approves.
  // alias itself is deliberately not read here: it's just listed in
  // `optional` above so its presence on this page's query string (e.g. a
  // relying party's /authorize redirect) doesn't fail the strict allowlist
  // check below. requestedAliasFromUrl reads location.search directly and
  // covers both this page and a bare https://app.did.md/?alias.
  return {
    clientId: value.client_id, responseType: value.response_type, codeChallenge: usesCode ? value.code_challenge : undefined,
    deviceJkt: value.dpop_jkt ?? undefined, loginHint: value.login_hint ?? undefined, username,
    redirectUri: value.redirect_uri, state: value.state, nonce: value.nonce ?? undefined,
    scope, authorizationDetails, capabilityType,
  };
}

// Settles when the boot-time read of the stored identity has finished.
let identityRestored = Promise.resolve();

async function beginOAuthAuthorization() {
  if (location.pathname !== "/authorize") return;
  // An invalid request must not leave its explanation hidden on the default
  // Authorization always has a visible Identity surface: either the
  // JWE loading surface or the precise request-validation error.
  selectTab("home");
  try {
    const request = await oauthAuthorizationParameters();
    if (!request) return;
    // A did:webvh-authenticated relying party (PLAN6) has no DCR
    // registration to look up: jarAuthorizationParameters already verified
    // its identity (JAR signature) and its redirect_uri (against its own
    // DID document's `service` array) directly, so client metadata is
    // derived from the request itself rather than fetched from
    // /v1/oauth/clients/.
    let clientName;
    if (request.clientId.startsWith("did:webvh:")) {
      clientName = request.clientId;
    } else {
      const response = await fetch(`${API}/v1/oauth/clients/${encodeURIComponent(request.clientId)}`, { cache: "no-store" });
      if (!response.ok) throw new Error(await response.text());
      const client = await response.json();
      if (!client || typeof client !== "object") throw new Error("The registered OAuth client metadata is invalid (response is not an object).");
      if (client.client_id !== request.clientId) throw new Error("The registered OAuth client metadata is invalid (client_id mismatch).");
      if (typeof client.client_name !== "string") throw new Error("The registered OAuth client metadata is invalid (client_name missing).");
      if (!Array.isArray(client.redirect_uris)) throw new Error("The registered OAuth client metadata is invalid (redirect_uris missing).");
      if (!client.redirect_uris.includes(request.redirectUri)) throw new Error(`The registered OAuth client metadata is invalid (redirect_uri ${request.redirectUri} is not registered).`);
      if (typeof client.scope !== "string") throw new Error("The registered OAuth client metadata is invalid (scope missing).");
      const registeredScopes = client.scope.split(" ");
      if (request.scope.some(scope => !registeredScopes.includes(scope))) throw new Error("The application requested a scope it did not register.");
      clientName = client.client_name;
    }
    walletAuthorization = { ...request, clientName };
    renderSync();
    selectTab("home");
    // Only when there is no identity at all. A stored but locked identity already
    // has one (Approve will ask for its passphrase), so telling the person to
    // "create or load an identity" would be wrong.
    await identityRestored;
    if (!loaded && !storedIdentityRecord) {
      // No identity at all yet lands on the creation screen (see
      // renderRoute's hasIdentity check) -- show this in ITS OWN output
      // field, not #wallet-result, which sits below the (now collapsed,
      // mostly empty-looking) authorize card further down the page and
      // read as if some unrelated banner had appeared there (found live,
      // 2026-09-14). A stored-but-locked identity still lands on the
      // dashboard, where #wallet-result is the right (only) place for it.
      const message = `Create or load an identity to authorize ${clientName}; no private key will be sent to the application.`;
      output("#create-result", message);
    }
  } catch (error) {
    output("#wallet-result", errorMessage(error), true);
  }
}

function oauthRedirect(request, values) {
  const target = new URL(request.redirectUri);
  for (const [key, value] of Object.entries(values)) target.searchParams.set(key, value);
  target.searchParams.set("iss", OAUTH_ISSUER);
  if (target.protocol === "file:" && !target.host) {
    // Safari may intentionally sever the opener relationship for a popup
    // opened by a file:// document. The client polls the short-lived, PKCE/DPoP
    // bound delivery record in that case.
    if (!window.opener) {
      output("#wallet-result", "Authorization completed. Return to the requesting application; it will finish signing in automatically.");
      return;
    }
    window.opener.postMessage({ type: "did.md/oauth-file-callback", protocol: 1, ...Object.fromEntries(target.searchParams), iss: OAUTH_ISSUER }, "*");
    window.close();
    return;
  }
  location.replace(target.toString());
}

// PLAN7: delivers a
// "vp_token id_token" response straight to the RP -- no api.did.md call,
// no `code` -- via whichever of biset's two existing channels applies.
// Same two channels oauthRedirect already uses for the "code" shape; only
// WHERE the payload travels changes, not the channel selection logic:
//   - https redirect_uri: URL fragment (never sent to any server, unlike a
//     query string -- no Referer/access-log exposure of the credential)
//   - file:// popup: postMessage to window.opener (already exposes nothing
//     outside this browser; same mechanism as the "code" shape, different
//     payload keys)
async function oauthDeliver(request, values) {
  const payload = { ...values, iss: OAUTH_ISSUER };
  // PLAN8: a real backend RP
  // (oidc-bridge) receives the response via its own POST endpoint instead
  // of a browser-only channel -- this Wallet POSTs directly to
  // response_uri and follows the single `redirect_uri` it hands back, per
  // OID4VP's direct_post response mode.
  if (request.responseMode === "direct_post") {
    const response = await fetch(request.responseUri, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(payload) });
    if (!response.ok) {
      const text = await response.text();
      let detail = text;
      try { detail = JSON.parse(text)?.error_description ?? text; } catch { /* not JSON: show it as is */ }
      // The relying party's request state lives a few minutes and works once: an old
      // tab, a reload after a wait, or a second Approve all end up here.
      if (/state is invalid/i.test(detail)) {
        throw new Error("This sign-in request has expired or was already used. Go back to the application and start again.");
      }
      throw new Error(`The application did not accept the response (${response.status}): ${detail}`);
    }
    const completed = await response.json();
    let completedRedirect;
    try { completedRedirect = new URL(completed?.redirect_uri ?? ""); } catch { throw new Error("The relying party returned an invalid direct_post response."); }
    // Same https-only scheme check as redirect_uri/response_uri above --
    // this value is RP-controlled (oidc-bridge's own response), so an
    // unvalidated scheme here would let a buggy or compromised RP turn a
    // same-origin navigation into a javascript:/data: URL executed with
    // this page's own privileges.
    if (completedRedirect.protocol !== "https:") throw new Error("The relying party returned an invalid direct_post response.");
    location.replace(completedRedirect.toString());
    return;
  }
  const target = new URL(request.redirectUri);
  if (target.protocol === "file:" && !target.host) {
    if (!window.opener) {
      output("#wallet-result", "Authorization completed. Return to the requesting application; it will finish signing in automatically.");
      return;
    }
    window.opener.postMessage({ type: "did.md/oauth-file-callback", protocol: 1, ...payload }, "*");
    window.close();
    return;
  }
  target.hash = new URLSearchParams(payload).toString();
  location.replace(target.toString());
}

async function approveAuthorization() {
  if (!walletAuthorization) throw new Error("There is no pending authorization request.");
  if (!loaded) throw new Error("Load the requested identity before approving.");
  const did = loaded.entries.at(-1).state.id;
  // login_hint (and so .username) is optional -- when the relying party
  // didn't send one, whichever identity is already loaded in this tab is
  // the one being authorized, same as it always was for a conventional
  // (non-DPoP) client.
  if (walletAuthorization.username && didMdUsername(did) !== walletAuthorization.username) throw new Error("The loaded identity does not match the authorization request.");
  const issuedAtMilliseconds = Date.now(); const issuedAt = new Date(issuedAtMilliseconds).toISOString();
  const edit = didDocumentEditDetail(walletAuthorization.authorizationDetails, did);
  const keyAuthorization = keyAuthorizationDetail(walletAuthorization.authorizationDetails);
  derivedSecretDetails(walletAuthorization.authorizationDetails); // validates before any network/signing work below
  if (edit && (edit.services.length || edit.verificationMethods.length || edit.remove.length)) {
    // The did:webvh implicit `#files` service dereferences
    // `<did>/routing.json` at this origin-root URL (never under .well-known).
    const currentResponse = await fetch(rootResource(did, "routing.json"), { cache: "no-store" });
    if (!currentResponse.ok && currentResponse.status !== 404) throw new Error(`Could not read existing routing metadata (${currentResponse.status}).`);
    const existing = currentResponse.status === 404 ? {} : await currentResponse.json();
    if (!existing || typeof existing !== "object" || Array.isArray(existing)) throw new Error("Existing routing metadata is invalid.");
    const routing = { ...existing };
    delete routing.proof;
    const isRemoved = id => edit.remove.some(removed => sameDidDocumentReference(did, id, removed));
    const methods = (Array.isArray(existing.keyAgreementVerificationMethod) ? existing.keyAgreementVerificationMethod : []).filter(value => !isRemoved(value.id));
    for (const method of edit.verificationMethods) { const index = methods.findIndex(value => sameDidDocumentReference(did, value.id, method.id)); if (index < 0) methods.push(method); else methods[index] = method; }
    const services = (Array.isArray(existing.service) ? existing.service : []).filter(value => !isRemoved(value.id));
    for (const service of edit.services) { const index = services.findIndex(value => sameDidDocumentReference(did, value.id, service.id)); if (index < 0) services.push(service); else services[index] = service; }
    routing.keyAgreementVerificationMethod = methods; routing.service = services;
    const routingChanged = JSON.stringify({ ...existing, proof: undefined }) !== JSON.stringify(routing);
    if (routingChanged) {
      // Keep routing.json as a compatibility resource while also committing
      // the requested material to the signed DID Document.
      // This consumes one pre-rotated update key by design.
      await publishRoutingDidUpdate(withRoutingInDidDocument(loaded.entries.at(-1).state, edit));
      await publishRoutingResource(did, routing, issuedAt);
    }
  }
  // Sign only after a requested DID edit, so generation names the state that
  // actually resulted from this approval.
  const keyCredential = keyAuthorization
    ? await createKeyAuthorizationCredentialWire({
      issuer: did, audience: walletAuthorization.clientId, subject: keyAuthorization.subject,
      generation: loaded.entries.at(-1).versionId,
      publicKey: keyAuthorization.publicKey, purposes: keyAuthorization.purposes,
      issuedAt, expiresAt: new Date(issuedAtMilliseconds + DEVICE_CAPABILITY_GRANT_MS).toISOString(),
      rootPrivateKey: loaded.root.privateKey,
      signPrivateKey: loaded.sign.privateKey,
    })
    : undefined;
  // Echoes back what was actually published, not what the relying party
  // originally asked for: substitutes the signed key-authorization
  // credential in for its placeholder, and -- since didDocumentEditDetail
  // above already forced every verificationMethod's controller to this
  // identity's own DID -- the corrected `edit`, not the relying party's
  // original (possibly wrong) controller values, in for the raw document
  // edit detail.
  const authorizationDetails = walletAuthorization.authorizationDetails.map(detail => {
    if (keyAuthorization && detail.type === KEY_AUTHORIZATION_DETAIL) return { type: KEY_AUTHORIZATION_DETAIL, credential: keyCredential };
    if (edit && detail.type === DID_DOCUMENT_EDIT_DETAIL) return edit;
    if (detail.type === DERIVED_SECRET_DETAIL) {
      return {
        type: DERIVED_SECRET_DETAIL, purpose: detail.purpose, ...(detail.context !== undefined ? { context: detail.context } : {}),
        value: base64url(deriveWalletSecret(loaded.root.privateKey, detail.purpose, detail.context)),
      };
    }
    return detail;
  });
  // PLAN3: the capability sent to
  // did.md is now a VC-DM 2.0 credential (`vc`) with an embedded proof, not
  // a flat document. `capability` below stays the flat convenience shape
  // (id/audience/deviceJkt/scope/issuedAt/expiresAt) that
  // saveApplicationAuthorizationMetadata/saveWalletOAuthGrant/
  // saveAuthorizedDeviceBinding already expect -- it is local bookkeeping,
  // never sent over the wire itself, so it did not need to change shape.
  const capabilityId = `urn:uuid:${crypto.randomUUID()}`;
  const capabilityExpiresAt = new Date(issuedAtMilliseconds + DEVICE_CAPABILITY_GRANT_MS).toISOString();
  const unsignedVc = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: capabilityId,
    type: ["VerifiableCredential", walletAuthorization.capabilityType],
    issuer: did,
    credentialSubject: {
      audience: walletAuthorization.clientId,
      ...(walletAuthorization.deviceJkt ? { deviceJkt: walletAuthorization.deviceJkt } : {}),
      scope: walletAuthorization.scope, issuedAt, expiresAt: capabilityExpiresAt,
      ...(authorizationDetails.length ? { authorizationDetails } : {}),
    },
  };
  const vcProof = await createDataIntegrityProof(unsignedVc, { privateKey: loaded.root.privateKey, verificationMethod: `${did}#pass-1`, proofPurpose: "authentication", created: issuedAt });
  const vc = { ...unsignedVc, proof: vcProof };
  const capability = { id: capabilityId, audience: walletAuthorization.clientId, deviceJkt: walletAuthorization.deviceJkt, scope: walletAuthorization.scope, issuedAt, expiresAt: capabilityExpiresAt };
  // "openid" gets the relying party a self-issued id_token -- signed here,
  // directly with the identity's own Root key, never by dito's server (see
  // createSelfIssuedIdToken). preferred_username/nickname/name mirror the
  // shape the server used to build itself in the now-retired oidcProfile().
  const username = scidFromDid(did);
  const idToken = walletAuthorization.scope.includes("openid")
    ? createSelfIssuedIdToken({
      iss: did, sub: did, aud: walletAuthorization.clientId,
      iat: Math.floor(issuedAtMilliseconds / 1000), exp: Math.floor(issuedAtMilliseconds / 1000) + Math.floor(DEVICE_CAPABILITY_GRANT_MS / 1000),
      ...(walletAuthorization.nonce ? { nonce: walletAuthorization.nonce } : {}),
      ...(walletAuthorization.scope.includes("profile") ? { preferred_username: username, nickname: username, name: username } : {}),
      ...(walletAuthorization.scope.includes("email") ? { email: `${username}@users.did.invalid`, email_verified: false } : {}),
    }, { privateKey: loaded.root.privateKey, did })
    : undefined;
  await saveWalletOAuthGrant({ id: capability.id, did, clientId: capability.audience, clientName: walletAuthorization.clientName, label: requestedDeviceLabel(authorizeDefaultName()), ...(walletAuthorization.clientDisplayHost ?? walletAuthorization.clientDisplayName ? { appKey: walletAuthorization.clientDisplayHost ?? walletAuthorization.clientDisplayName } : {}), ...(capability.deviceJkt ? { deviceJkt: capability.deviceJkt } : {}), scope: capability.scope, issuedAt: capability.issuedAt, expiresAt: capability.expiresAt });
  if (capability.deviceJkt) await saveAuthorizedDeviceBinding({ did, deviceJkt: capability.deviceJkt, clientName: walletAuthorization.clientName, didCommKeyId: edit?.verificationMethods[0]?.id });
  await saveApplicationAuthorizationMetadata({ capability, edit, appKey: walletAuthorization.clientDisplayHost ?? walletAuthorization.clientDisplayName ?? undefined });
  // PLAN7: "vp_token id_token" delivers straight to the RP -- no
  // api.did.md call, no `code` -- see oauthDeliver's own comment. "code"
  // (oidc-bridge and any other RP still on the DCR/JAR + code+token
  // round trip) keeps calling /v1/oauth/authorize/complete exactly as
  // before.
  if (walletAuthorization.responseType === "vp_token id_token") {
    await oauthDeliver(walletAuthorization, { vp_token: JSON.stringify({ capability: [vc] }), ...(idToken ? { id_token: idToken } : {}), state: walletAuthorization.state });
    return;
  }
  const response = await fetch(`${API}/v1/oauth/authorize/complete`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_id: walletAuthorization.clientId, redirect_uri: walletAuthorization.redirectUri, state: walletAuthorization.state,
      code_challenge: walletAuthorization.codeChallenge, code_challenge_method: "S256",
      vp_token: { capability: [vc] }, ...(idToken ? { id_token: idToken } : {}),
      // Always offered, not just for a not-yet-published DID: the Root
      // (#pass-1) key this signs with never rotates across an identity's
      // life, so submitting its genesis entry is harmless even for an
      // already-hosted identity, and lets the server authenticate this
      // approval without depending on this host's own did.jsonl resolution.
      did_log: `${JSON.stringify(loaded.entries[0])}\n`,
    }),
  });
  if (!response.ok) throw new Error(await response.text());
  const completed = await response.json();
  if (!completed || typeof completed.code !== "string" || completed.state !== walletAuthorization.state || completed.redirect_uri !== walletAuthorization.redirectUri || completed.iss !== OAUTH_ISSUER) throw new Error("The authorization server returned an invalid authorization response.");
  oauthRedirect(walletAuthorization, { code: completed.code, state: completed.state });
}

async function rejectOAuthAuthorization() {
  if (!walletAuthorization) return;
  const pending = walletAuthorization;
  const values = { error: "access_denied", error_description: "The authorization was cancelled.", state: pending.state };
  try {
    if (pending.responseType === "vp_token id_token") { await oauthDeliver(pending, values); return; }
    oauthRedirect(pending, values);
  } catch (error) {
    // Closing the card must not depend on successfully notifying the RP --
    // e.g. oauthDeliver's direct_post can 400 if the bridge's own session
    // already expired (its 5-minute TTL) by the time Cancel is clicked.
    // Leaving the card open with no way to dismiss it just because that
    // notification failed is worse than closing it and saying so.
    walletAuthorization = null;
    renderWalletAuthorization();
    // The pending request still lives in this page's own URL (client_id,
    // request=<JAR>, ...) -- beginOAuthAuthorization re-parses that on every
    // load, so leaving it there would silently bring the card right back on
    // refresh even though it was just dismissed.
    if (location.pathname === "/authorize") history.replaceState(null, "", location.pathname);
    output("#loaded-identity-message", `Could not notify ${didHost(pending.clientName) ?? pending.clientName} that the request was cancelled: ${errorMessage(error)}`, true);
  }
}

function logoutWallet(message = "Private key material was cleared from this tab.", forgetSession = true) {
  clearLoadedIdentitySession();
  if (forgetSession) forgetPasskeyWalletSession();
  void restoreStoredIdentityRecord();
  void renderLoadedIdentity();
  if (message) output("#wallet-result", message);
}

/** Unlike logoutWallet (which only re-locks this tab; the identity stays
 * "loaded" for next time), this permanently erases the browser's copy: the
 * encrypted keyring, cached DID log, device labels, and grant records. Only
 * the Passphrase (or a separately held EIC) can restore it afterward. */
async function unloadIdentity() {
  clearLoadedIdentitySession();
  if (draft) {
    wipeCreateMaterial(draft.material);
    draft = null;
  }
  await clearBrowserIdentityState();
  storedIdentityRecord = null;
  publicApplicationState = null;
  query("#create-form-area").classList.add("hidden");
  query("#master-mnemonic").value = "";
  setCreationConfirmStep(false);
  renderSync();
  await refreshIdentityViews();
  void renderLoadedIdentity();
  void updateConnectionStatus();
  // The form stays hidden while its replacement draft is generated.
  maybeBeginCreateDraft();
  output("#create-result", "This identity was erased from this browser.");
}

// Shared by every fixed, centered "card" dialog (Connect help, ...): only
// one can be open at a time, and all three dismiss paths (Esc, clicking the
// scrim outside it, its own close button) go through closeModalCard() so a
// new card gets this for free by using these instead of hand-rolling its own
// open/close pair. Unload's own confirmation used to be one of these -- it's
// now the Context Window's inline "unload" view instead (see setUnloadView),
// consistent with Files/Export as "file context" actions rather than a
// floating overlay.
let openModalCardId = null;

// The GitHub host view is inline: it takes over the identity card's own
// contents (.github-host-open) instead of floating over the page, so it has
// no scrim.
const INLINE_CARD_IDS = new Set(["github-host-card"]);

function openModalCard(id) {
  query(`#${id}`).classList.remove("hidden");
  if (INLINE_CARD_IDS.has(id)) query(".user-info-copy").classList.add("github-host-open");
  else query("#menu-scrim").classList.remove("hidden");
  openModalCardId = id;
}

function closeModalCard() {
  if (!openModalCardId) return;
  // PLAN-github-host: a PAT typed into #github-pat-input must leave the
  // DOM on every dismiss path (close button, Escape, scrim) -- not only
  // on Cancel -- or it would linger in a hidden input.
  if (openModalCardId === "github-host-card") wipeGitHubPat();
  query(`#${openModalCardId}`).classList.add("hidden");
  if (INLINE_CARD_IDS.has(openModalCardId)) query(".user-info-copy").classList.remove("github-host-open");
  else query("#menu-scrim").classList.add("hidden");
  openModalCardId = null;
}

document.addEventListener("keydown", event => {
  if (event.key === "Escape" && openModalCardId) closeModalCard();
  if (event.key === "Escape" && unloadViewActive) setUnloadView(false);
});

// Plain-text clickable elements (role="button"/"tab" on a <span> rather than
// a <button> -- see #identity-alias-edit, the per-file spans in
// renderIdentityFiles, .application-tabs [role="tab"]) get Enter/Space
// activation for free on a real <button>; a <span> needs it wired by hand or
// keyboard users lose it.
document.addEventListener("keydown", event => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const target = event.target.closest('[role="button"], [role="tab"]');
  if (!target || target.tagName === "BUTTON") return;
  event.preventDefault();
  target.click();
});

queryAll(".modal-card-close").forEach(button => {
  button.addEventListener("click", closeModalCard);
});

query("#nav-unload").addEventListener("click", () => {
  closeMenu();
  setUnloadView(true);
});

query("#context-unload-menu").addEventListener("click", () => {
  setUnloadView(true);
});
// Second entry point for the same confirmation, from the Files tab -- see
// the comment on #files-unload in dashboard.html.
query("#files-unload").addEventListener("click", () => {
  setUnloadView(true);
});
// Closing this view (no Cancel button of its own) is #files-back, wired
// alongside updateFilesHeader() above -- one <- for every detail view this
// card can show, not a separate one per view.

query("#context-unload-confirm").addEventListener("click", async () => {
  const submit = query("#context-unload-confirm");
  submit.disabled = true;
  const disconnect = query("#unload-disconnect-host").checked;
  const hosted = isHostedConnected();
  const unload = async () => {
    try {
      if (disconnect && hosted) await disconnectHostedData();
      await unloadIdentity();
      setUnloadView(false);
    } catch (error) {
      output("#loaded-identity-message", errorMessage(error), true);
    } finally {
      submit.disabled = false;
    }
  };
  if (disconnect && hosted) {
    if (!loaded) {
      submit.disabled = false;
      setUnloadView(false);
    }
    await withUnlock(unload);
  } else {
    await unload();
  }
});

// A host move (see connectHostedData) signs the disconnect with the Sign
// key that was current *for that host* -- the one it actually knows about
// -- since the server checks the proof against its own last-seen
// updateKeys, not whatever key generation the identity has rotated to
// since. host.ts's adapter builds that proof inside remove().
// GitHub removes only the DID files (repo stays) and needs a PAT; a
// missing one opens the same dialog with intent "remove" and resumes.
// Returns "removed" or "awaiting-credential" so callers do not flip the
// status-dot before the write actually happened.
async function disconnectHostedDataAt(did, signKey = loaded.sign) {
  const host = hostForDid(did);
  try {
    await host.remove(did, signKey, currentGitHubPat() ?? undefined);
    return "removed";
  } catch (error) {
    if (error instanceof CredentialRequiredError) {
      // A remembered token should have prevented this -- ask again.
      pendingGitHubPublish = () => disconnectHostedDataAt(did, signKey);
      openGitHubHostCard({ intent: "remove" });
      return "awaiting-credential";
    }
    if ((error as { status?: number }).status === 401 || /rejected this token/i.test(String((error as Error).message))) {
      clearStoredGitHubPat();
      githubPatInMemory = null;
      pendingGitHubPublish = () => disconnectHostedDataAt(did, signKey);
      openGitHubHostCard({ intent: "remove" });
      output("#loaded-identity-message", "Saved GitHub token was rejected. Paste a new one.", true);
      return "awaiting-credential";
    }
    throw error;
  }
}

async function disconnectHostedData() {
  if (!loaded) throw new Error("Unlock this identity first.");
  const did = loaded.entries.at(-1).state.id;
  const outcome = await disconnectHostedDataAt(did);
  if (outcome !== "removed") return; // PAT dialog is open; keep the dot as-is
  hintConnection(false);
  await updateConnectionStatus();
  output("#loaded-identity-message", hostForDid(did).kind === "github"
    ? `Removed DID files from GitHub.${GITHUB_PAGES_LAG_NOTE}`
    : `Removed ${didHost(did) ?? "identity"} from the server.`);
}

// The disconnected-state counterpart to disconnectHostedData() --
// republishes to the same host this identity is already configured for
// (didHost of its own current DID), not a new one: reuses
// connectHostedData()'s own PUT, which is a plain republish (not a move,
// so none of its portable-import logic runs) whenever the target host
// already matches. Provisional identities (no host yet) throw here instead
// -- #connection-dot has no separate hidden state for those, see
// updateConnectionStatus.
async function republishHostedData() {
  if (!loaded) throw new Error("Unlock this identity first.");
  const did = loaded.entries.at(-1).state.id;
  const host = hostForDid(did);
  if (host.kind === "github") {
    // GitHub has no PUT -- rewrite the full log through the adapter
    // (prompts for a PAT when needed).
    const status = await publishEntriesToCurrentHost(
      loaded.entries,
      `Republish did:webvh ${loaded.entries.at(-1).versionId}`,
      "replace",
      () => republishHostedData(),
    );
    if (status === "published") await updateConnectionStatus();
    return;
  }
  const targetHost = didHost(did);
  if (!targetHost) throw new Error("This identity has no host to republish to.");
  await connectHostedData(targetHost);
  await updateConnectionStatus();
}

query("#context-menu-button").addEventListener("click", event => {
  event.stopPropagation();
  setMenuView(!menuViewActive);
});
query("#context-menu-close").addEventListener("click", () => setMenuView(false));
query("#context-menu-view").addEventListener("click", event => {
  if (event.target.closest(".context-connect-button")) return;
  setCommandMode(true, "menu");
});
query("#context-connect-menu").addEventListener("click", () => {
  setAliasEditMode(true);
});

queryAll("#nav-menu button[data-tab], .page-toc button[data-tab], .switch-tab").forEach(el => el.addEventListener("click", event => {
  if (el.tagName === "A") event.preventDefault();
  selectTab(el.dataset.tab);
}));

query("#site-header-logo-home").addEventListener("click", () => {
  setCreationLoadMode(false);
  navigate("/");
});
query("#creation-about-link").addEventListener("click", event => {
  event.preventDefault();
  navigate("/about");
});
query("#about-back-link").addEventListener("click", event => {
  event.preventDefault();
  navigate("/");
});

queryAll("[data-application-tab]").forEach(button => {
  button.addEventListener("click", () => {
    const tab = button.dataset.applicationTab;
    // Leaving and returning to Keys is "the next action" that clears
    // #rotate-key's own "Rotated" state back to normal -- see justRotated.
    if (tab === "credentials") justRotated = false;
    if (tab === "credentials" && storedIdentityRecord) void withUnlock(() => selectApplicationTab("credentials"));
    else selectApplicationTab(tab);
  });
});

query("#menu-toggle")?.addEventListener("click", toggleMenu);
query("#loaded-identity-menu")?.addEventListener("click", toggleMenu);
query("#menu-scrim").addEventListener("click", () => {
  if (openModalCardId) { closeModalCard(); return; }
  closeMenu();
});
query("#nav-logout").addEventListener("click", () => logoutWallet());

async function downloadIdentityBackup(kind, record, masterSeed) {
  const container = kind === "real" ? await createIdentityContainer(masterSeed) : await provisionalContainerFromStoredRecord(record, masterSeed);
  downloadWalletBackup(await encryptIdentityContainer(container, masterSeed), container.manifest.identities[0].did);
}

/** Rebuilds a provisional (still genesis) container after a reload, when
 * only the local record and its cached log snapshot survive -- there is no
 * host to fetch the log from yet, unlike createIdentityContainer. */
async function provisionalContainerFromStoredRecord(record, masterSeed) {
  const snapshot = await readDidLogSnapshot(record.username);
  if (!snapshot?.didJsonl) throw new Error("This provisional identity's log is not cached in this browser; export it in the same tab session where it was created or loaded.");
  const entries = parseLog(snapshot.didJsonl);
  const entry = entries.at(-1);
  const didLogPath = containerPath(record.did, "did.jsonl");
  const keyringPath = containerPath(record.did, "keyring.json");
  return {
    format: "did.md/identity-container",
    version: 3,
    manifest: {
      format: "did.md/identity-container",
      version: 3,
      createdAt: new Date().toISOString(),
      provisional: true,
      identities: [{
        did: entry.state.id, rootKey: record.rootKey, generation: entry.versionId,
        didLogPath, keyringPath, derivationProfile: "did.md/master-ed25519-v1",
      }],
      contents: [didLogPath, keyringPath, "metadata/device-bindings.json", "metadata/grants.json"],
    },
    files: {
      [didLogPath]: snapshot.didJsonl,
      [keyringPath]: { type: "bip39-slip10-ed25519", masterEntropy: base64url(masterSeed), derivationProfile: "did.md/master-ed25519-v1" },
      "metadata/device-bindings.json": [],
      "metadata/grants.json": { oauth: [] },
    },
  };
}

onClick("#wallet-backup-export", () => (loaded ? "#loaded-identity-message" : "#wallet-result"), async () => {
  const record = storedIdentityRecord;
  if (!record) throw new Error("Create or load an identity first.");
  const kind = isProvisionalDid(record.did) ? "provisional" : "real";
  await withUnlock(async () => {
    if (!loaded || loaded.record?.username !== record.username) throw new Error("A different identity is loaded in this tab.");
    await downloadIdentityBackup(kind, record, loaded.masterSeed);
    // Only on success -- an error here still falls through to onClick's own
    // resultTarget (a toast), same as any other action. This view showing
    // means the download already happened, not a separate step still to do.
    setExportView(true);
  });
});

// This tool is intentionally part of the same single-file app. It uses
// WebCrypto and the already-bundled did:webvh implementation only; it does
// not rely on IndexedDB, a passkey, or an app.did.md session.
function parsePortableEicForMove(value) {
  if (!value || typeof value !== "object" || value.format !== "did.md/identity-container" || (value.version !== 2 && value.version !== 3)
    || !value.manifest || value.manifest.version !== value.version || !Array.isArray(value.manifest.identities) || value.manifest.identities.length !== 1
    || !value.files || typeof value.files !== "object") throw new Error("This operation accepts one did.md identity container (v2 or v3).");
  const identity = value.manifest.identities[0];
  if (!identity || typeof identity.did !== "string" || typeof identity.didLogPath !== "string" || typeof identity.keyringPath !== "string") {
    throw new Error("The EIC manifest is invalid.");
  }
  const source = value.files[identity.didLogPath];
  const keyring = value.files[identity.keyringPath];
  if (typeof source !== "string" || !source.endsWith("\n") || !keyring || keyring.type !== "bip39-slip10-ed25519" || keyring.derivationProfile !== "did.md/master-ed25519-v1") {
    throw new Error("The EIC log or portable keyring is invalid.");
  }
  const entries = parseLog(source);
  if (!entries.length || entries.at(-1)?.state?.id !== identity.did) throw new Error("The EIC history does not match its DID.");
  const masterSeed = base64urlBytes(keyring.masterEntropy, "Master entropy");
  if (masterSeed.length !== 32) throw new Error("Master entropy must be 32 bytes.");
  return { source, entries, masterSeed, did: identity.did };
}

// The did:webvh DID-to-HTTPS transformation (see the method spec): strips
// the did:webvh: prefix and SCID, decodes the domain (with its optional
// %3A-encoded port) and any deployment path segments, and reconstructs the
// HTTPS URL for the DID Log.
function didWebvhToHttpsUrl(did) {
  const prefix = "did:webvh:";
  if (!did.startsWith(prefix)) throw new Error("Not a did:webvh identifier.");
  const rest = did.slice(prefix.length);
  const firstColon = rest.indexOf(":");
  if (firstColon === -1) throw new Error("This did:webvh identifier has no domain.");
  const scid = rest.slice(0, firstColon);
  const segments = rest.slice(firstColon + 1).split(":");
  const domainSegment = segments.shift();
  const portMatch = /^(.*)%3A(\d{1,5})$/i.exec(domainSegment);
  const domain = decodeURIComponent(portMatch ? portMatch[1] : domainSegment);
  const host = portMatch ? `${domain}:${portMatch[2]}` : domain;
  const path = segments.length ? `/${segments.map(segment => encodeURIComponent(decodeURIComponent(segment))).join("/")}` : "/.well-known";
  return { url: `https://${host}${path}/did.jsonl`, scid };
}

async function loadFromOnlineDid(did, masterSeed, mnemonic) {
  const { url } = didWebvhToHttpsUrl(did);
  const username = await storageKeyForDid(did);
  clearLoadedIdentitySession();
  await clearBrowserIdentityState();
  // Fetch and verify the Passphrase against the live log first; only a
  // verified identity is persisted, matching the pattern used elsewhere for
  // loading a real identity by its Passphrase.
  await loadMasterIdentity(username, did, undefined, masterSeed, url);
  loaded.record = await savePasswordStoredIdentity({
    username, did: loaded.entries.at(-1).state.id, rootKey: loaded.root.multikey,
    generation: loaded.entries.at(-1).versionId, masterSeed, password: mnemonic,
  });
  // loadMasterIdentity() only sets `loaded` -- unlike unlockIdentity(), it
  // does not refresh the UI. Without this, `loaded` was already true (this
  // identity really is loaded) while the screen kept showing the Load form,
  // forever, since nothing ever told it to re-render.
  await keepOnlyLoadedIdentityRecord();
  void activateLoadedIdentity();
}

/** Saves the provisional identity's password-protected Master and a local
 * snapshot of its (unpublished) genesis log, so reloading this browser still
 * shows it as loaded. Without a password, nothing survives a reload -- the
 * same as any other identity in this app. */
async function persistProvisionalIdentity(entryOrEntries, masterSeed, protection) {
  if (!protection?.password && !protection?.protector) return;
  const entries = Array.isArray(entryOrEntries) ? entryOrEntries : [entryOrEntries];
  const entry = entries.at(-1);
  const username = await storageKeyForDid(entry.state.id);
  const root = await rootFromMasterSeed(masterSeed);
  try {
    if (protection.protector) {
      await saveMasterStoredIdentity({ username, did: entry.state.id, rootKey: root.multikey, generation: entry.versionId, masterSeed, protector: protection.protector });
    } else {
      await savePasswordStoredIdentity({ username, did: entry.state.id, rootKey: root.multikey, generation: entry.versionId, masterSeed, password: protection.password });
    }
  } finally {
    wipe(root.privateKey);
  }
  await saveDidLogSnapshot({
    username,
    did: entry.state.id,
    generation: entry.versionId,
    didJsonl: `${entries.map(item => JSON.stringify(item)).join("\n")}\n`,
    savedAt: new Date().toISOString(),
  });
}

async function loadProvisionalIdentityForMove(entryOrEntries, masterSeed, protection) {
  updateOverviewState();
  updateIdentityOptionsVisibility();
  try {
    await persistProvisionalIdentity(entryOrEntries, masterSeed, protection);
    storedIdentityRecord = (await listStoredIdentities())[0] ?? null;
    return true;
  } catch (error) {
    output("#wallet-result", `Loaded in this tab, but could not save it locally: ${errorMessage(error)}`, true);
    return false;
  }
}

// A provisional genesis identity is still an identity the user has chosen
// to work with. Loading it replaces the browser's previous local identity.
async function replaceBrowserIdentityWithProvisional(entryOrEntries, masterSeed, protection) {
  clearLoadedIdentitySession();
  await clearBrowserIdentityState();
  updateNavVisibility();
  return loadProvisionalIdentityForMove(entryOrEntries, masterSeed, protection);
}

query("#header-load-toggle").addEventListener("click", () => {
  if (locationRoute() !== "/") {
    navigate("/");
    setCreationLoadMode(true);
    return;
  }
  setCreationLoadMode(!query("#create-load-form").classList.contains("creation-load-mode"));
});

document.addEventListener("click", event => {
  const toggle = event.target.closest(".recovery-toggle");
  if (!toggle) return;
  const field = toggle.dataset.for
    ? query(`#${toggle.dataset.for}`)
    : query(`[name="${toggle.dataset.forName}"]`);
  if (!field) return;
  const revealed = field.type === "text";
  field.type = revealed ? "password" : "text";
  toggle.textContent = revealed ? "Show" : "Hide";
});

document.addEventListener("click", event => {
  const toggle = event.target.closest(".recovery-eye-toggle");
  if (!toggle) return;
  const field = query(`#${toggle.dataset.for}`);
  if (!field) return;
  const revealed = field.type === "text";
  field.type = revealed ? "password" : "text";
  toggle.setAttribute("aria-label", revealed ? "Show passphrase" : "Hide passphrase");
  query(`#${toggle.dataset.for}-eye-slash`).classList.toggle("hidden", !revealed);

  // Purely cosmetic wrapped view, #master-mnemonic only -- see its comment
  // in creation.html for why #master-mnemonic itself is never hidden/
  // covered, only shown/hidden AFTER this explicit user action. Skipped
  // while the field is on loan to the Load card (see setCreationLoadMode):
  // this wrap's eye-toggle/overlay stay behind in the Create-mode slot,
  // not the moved <input>.
  if (toggle.dataset.for === "master-mnemonic") {
    const display = query("#master-mnemonic-display");
    const homeSlot = query("#master-mnemonic-wrap");
    if (display && field.parentElement === homeSlot) {
      if (revealed) {
        display.classList.add("hidden");
        field.classList.remove("passphrase-field-covered");
      } else {
        display.value = field.value;
        display.classList.remove("hidden");
        field.classList.add("passphrase-field-covered");
      }
    }
  }
});

// Clicking anywhere in the field's wrap copies it -- the eye toggle and the
// copy button itself keep their own direct behavior (unmask / copy), so only
// forward clicks that land elsewhere in the wrap (the input, its padding).
// The copy button is hidden while #master-mnemonic is in "load" mode (typing
// an existing phrase in), so this is a no-op there and the field just
// focuses/positions the cursor as normal.
document.addEventListener("click", event => {
  const wrap = event.target.closest(".recovery-field-wrap");
  if (!wrap) return;
  if (event.target.closest(".recovery-eye-toggle, .recovery-copy")) return;
  const copyBtn = wrap.querySelector(".recovery-copy");
  if (!copyBtn || copyBtn.classList.contains("hidden")) return;
  copyBtn.click();
});

// Clicking anywhere on the home passphrase block copies the phrase.
// (Load-card passphrase lives elsewhere — only this block id fires.)
document.addEventListener("click", (event) => {
  const block = event.target.closest("#creation-passphrase-row");
  if (!block) return;
  if (event.target.closest(".recovery-copy, .passphrase-copy-btn")) return;
  const field = block.querySelector("#master-mnemonic");
  if (!field || !field.value) return;
  const copyBtn = block.querySelector(".recovery-copy[data-for='master-mnemonic'], .passphrase-copy-btn");
  if (!copyBtn || copyBtn.classList.contains("hidden")) return;
  copyBtn.click();
});

document.addEventListener("click", event => {
  const copy = event.target.closest(".recovery-copy");
  if (!copy) return;
  const field = query(`#${copy.dataset.for}`);
  if (!field || !field.value) return;
  navigator.clipboard.writeText(field.value)
    .then(() => {
      copy.classList.add("copied");
      const hint = query(`#${copy.dataset.for}-copy-hint`);
      const feedback = query(`#${copy.dataset.for}-copy-feedback`);
      hint?.classList.add("hidden");
      feedback?.classList.remove("hidden");
      setTimeout(() => {
        copy.classList.remove("copied");
        feedback?.classList.add("hidden");
      }, 1500);
    })
    .catch(() => {});
});

document.addEventListener("click", event => {
  const copy = event.target.closest("#identity-did-copy");
  if (!copy || !copy.dataset.did) return;
  navigator.clipboard.writeText(copy.dataset.did)
    .then(() => {
      copy.classList.add("copied");
      setTimeout(() => copy.classList.remove("copied"), 1500);
      output("#loaded-identity-message", "Did:webvh copied to clipboard.");
    })
    .catch(() => {});
});

// Already running from a downloaded copy: nothing to download (see
// .header-download in styles.css).
if (location.protocol === "file:") document.documentElement.classList.add("local-file");

query("#footer-top").addEventListener("click", () => {
  window.scrollTo({ top: 0, behavior: "smooth" });
});

// Copy onion address to clipboard (the "Copied" bubble is CSS, keyed off
// .copied)
document.addEventListener("click", event => {
  const onionBtn = event.target.closest(".footer-onion-link");
  if (!onionBtn) return;
  const address = onionBtn.dataset.onionAddress;
  if (!address) return;
  const fullUrl = `http://${address}`;
  navigator.clipboard.writeText(fullUrl)
    .then(() => {
      onionBtn.classList.add("copied");
      setTimeout(() => onionBtn.classList.remove("copied"), 1500);
    })
    .catch(() => {});
});

// Drives --header-progress (0..1) off window.scrollY every animation frame
// instead of toggling a single .scrolled class at a scrollY>0 threshold --
// that boolean snapped the header/logo/subtitle to their end state in one
// jump on the first pixel of scroll, which read as janky rather than
// following the scroll position. rAF-throttled so a burst of scroll events
// between frames only computes the style once.
const siteHeader = query("#site-header");
const HEADER_SCROLL_RANGE = 120;
let headerScrollFrame = 0;
function applyHeaderScrollProgress() {
  headerScrollFrame = 0;
  const progress = Math.max(0, Math.min(1, window.scrollY / HEADER_SCROLL_RANGE));
  siteHeader.style.setProperty("--header-progress", progress.toFixed(4));
  siteHeader.classList.toggle("scrolled", progress >= 1);
}
function updateSiteHeaderScrolled() {
  if (headerScrollFrame) return;
  headerScrollFrame = requestAnimationFrame(applyHeaderScrollProgress);
}
window.addEventListener("scroll", updateSiteHeaderScrolled, { passive: true });
applyHeaderScrollProgress();

for (const eventName of ["pointerdown", "keydown", "touchstart"]) document.addEventListener(eventName, armAutoLock, { passive: true });
restorePendingAuthorizeSearch();
// Deliberately deferred one tick (rather than run inline here): this scrubs
// the username/password a just-submitted Create/Load form left in the URL
// after a real, password-manager-visible navigation (see the comment on
// #create-load-form's submit listener) -- calling history.replaceState()
// synchronously during the very first script tick of the new page load
// appears to read to at least one extension (Proton Pass) as "this was
// already the current page, not a fresh navigation," and made it defer its
// own save-prompt bubble until some later, unrelated reload instead of
// showing it right after Create. Letting the page's initial load settle
// first, then scrubbing, still removes the secret from the address bar well
// before the user would notice it, without confusing that detection.
if (location.search && location.pathname !== "/authorize") {
  setTimeout(() => history.replaceState(null, "", location.pathname + location.hash), 0);
}
renderRoute();
window.addEventListener("popstate", renderRoute);
if (location.protocol === "file:") window.addEventListener("hashchange", renderRoute);
// beginOAuthAuthorization must know whether a stored identity exists before it
// decides the person has none, so it waits for this read (see identityRestored).
identityRestored = restoreStoredIdentityRecord();
void renderLoadedIdentity();
void beginOAuthAuthorization();

async function beginCreateDraft() {
  if (draftBeingCreated) return;
  draftBeingCreated = true;
  try {
    const material = await createIdentityMaterial();
    // The Passphrase is the only secret shown to the user; it also
    // protects the local copy kept in this browser, instead of a second,
    // separately invented password. Nothing is saved to the browser yet --
    // that happens explicitly when "Load portable identity" is clicked.
    draft = { password: material.masterMnemonic, material };
    const entry = await provisionalGenesisEntry();
    showDraftPhrase();
    renderDidWithScid(query("#create-identity-did"), entry.state.id);
    // Proton Pass (applications/pass-extension/src/app/content/services/form/
    // form.tracker.ts) only stages a save candidate on submit if
    // state.interactionAt was set, which only happens via its own 'input'
    // listener on the field (field.tracker.ts) -- a plain .value= assignment
    // never fires that event, so without this dispatch the extension's
    // FormTracker never saw this field as "interacted with" and silently
    // skipped it on submit, independent of anything about the field being
    // programmatically filled or offscreen.
    query("#create-username").value = entry.state.id;
    query("#create-username").dispatchEvent(new Event("input", { bubbles: true }));
    resetCreationAlias();
    if (requestedAliasFromUrl) setCreationAliasEnabled(true);
  } catch (error) {
    output("#create-result", errorMessage(error), true);
  } finally {
    draftBeingCreated = false;
  }
}

// Discards the current draft (and, in case Create already persisted it, any
// provisional record already written to this browser) and generates a
// completely fresh SCID/mnemonic pair in its place. The wiped draft's key
// material can't be un-wiped, so there's no way to go back to exactly the
// same identity -- "start over" is the only safe meaning for the reload icon.
async function resetCreateDraft() {
  // Restart the spin even if it's already mid-run (e.g. the button is
  // clicked again before the previous spin finished) -- same reflow-then-
  // reclass trick as the command bar's shake animation above. .reload-icon
  // is an <svg>, not an HTMLElement, so it has no .offsetWidth to read (that
  // read is a no-op on SVG in most browsers) -- getBoundingClientRect() is
  // the one reflow-forcing read that works on both. Without a real forced
  // reflow, the remove+add ran back-to-back in the same tick and the browser
  // coalesced them into "class was already there", so only the very first
  // click (going from no class to the class) ever animated.
  const icon = query("#create-regenerate .reload-icon");
  if (icon) {
    icon.classList.remove("spin-once");
    void icon.getBoundingClientRect();
    icon.classList.add("spin-once");
  }
  const aliasEnabled = query("#creation-alias-toggle").getAttribute("aria-checked") === "true";
  const alias = query("#creation-alias").value;
  if (draft) wipeCreateMaterial(draft.material);
  draft = null;
  await clearBrowserIdentityState();
  storedIdentityRecord = null;
  setCreationConfirmStep(false);
  await beginCreateDraft();
  if (aliasEnabled) {
    query("#creation-alias").value = alias;
    setCreationAliasEnabled(true);
  }
}

onClick("#create-regenerate", "#create-result", resetCreateDraft);

// EXPERIMENT (2026-09-14, temporary): testing whether skipping the "Saved
// the passphrase? [Yes]" confirm step below and navigating straight to the
// dashboard still gets a password manager (Proton Pass) to offer saving the
// Passphrase. Flip back to false to restore the Yes-step behavior -- none
// of that code is removed, just unreached while this is true.
const EXPERIMENTAL_SKIP_CREATION_CONFIRM = false;

// Create (a plain, always-clickable button -- see its own click listener
// below) does the actual persisting; once that succeeds this swaps it out
// for a "Saved the passphrase? [Yes]" confirmation, whose Yes button is the
// one real type="submit" control left in the form (see the submit listener
// further down for why that matters for password managers).
let creationConfirmActive = false;

function setCreationConfirmStep(active) {
  creationConfirmActive = active;
  query("#creation-create-actions").classList.toggle("hidden", active);
  query("#creation-confirm-actions").classList.toggle("hidden", !active);
  // Dim everything except the Passphrase field and this confirm pill itself
  // (including the header), the same way a floating card dims the page
  // behind it.
  document.body.classList.toggle("creation-confirm-dim", active);
}

let loadGlassCloseTimer = null;

function setCreationLoadMode(enabled) {
  const card = query("#load-glass-card");
  const scrim = query("#load-glass-scrim");
  const field = query("#master-mnemonic");
  const homeSlot = query("#master-mnemonic-wrap");
  const cardSlot = query("#passphrase-slot-load");

  query("#create-load-form").classList.toggle("creation-load-mode", enabled);
  query("#header-load-toggle").classList.toggle("active", enabled);
  query("#header-load-toggle").setAttribute("aria-pressed", String(enabled));

  if (enabled) {
    // Keep last known phrase so returning from Load can restore it
    const current = query("#master-mnemonic")?.value;
    if (current) lastCreatePhrase = current;
    if (scrim) {
      scrim.classList.remove("hidden");
      requestAnimationFrame(() => scrim.classList.add("is-open"));
    }
    if (card) {
      card.classList.remove("hidden");
      requestAnimationFrame(() => card.classList.add("is-open"));
    }
    if (field && cardSlot && field.parentElement !== cardSlot) {
      cardSlot.append(field);
      field.style.height = "";
      field.placeholder = "Passphrase";
    }
    query("#master-mnemonic")?.classList.remove("hidden");
    query("#creation-load-actions")?.classList.remove("hidden");
    query("#creation-load-source").value = "";
    query("#master-mnemonic").value = "";
    resetCreationLoadUrlStatus();
    updateCreationLoadSubmit();
    window.setTimeout(() => query("#creation-load-source")?.focus(), 50);
    return;
  }

  if (loadGlassCloseTimer) clearTimeout(loadGlassCloseTimer);
  if (scrim) scrim.classList.remove("is-open");
  if (card) {
    card.classList.remove("is-open");
    loadGlassCloseTimer = window.setTimeout(() => {
      if (!card.classList.contains("is-open")) card.classList.add("hidden");
      if (scrim && !scrim.classList.contains("is-open")) scrim.classList.add("hidden");
    }, 350);
  }

  restoreHomePassphrase();
  query("#creation-load-source").value = "";
  query("#creation-load-file").value = "";
  resetCreationLoadUrlStatus();
  updateCreationLoadSubmit();
}

query("#load-glass-close")?.addEventListener("click", () => {
  setCreationLoadMode(false);
});

query("#load-glass-scrim")?.addEventListener("click", () => {
  setCreationLoadMode(false);
});

query("#load-file-select")?.addEventListener("click", () => {
  query("#creation-load-file")?.click();
});

function randomAlias() {
  const bytes = crypto.getRandomValues(new Uint8Array(2));
  return `${[...bytes].map(byte => byte.toString(16).padStart(2, "0")).join("")}.did.md`;
}

function selectedCreationAliasHost() {
  const value = query("#creation-alias").value.trim().toLowerCase();
  const host = value.endsWith(".did.md") ? value : `${value}.did.md`;
  const parsed = splitHostedTarget(host);
  if (!parsed || parsed.domain !== DOMAIN || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(parsed.username)) {
    throw new Error("Enter a valid did.md Alias.");
  }
  return host;
}

function updateCreationDidSuffix() {
  const element = query("#create-identity-did");
  const suffix = element.querySelector(".did-suffix");
  if (!suffix) return;
  const aliasEnabled = query("#creation-alias-toggle").getAttribute("aria-checked") === "true";
  const alias = query("#creation-alias").value.trim().toLowerCase();
  const host = aliasEnabled
    ? (alias.endsWith(".did.md") ? alias : `${alias}.did.md`)
    : element.dataset.defaultSuffix;
  suffix.textContent = `:${host ?? ""}`;
  suffix.classList.toggle("alias-active", aliasEnabled);
}

function setCreationAliasEnabled(enabled) {
  query("#creation-alias-row").classList.toggle("alias-disabled", !enabled);
  query("#creation-alias-toggle").setAttribute("aria-checked", String(enabled));
  updateCreationDidSuffix();
  if (enabled) checkCreationAlias();
  else resetCreationAliasStatus();
}

function resetCreationAlias() {
  query("#creation-alias").value = randomAlias();
  setCreationAliasEnabled(false);
}

function resetCreationAliasStatus() {
  if (creationAliasTimer) clearTimeout(creationAliasTimer);
  creationAliasTimer = null;
  creationAliasController?.abort();
  creationAliasController = null;
  setAliasStatusIcon(query("#creation-alias-status"), "idle");
}

function checkCreationAlias() {
  resetCreationAliasStatus();
  if (query("#creation-alias-toggle").getAttribute("aria-checked") !== "true") return;
  const value = query("#creation-alias").value.trim().toLowerCase();
  const username = value.endsWith(".did.md") ? value.slice(0, -7) : value;
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(username)) return;

  const status = query("#creation-alias-status");
  setAliasStatusIcon(status, "checking", "Checking alias availability");
  creationAliasTimer = setTimeout(async () => {
    const controller = new AbortController();
    creationAliasController = controller;
    try {
      // The did:webvh Hosting Protocol's own availability rule (SPEC §6): a
      // location is free iff its did.jsonl is a 404 -- no did.md-only
      // /v1/availability endpoint (and no API server) needed.
      const probe = await new WebvhHostingClient().probe(`${username}.${DOMAIN}`, { capabilities: false });
      if (controller.signal.aborted) return;
      if (probe.available === undefined) throw new Error("Availability unknown");
      setAliasStatusIcon(status, probe.available ? "available" : "unavailable", probe.available ? "Alias available" : "Alias unavailable");
    } catch (error) {
      if (error?.name === "AbortError") return;
      setAliasStatusIcon(status, "checking", "Alias availability unknown");
    } finally {
      if (creationAliasController === controller) creationAliasController = null;
    }
  }, 350);
}

query("#creation-alias-toggle").addEventListener("click", () => {
  const enabled = query("#creation-alias-toggle").getAttribute("aria-checked") !== "true";
  setCreationAliasEnabled(enabled);
});

query("#creation-alias").addEventListener("input", () => {
  updateCreationDidSuffix();
  checkCreationAlias();
});

function updateCreationLoadSubmit() {
  const hasSource = Boolean(query("#creation-load-source").value.trim());
  const hasRecoveryPhrase = Boolean(query("#master-mnemonic").value.trim());
  query("#creation-load-submit").disabled = !(hasSource && hasRecoveryPhrase);
}

function resetCreationLoadUrlStatus() {
  if (creationLoadUrlTimer) clearTimeout(creationLoadUrlTimer);
  creationLoadUrlTimer = null;
  creationLoadUrlController?.abort();
  creationLoadUrlController = null;
  query("#load-file-select").classList.remove("hidden");
  const status = query("#creation-load-url-status");
  status.classList.add("hidden");
  status.classList.remove("reachable");
  status.setAttribute("aria-label", "DID document not checked");
}

function creationLoadLogUrl(value) {
  const withScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`;
  const url = new URL(withScheme);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Not a web URL");
  if (url.pathname === "/" || !url.pathname) {
    url.pathname = "/.well-known/did.jsonl";
  } else if (url.pathname.endsWith("/did.json")) {
    url.pathname = `${url.pathname}l`;
  }
  return url;
}

function checkCreationLoadUrl() {
  const value = query("#creation-load-source").value.trim();
  updateCreationLoadSubmit();
  resetCreationLoadUrlStatus();
  if (!value) return;

  query("#load-file-select").classList.add("hidden");
  const status = query("#creation-load-url-status");
  status.classList.remove("hidden");
  status.setAttribute("aria-label", "Checking DID document");

  creationLoadUrlTimer = setTimeout(async () => {
    const controller = new AbortController();
    creationLoadUrlController = controller;
    try {
      const url = creationLoadLogUrl(value);
      const response = await fetch(url, { cache: "no-store", signal: controller.signal });
      if (!response.ok) throw new Error(`DID document returned ${response.status}`);
      const entries = parseLog(await response.text());
      if (!entries.at(-1)?.state?.id?.startsWith("did:webvh:")) throw new Error("Not a did:webvh log");
      status.classList.add("reachable");
      status.setAttribute("aria-label", "DID document reachable");
    } catch (error) {
      if (error?.name === "AbortError") return;
      status.classList.remove("reachable");
      status.setAttribute("aria-label", "DID document unavailable");
    } finally {
      if (creationLoadUrlController === controller) creationLoadUrlController = null;
    }
  }, 400);
}

query("#creation-load-source").addEventListener("input", checkCreationLoadUrl);
query("#master-mnemonic").addEventListener("input", updateCreationLoadSubmit);

// #master-mnemonic is dual-purpose: in "load" mode the user types/pastes
// their own existing Passphrase here, but in "create" mode it holds a
// freshly generated one that must never be hand-edited. `readonly` would be
// the obvious way to block that, but Proton Pass's own content script (see
// packages/pass/utils/dom/form.ts's BUSY_ATTRIBUTES, which includes
// `readonly` alongside `disabled`/`aria-disabled`/`aria-busy`) treats any
// field carrying it as "form busy" and skips the idle reconciliation that
// triggers its save prompt (form.tracker.ts's observeIdle) -- so the block
// has to happen at the JS level instead, exactly like #publish-create above.
for (const eventName of ["beforeinput", "paste", "drop"]) {
  query("#master-mnemonic").addEventListener(eventName, (event) => {
    if (!query("#create-load-form").classList.contains("creation-load-mode")) event.preventDefault();
  });
}

// Same rationale as #master-mnemonic just above, applied to #creation-alias:
// a real `disabled` attribute here (its previous implementation) marks the
// *whole* form "busy" per Proton Pass's BUSY_ATTRIBUTES check, not just this
// field -- which is exactly how the Passphrase field managed to stay hidden
// from its idle-reconciliation save prompt while the Alias toggle defaulted
// off, and exactly what broke (an immediate, unwanted save-prompt right on
// page load) once the toggle got enabled -- even programmatically, via
// requestedAliasFromUrl, before the user ever touched Create (found live,
// 2026-09-14). Block edits at the JS level instead, so no field in this
// form ever carries a busy attribute regardless of the toggle's state.
for (const eventName of ["beforeinput", "paste", "drop"]) {
  query("#creation-alias").addEventListener(eventName, event => {
    if (query("#creation-alias-toggle").getAttribute("aria-checked") !== "true") event.preventDefault();
  });
}

// The beforeinput/paste/drop guards above only cover a human directly
// editing the field -- a password manager's autofill sets .value straight
// through the native setter (that's what makes it usable at all) and only
// then dispatches "input", never "beforeinput", so it walks right past
// them. This is the backstop: in "create" mode the field may only ever
// hold draft.material.masterMnemonic, so any input event that leaves it
// holding something else (autofill included) gets reverted on the spot.
for (const eventName of ["input", "change"]) {
  query("#master-mnemonic").addEventListener(eventName, () => {
    if (query("#create-load-form").classList.contains("creation-load-mode")) return;
    const field = query("#master-mnemonic");
    const canonical = draft?.material?.masterMnemonic ?? "";
    if (field.value !== canonical) field.value = canonical;
  });
}

// In "create" mode there is nothing to click into the field FOR -- editing
// is already blocked above, and the click-to-copy handler below covers the
// one thing a click on it should do -- so a mouse click is never allowed to
// actually focus it. preventDefault on mousedown (not click) is what
// suppresses the browser's default click-to-focus; the click event itself
// still fires afterward, so copy keeps working. This is also what stops a
// password manager's autofill suggestion from popping up on click in the
// first place, rather than just reverting it after the fact.
query("#master-mnemonic").addEventListener("mousedown", (event) => {
  if (!query("#create-load-form").classList.contains("creation-load-mode")) event.preventDefault();
});

query("#creation-load-file").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  query("#creation-load-source").value = file ? `file://${file.name}` : "";
  resetCreationLoadUrlStatus();
  updateCreationLoadSubmit();
});

// "Create" is a real type="submit" button inside a real <form>: only an
// actual click on it reads as trusted enough for a password manager to offer
// saving the mnemonic (a JS-driven requestSubmit() does not). So it stays
// disabled -- dim -- while the checkbox below does the async work of
// persisting the identity, and is only enabled once that work has finished;
// the click itself then does nothing but trigger the native submit/reload.
// Create does the actual persisting -- genesis entry, optional Alias
// publish, and the local IndexedDB write -- as a plain button click (never a
// type="submit"), so none of that async work ever sits between a click and
// a form submit. Only #creation-confirm-saved below is a real submit button:
// see its own comment for why that split exists.
query("#publish-create").addEventListener("click", async () => {
  if (!draft) return;
  const button = query("#publish-create");
  button.disabled = true;
  try {
    const currentDraft = draft;
    const entry = await provisionalGenesisEntry();
    let entries = [entry];
    if (query("#creation-alias-toggle").getAttribute("aria-checked") === "true") {
      if (query("#creation-alias-status").dataset.state !== "available") {
        throw new Error("Choose an available Alias before creating this identity.");
      }
      const targetHost = selectedCreationAliasHost();
      const target = splitHostedTarget(targetHost);
      const move = await preparePortableImport({
        entries,
        username: target.username,
        domain: target.domain,
        masterSeed: currentDraft.material.masterSeed,
      });
      entries = [...entries, move.entry];
      const body = `${entries.map(item => JSON.stringify(item)).join("\n")}\n`;
      await publish(`https://${targetHost}/.well-known/did.jsonl`, "PUT", body);
    }
    const finalEntry = entries.at(-1);
    const persisted = await replaceBrowserIdentityWithProvisional(entries, currentDraft.material.masterSeed, { password: currentDraft.password });
    draft = null;
    wipeCreateMaterial(currentDraft.material);
    if (persisted) {
      // Fire-and-forget: a password-manager extension hooking this API can
      // leave its promise hanging indefinitely, and that must never block
      // the confirm step from appearing.
      void offerToSaveLocalPassword(finalEntry.state.id, currentDraft.password);
      if (EXPERIMENTAL_SKIP_CREATION_CONFIRM) {
        // restoreStoredIdentityRecord() alone (an earlier fix here) gets the
        // dashboard rendering, but leaves the identity locked -- the same as
        // reloading normally would, since neither path sets `loaded`. The
        // user just saw this exact Passphrase on screen; asking them to
        // retype it immediately to unlock is pointless here. currentDraft.password
        // is still the plain mnemonic string (wipeCreateMaterial above only
        // zeroes the Uint8Array key material in currentDraft.material, not
        // this), so unlock with it directly -- unlockIdentity ends in
        // activateLoadedIdentity(), which covers renderSync/renderAsync/
        // armAutoLock/rememberPasskeyWalletSession too, making the standalone
        // restoreStoredIdentityRecord() call above redundant.
        await unlockIdentity(await storageKeyForDid(finalEntry.state.id), currentDraft.password);
        // Skipping the Yes step means #master-mnemonic (a real type=password
        // field, paired with #create-username) never gets the real, trusted
        // form submission that used to happen moments after Create -- it
        // just sits there holding the live Passphrase indefinitely. That is
        // exactly the "password field held a value" condition the
        // beforeunload/pagehide blanking further down exists to catch, and
        // that guard only fires AT unload -- it does nothing about a
        // password-manager extension's own idle-DOM heuristic (Proton
        // Pass's observeIdle) queuing a save candidate from this field WHILE
        // the page sits open and unloaded, well before any navigation. That
        // queued candidate then surfaces as an unrelated-looking save prompt
        // on some later, unconnected page load -- e.g. the /authorize
        // redirect during a subsequent Wallet approval (found live,
        // 2026-09-14). offerToSaveLocalPassword's real navigator.credentials
        // API call above is the intended way to offer saving this Passphrase
        // now; there is no reason to leave a second, uncontrolled copy
        // sitting in a live password field afterward.
        const mnemonicField = query("#master-mnemonic");
        if (mnemonicField) mnemonicField.value = "";
        const usernameField = query("#create-username");
        if (usernameField) usernameField.value = "";
      } else {
        setCreationConfirmStep(true);
      }
    } else {
      await restoreStoredIdentityRecord();
      output("#create-result", "Store the single 24-word Passphrase. It could not be saved locally automatically; see the message below.");
    }
  } catch (error) {
    output("#create-result", errorMessage(error), true);
  } finally {
    button.disabled = false;
  }
});

// A password-manager extension that hooks a password-bearing form's submit
// can call preventDefault() on it once it has done its own work (to inject
// a save prompt, an autofill menu, etc.), silently swallowing the native
// navigation this flow relies on. The browser resolves defaultPrevented
// synchronously once every submit listener has run, so checking it from a
// macrotask queued here reliably tells us whether that happened; if so,
// finish the job ourselves instead of leaving the user stuck on this screen.
let createFormSubmitting = false;

query("#create-load-form").addEventListener("submit", event => {
  // #creation-confirm-saved only exists to let a real, untouched-by-JS click
  // reach the browser as a trusted form submission -- that's what makes
  // Chrome/Safari/Proton Pass etc. offer to save the Passphrase. It's
  // never given `disabled`/`aria-disabled`/`readonly` for the same reason
  // #publish-create above never was (see BUSY_ATTRIBUTES in Proton Pass's
  // own content-script source, packages/pass/utils/dom/form.ts) -- so this
  // guard, not an attribute, is what stops a stray Enter keypress in some
  // other field from submitting before the confirm step is actually showing.
  if (!creationConfirmActive) {
    event.preventDefault();
    return;
  }
  // A native GET is kept so password managers observe a real completed form
  // -- POST was tried instead (with Caddy rewriting the method back to GET
  // server-side, since file_server 405s anything else) on the theory that
  // Chrome's own save-password heuristic prefers POST, but a working-vs-not
  // comparison against an older, known-good build (2026-09-13) showed GET is
  // what actually got Proton Pass/Safari Keychain to fire; reverted. Its
  // named identity/password controls must not replace a pending /authorize
  // request's own query string -- stash it so boot can restore it after this
  // reload (see stashPendingAuthorizeSearch/restorePendingAuthorizeSearch).
  stashPendingAuthorizeSearch();
  createFormSubmitting = true;
  setTimeout(() => {
    if (event.defaultPrevented) location.href = location.pathname + location.hash;
  }, 0);
});

// A fresh, never-submitted Passphrase sits in #master-mnemonic as soon
// as a draft is generated (Unload immediately starts a new one -- see
// maybeBeginCreateDraft). If the page is then closed or reloaded without the
// user ever clicking Create, some password managers treat "a password field
// held a value when the page unloaded" as a submission signal on its own and
// stage it as a save candidate -- surfacing this made-up phrase as a login
// prompt later, once some other page load finally has no matching form to
// defer against (see the investigation this fixes). Blank the field on any
// unload that isn't the real Create submit, so there is nothing left for
// that heuristic to pick up.
for (const eventName of ["beforeunload", "pagehide"]) {
  window.addEventListener(eventName, () => {
    if (createFormSubmitting) return;
    // Only clear a field that is actually in the live document.
    const field = Document.prototype.querySelector.call(document, "#master-mnemonic");
    if (field) field.value = "";
  });
}

async function provisionalGenesisEntry() {
  if (!draft) throw new Error("Create a Passphrase first.");
  if (!draft.entry) {
    draft.entry = await buildGenesis({
      username: "ex", root: draft.material.root, sign: draft.material.sign,
      nextSpare: draft.material.nextSpare, domain: "alias", api: API,
    });
  }
  return draft.entry;
}

async function submitOAuthAuthorizationApproval() {
  const button = query("#wallet-authorize-approve");
  button.disabled = true;
  // Loading state: the label becomes ・ → ・・ → ・・・, looping, until the approval ends.
  const label = button.textContent;
  const frames = ["・", "・・", "・・・"];
  let frame = 0;
  button.classList.add("is-loading");
  button.setAttribute("aria-busy", "true");
  button.setAttribute("aria-label", "Approving");
  button.textContent = frames[0];
  const timer = setInterval(() => { frame = (frame + 1) % frames.length; button.textContent = frames[frame]; }, 350);
  try {
    await approveAuthorization();
  } catch (error) {
    output("#loaded-identity-message", errorMessage(error), true);
    button.disabled = false;
    clearInterval(timer);
    button.classList.remove("is-loading");
    button.removeAttribute("aria-busy");
    button.removeAttribute("aria-label");
    button.textContent = label;
  }
}

query("#wallet-authorize-approve").addEventListener("click", async () => {
  await withUnlock(submitOAuthAuthorizationApproval);
});

query("#wallet-authorize-cancel").addEventListener("click", () => {
  applicationActionAfterUnlock = null;
  rejectOAuthAuthorization();
});

query("#wallet-authorize-edit-device").addEventListener("click", event => {
  event.stopPropagation();
  setAuthorizeNameEditing(query("#wallet-authorize-device-label").classList.contains("hidden"));
});
// Keep focus in the input when the pencil is pressed, so the click closes the editor
// (instead of blur closing it and the click reopening it).
query("#wallet-authorize-edit-device").addEventListener("mousedown", event => event.preventDefault());
{
  const input = query("#wallet-authorize-device-label");
  let before = "";
  input.addEventListener("focus", () => { before = input.value; });
  input.addEventListener("keydown", event => {
    if (event.key === "Enter") { event.preventDefault(); setAuthorizeNameEditing(false); }
    else if (event.key === "Escape") { event.stopPropagation(); input.value = before; setAuthorizeNameEditing(false); }
  });
  input.addEventListener("blur", () => setAuthorizeNameEditing(false));
}


// The card is a fixed bottom sheet, not part of normal document flow, so it
// can cover page content (the Create button, the Alias toggle, ...) with no
// way to scroll that content into view above it -- the page's own scroll
// height never accounted for the card sitting on top. Keep a CSS variable
// in sync with the card's actual current height (0 while hidden, and
// whatever it is right now while expanded/collapsed/editing a device
// label, all of which resize it) so body's padding-bottom can reserve
// exactly that much extra scroll room, no more.
{
  const authorizePanel = query("#wallet-authorize-panel");
  const syncAuthorizeCardHeight = () => {
    const height = authorizePanel.classList.contains("hidden") ? 0 : authorizePanel.offsetHeight;
    document.documentElement.style.setProperty("--wallet-authorize-card-height", `${height}px`);
  };
  new ResizeObserver(syncAuthorizeCardHeight).observe(authorizePanel);
  syncAuthorizeCardHeight();
}

function serviceDirectoryFor(serviceId) {
  for (const application of portableApplications) {
    const directory = application.services?.find(candidate => candidate.id === serviceId);
    if (directory) return { application, directory };
  }
  return undefined;
}

function serviceReferencesFor(serviceId) {
  return portableApplications.flatMap(application => (application.services ?? [])
    .filter(service => service.id === serviceId).map(service => ({ application, service })));
}

function withoutVerificationKeys(state, removedKeyIds) {
  const removed = new Set(removedKeyIds);
  const methods = Array.isArray(state.verificationMethod) ? state.verificationMethod : [];
  const next = { ...state, verificationMethod: methods.filter(method => !removed.has(method.id)) };
  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    if (Array.isArray(state[relationship])) next[relationship] = state[relationship].filter(id => !removed.has(id));
  }
  return next;
}

function renderServicesList() {
  const list = query("#services-list");
  list.replaceChildren();
  const visibleState = loaded?.entries?.at(-1)?.state ?? publicApplicationState;
  const services = Array.isArray(visibleState?.service) ? visibleState.service : [];
  if (!services.length) return;
  for (const service of services) {
    const row = document.createElement("div");
    row.className = "record-card service-card";
    const heading = document.createElement("div");
    heading.className = "record-card-heading";
    const title = document.createElement("h4");
    const serviceType = typeof service.type === "string" ? service.type : "unknown";
    const endpoint = typeof service.serviceEndpoint === "string" ? service.serviceEndpoint : JSON.stringify(service.serviceEndpoint);
    const applicationName = serviceType === "DIDCommMessaging" ? "DIDComm Mediator"
      : serviceType === "BisetMimiVaultRoom" ? "MIMI Vault"
        : serviceType;
    const references = serviceReferencesFor(service.id);
    const association = references[0] ?? serviceDirectoryFor(service.id);
    const owner = association?.application ?? portableApplications.find(application => application.serviceIds.includes(service.id));
    title.textContent = service.id?.split("#").at(-1) ?? applicationName;
    const details = document.createElement("dl");
    details.className = "service-facts";
    for (const [label, value] of [["Type", serviceType], ["Endpoint", endpoint]]) {
      const dt = document.createElement("dt"); dt.textContent = label;
      const dd = document.createElement("dd"); dd.textContent = value;
      details.append(dt, dd);
    }
    const remove = document.createElement("span");
    remove.className = "identity-name-copy";
    remove.setAttribute("role", "button");
    remove.tabIndex = 0;
    remove.setAttribute("aria-label", `Remove ${applicationName} service`);
    remove.append(trashIcon());
    onClick(remove, "#services-result", async () => {
      const prepareRemoval = async () => {
        const current = loaded.entries.at(-1).state;
        const currentServices = Array.isArray(current.service) ? current.service : [];
        const state = { ...current, service: currentServices.filter(other => other.id !== service.id) };
        try {
          await preparePublication(state, "update");
          await publishPreparedEntry();
        } catch (error) {
          discardPending();
          throw error;
        }
        output("#services-result", `Removed ${applicationName}. Referenced keys remain in the DID Document.`);
      };
      await withUnlock(prepareRemoval);
    });
    const ownedKeyIds = [...new Set(references.flatMap(reference => reference.service.keyIds))];
    const methods = Array.isArray(visibleState.verificationMethod) ? visibleState.verificationMethod : [];
    const ownedMethods = ownedKeyIds.map(id => methods.find(method => method.id === id)).filter(Boolean);
    const metadata = encryptedMetadataPanel([
      ["Added by", owner?.clientName ?? "Unknown"],
      ["Used by devices", references.length ? [...new Set(references.map(reference => reference.application.deviceJkt))].join("\n") : loaded ? "No device references" : "Unlock to view"],
      ["Uses keys", ownedMethods.length ? ownedMethods.map(method => method.id).join("\n") : loaded ? "No key references" : "Unlock to view"],
    ]);
    heading.append(title, remove);
    row.append(heading, details, metadata);
    list.append(row);
  }
}

const VERIFICATION_RELATIONSHIPS = ["authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"];

function renderApplicationKeysList() {
  const manager = query("#application-keys-manager");
  const list = query("#application-keys-list");
  list.replaceChildren();
  const state = loaded?.entries?.at(-1)?.state ?? publicApplicationState;
  const allMethods = Array.isArray(state?.verificationMethod) ? state.verificationMethod : [];
  // Authentication methods (e.g. the Root key, pass-1) are shown on the Keys
  // tab, so they are left out here rather than listed twice.
  const authentication = Array.isArray(state?.authentication) ? state.authentication : [];
  const methods = allMethods.filter(method => !authentication.includes(method.id));
  // The selected tab, not data availability, controls whether this pane is
  // visible; an empty list simply renders nothing.
  manager.classList.toggle("hidden", currentApplicationTab !== "docs");
  for (const method of methods) {
    const relationships = VERIFICATION_RELATIONSHIPS.filter(name => Array.isArray(state[name]) && state[name].includes(method.id));
    const owner = portableApplications.find(application => application.keyIds.includes(method.id));
    const keyReferences = portableApplications.flatMap(application => (application.services ?? [])
      .filter(service => service.keyIds.includes(method.id)).map(service => ({ application, service })));
    const usedBy = [...new Set(keyReferences.map(reference => reference.service.id))];
    const usedByDevices = [...new Set(keyReferences.map(reference => reference.application.deviceJkt))];
    const isRoot = relationships.includes("authentication") || (loaded && method.publicKeyMultibase === loaded.root.multikey);
    const row = document.createElement("div");
    row.className = "record-card application-key-card";
    const title = document.createElement("h4");
    title.textContent = method.id?.split("#").at(-1) ?? "(unnamed key)";
    const details = document.createElement("dl");
    details.className = "fields";
    for (const [label, value] of [["Type", method.type ?? "unknown"], ["Relationship", relationships.join(", ") || "verificationMethod only"]]) {
      const dt = document.createElement("dt"); dt.textContent = label;
      const dd = document.createElement("dd"); dd.textContent = value;
      details.append(dt, dd);
    }
    // Same heading-row trash icon as a service card.
    const remove = document.createElement("span");
    remove.className = "identity-name-copy";
    remove.setAttribute("role", "button");
    remove.tabIndex = 0;
    remove.setAttribute("aria-label", `Remove key ${title.textContent}`);
    remove.append(trashIcon());
    if (!isRoot) onClick(remove, "#services-result", async () => {
      const prepareRemoval = async () => {
        if (usedBy.length && !confirm(`This key is referenced by:\n\n${usedBy.join("\n")}\n\nRemove the key anyway? The services will remain in the DID Document.`)) return;
        const current = loaded.entries.at(-1).state;
        const next = withoutVerificationKeys(current, [method.id]);
        try {
          await preparePublication(next, "update");
          await publishPreparedEntry();
        } catch (error) {
          discardPending();
          throw error;
        }
        output("#services-result", `Removed ${method.id}.`);
      };
      await withUnlock(prepareRemoval);
    });
    // Root methods are not application-owned, but they belong in the same
    // directory and need the same provenance/reference surface as every
    // other verification method.
    const metadata = encryptedMetadataPanel(loaded
      ? isRoot
        ? [
          ["Added by", "did.md Wallet (identity creation)"],
          ["Key source", "Passphrase · m/0' Root derivation"],
          ["Used by services", usedBy.length ? usedBy.join("\n") : "No service references"],
          ["Used by devices", usedByDevices.length ? usedByDevices.join("\n") : "No device references"],
        ]
        : [
          ["Added by", owner?.clientName ?? "Unknown"],
          ["Used by services", usedBy.length ? usedBy.join("\n") : "No service references"],
          ["Used by devices", usedByDevices.length ? usedByDevices.join("\n") : owner?.deviceJkt ?? "No device references"],
        ]
      : [["Application metadata", "Unlock this identity to view application and device references."]]);
    const heading = document.createElement("div");
    heading.className = "record-card-heading";
    heading.append(title);
    if (!isRoot) heading.append(remove);
    row.append(heading, details);
    row.append(metadata);
    list.append(row);
  }
}


// Every caller (Rotate key, Docs' service/key removal) runs prepare and
// publish back to back as one atomic action -- there is exactly one
// legitimate next entry for a given DID Document state, so there was never
// a real multi-step review to have; each caller reports its own result
// once publishPreparedEntry() below actually succeeds.
async function preparePublication(state, kind) {
  if (!loaded) throw new Error("Load an identity first.");
  if (state.id !== loaded.entries.at(-1).state.id) throw new Error("This UI publishes at the current did.md location; state.id cannot be changed here.");
  if (!rootIsPublished(state, loaded.root.multikey)) throw new Error("The Root Key verification method must remain in the DID Document.");

  const prepared = await preparePreRotatedUpdate({
    entries: loaded.entries,
    state,
    masterSeed: loaded.masterSeed,
    currentSpareIndex: loaded.currentSpareIndex,
  });
  pending = { ...prepared, state, kind };
}

// The single entry point for any action that needs the Master seed decrypted
// in memory. If already unlocked, runs `action` immediately. If locked, opens
// the mnemonic prompt and defers `action` until unlock succeeds -- nothing
// about the current view (selection state, visible tab, menus...) is touched
// beforehand, so the UI doesn't flash into a half-switched state before the
// password prompt appears.
async function withUnlock(action) {
  if (loaded) { await action(); return; }
  applicationActionAfterUnlock = action;
  openLockUnlockForm();
}

// While locked, #lock-toggle no longer opens a dedicated field of its own --
// it hands off to the Context Window's command line, in "unlock" context (see
// setCommandMode), the same "input mode" surface the menu/default view's
// command line uses. While unlocked, #lock-toggle re-locks directly instead.
function openLockUnlockForm() {
  setCommandMode(true, "unlock");
}

// Only closes the UI -- does NOT touch applicationActionAfterUnlock. This is
// also called as a plain visibility-sync side effect (updateLockToggleVisibility,
// on every successful unlock and whenever there's no identity to represent),
// not just on genuine user cancellation; clearing the pending action here
// used to race the unlock submit handler's own resume -- unlockIdentity's
// internal render chain reached this before the handler could capture
// applicationActionAfterUnlock, silently dropping every deferred action
// (Approve, Connect, ...) and leaving the user to press it again by hand.
// Callers that actually mean to cancel (Escape, or the button while empty)
// clear it themselves.
function closeLockUnlockForm() {
  if (commandModeActive && commandModeContext === "unlock") setCommandMode(false);
  // Only reveal the lock icon again if there's actually an identity for it
  // to represent -- this is also called with no identity loaded at all
  // (updateLockToggleVisibility's !hasIdentity branch), where it must stay
  // hidden rather than popping back into view.
  query("#lock-toggle").classList.toggle("hidden", !(loaded || storedIdentityRecord));
}

query("#lock-toggle").addEventListener("click", () => {
  const button = query("#lock-toggle");
  if (button.dataset.locked === "false") {
    logoutWallet("Locked.", false);
    return;
  }
  openLockUnlockForm();
});

function cancelLockUnlockForm() {
  applicationActionAfterUnlock = null;
  closeLockUnlockForm();
}

async function submitUnlockMnemonic(mnemonic) {
  const submit = query("#context-command-submit");
  submit.disabled = true;
  // Unlocking rebuilds the Identity files card list from scratch (activateLoadedIdentity
  // -> renderIdentityFiles), which resets the selection to the first tab --
  // reselect whatever the user had open, so e.g. clicking keyring.json while
  // locked lands back on keyring.json, now shown directly, instead of did.jsonl.
  const previouslySelectedFile = identityFilesView?.selected;
  try {
    if (!storedIdentityRecord) throw new Error("Create or load an identity first.");
    await unlockIdentity(storedIdentityRecord.username, mnemonic);
    const resumeApplicationAction = applicationActionAfterUnlock;
    applicationActionAfterUnlock = null;
    setCommandMode(false);
    // The Files tab is independent of the Context Window's command mode --
    // unlocking never hides it -- so unlike before, there is no view to
    // restore here; re-clicking the file just re-runs `show()` now that
    // `loaded` is set, refreshing its content in place.
    if (resumeApplicationAction) {
      await resumeApplicationAction();
    } else if (previouslySelectedFile && identityFilesView?.names.includes(previouslySelectedFile)) {
      query(`#identity-file-list [data-file="${CSS.escape(previouslySelectedFile)}"]`)?.click();
    } else {
      output("#loaded-identity-message", "Unlocked.");
    }
  } catch (error) {
    output("#wallet-result", errorMessage(error), true);
  } finally {
    submit.disabled = false;
  }
}

// Rotate key is atomic (prepare + publish in one click) -- pre-rotation's
// commitment scheme only ever has one legitimate next step (this identity's
// one pending Spare key), there's no local multi-step chain to build up
// before publishing, so a review step bought nothing but an extra click.
// Success is shown by #rotate-key turning into "Rotated" (justRotated, via
// updateKeyStatus() inside publishPreparedEntry).
//
// No retry button on failure (prepare's own validation, or a network error
// in publish after the local signing already succeeded) -- whatever partial
// state preparePublication left in `pending` is simply discarded, and
// #key-status itself reports the failure (rotateKeyFailed) the same way it
// reports success, replacing its own message rather than a one-off panel/
// toast the user has to separately notice. Retrying means clicking Rotate
// key again, which redoes the signing fresh rather than resubmitting a
// possibly-stale prepared entry.
//
// Not onClick(): its own finally always resets .disabled to false once the
// handler returns, which would immediately undo justRotated's own
// button.disabled = true right after setting it. updateRotateKeyButton()
// (called from updateKeyStatus() on success, or directly in the finally
// below) is the single source of truth for the button's disabled state
// instead.
query("#rotate-key").addEventListener("click", async () => {
  const button = query("#rotate-key");
  if (button.disabled) return;
  button.disabled = true;
  rotateKeyFailed = false;
  try {
    await withUnlock(async () => {
      if (pending) throw new Error("A DID Document update is already prepared. Publish it before preparing another one.");
      try {
        await preparePublication(JSON.parse(JSON.stringify(loaded.entries.at(-1).state)), "rotation");
        await publishPreparedEntry();
        justRotated = true;
      } catch (error) {
        discardPending();
        rotateKeyFailed = true;
        throw error;
      }
    });
  } catch {
    // Reported via #key-status (see updateKeyStatus/rotateKeyFailed), not
    // #keys-result -- there's no separate panel to point the error at once
    // Rotate key has nothing left to retry.
  } finally {
    updateKeyStatus();
  }
});


async function persistMasterMetadata() {
  const args = {
    username: loaded.username,
    did: loaded.entries.at(-1).state.id,
    rootKey: loaded.root.multikey,
    generation: loaded.entries.at(-1).versionId,
  };
  if (loaded.record?.v === 5) {
    loaded.record = await updatePasswordStoredIdentityMetadata(loaded.record, args);
  } else if (loaded.record?.protection === "passkey" && loaded.passkeyProtector) {
    loaded.record = await saveMasterStoredIdentity({ ...args, masterSeed: loaded.masterSeed, protector: loaded.passkeyProtector, applicationMetadata: loaded.record.applicationMetadata });
  } else if (loaded.record?.protection !== "passkey") {
    loaded.record = await saveMasterStoredIdentity({ ...args, applicationMetadata: loaded.record?.applicationMetadata });
  }
}

// Shared by Rotate key and Docs' service/key removal, both atomic (prepare
// then publish back to back, no separate review/retry button -- see
// preparePublication above). Reports nothing itself; each caller knows
// what it just did and writes its own result once this actually succeeds.
async function publishPreparedEntry() {
  if (!loaded || !pending) throw new Error("Prepare a publication first.");
  const nextEntries = [...loaded.entries, pending.entry];
  const published = await publishEntriesToCurrentHost(
    nextEntries,
    `Publish ${pending.kind ?? "update"} ${pending.entry.versionId}`,
    "append",
    // Full re-entry so the resumed write also runs the local state updates.
    () => publishPreparedEntry(),
  );
  // Credential dialog opened -- leave `pending` in place so the resumed
  // write after the PAT is entered still has the entry to publish.
  if (published !== "published") return;
  loaded.entries = nextEntries;
  loaded.parameters = currentParameters(loaded.entries);
  publicApplicationState = loaded.entries.at(-1).state;
  if (loaded.record?.applicationMetadata) {
    const serviceIds = new Set((Array.isArray(publicApplicationState.service) ? publicApplicationState.service : []).map(service => service.id));
    const keyIds = new Set((Array.isArray(publicApplicationState.verificationMethod) ? publicApplicationState.verificationMethod : []).map(method => method.id));
    portableApplications = portableApplications.map(application => ({
      ...application,
      serviceIds: application.serviceIds.filter(id => serviceIds.has(id)),
      keyIds: application.keyIds.filter(id => keyIds.has(id)),
      services: (application.services ?? []).filter(service => serviceIds.has(service.id)).map(service => ({
        id: service.id, keyIds: service.keyIds.filter(id => keyIds.has(id)),
      })),
    }));
    loaded.record = await savePortableApplications(loaded.record, loaded.masterSeed, portableApplications);
  }
  renderServicesList();
  renderApplicationKeysList();

  loaded.sign = await spareFromMasterSeed(loaded.masterSeed, loaded.currentSpareIndex);
  loaded.currentSpareIndex = pending.nextSpareIndex;
  await persistMasterMetadata();
  // routing.json is a did.md-hosted root resource. GitHub user sites have
  // no equivalent mutable API in this MVP -- skip rather than fail the update.
  if (pending.routingResource && !isGitHubHostedDid(loaded.entries.at(-1).state.id)) {
    await publishRoutingResource(loaded.entries.at(-1).state.id, pending.routingResource);
  }
  await refreshIdentityViews();
  void renderLoadedIdentity();
  discardPending();
  updateKeyStatus();
}

/**
 * One write path for Docs/Keys/routing updates. Picks the adapter via
 * hostForDid; a GitHub write without a PAT stashes `pendingGitHubPublish`
 * and opens the PAT dialog so the user can finish the same update.
 */
async function publishEntriesToCurrentHost(entries, message, mode = "append", resumeAfterCredential) {
  const did = entries.at(-1)?.state?.id;
  if (!did) throw new Error("The DID log has no current DID Document.");
  const host = hostForDid(did);
  try {
    await host.publish({
      entries,
      message,
      // GitHub always rewrites the full log; did.md appends one entry.
      mode: host.kind === "github" ? "replace" : mode,
      credential: currentGitHubPat() ?? undefined,
    });
    if (host.kind === "github") void updateConnectionStatus();
    return "published";
  } catch (error) {
    if (error instanceof CredentialRequiredError) {
      pendingGitHubPublish = resumeAfterCredential ?? null;
      openGitHubHostCard({ intent: "update" });
      return "awaiting-credential";
    }
    if ((error as { status?: number }).status === 401 || /rejected this token/i.test(String((error as Error).message))) {
      clearStoredGitHubPat();
      githubPatInMemory = null;
      pendingGitHubPublish = resumeAfterCredential ?? null;
      openGitHubHostCard({ intent: "update" });
      output("#loaded-identity-message", "Saved GitHub token was rejected. Paste a new one.", true);
      return "awaiting-credential";
    }
    throw error;
  }
}

onClick("#enable-passkey", "#keys-result", async () => {
  if (!loaded) throw new Error("Load an identity first.");
  const protector = await createPasskeyProtector(loaded.username);
  loaded.passkeyProtector = protector;
  loaded.record = await saveMasterStoredIdentity({
    username: loaded.username, did: loaded.entries.at(-1).state.id, rootKey: loaded.root.multikey,
    generation: loaded.entries.at(-1).versionId, masterSeed: loaded.masterSeed, protector,
    applicationMetadata: loaded.record?.applicationMetadata,
  });
  rememberPasskeyWalletSession();
  await refreshIdentityViews();
  updateKeyStatus();
  output("#keys-result", "The Passphrase is now encrypted in this browser with this passkey.");
});

// Masonry for the card grids (Apps, Services, Keys): grid-auto-rows is 1px in CSS, so every
// grid item gets a row span equal to its own height plus the gap. Wrappers with
// display:contents are looked through; any size change (a card unlocking, a window resize)
// re-measures.
function packMasonry(container) {
  const gap = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
  const items = [];
  const collect = parent => {
    for (const child of parent.children) {
      if (getComputedStyle(child).display === "contents") collect(child);
      else if (getComputedStyle(child).display !== "none") items.push(child);
    }
  };
  collect(container);
  for (const item of items) {
    const height = item.getBoundingClientRect().height;
    item.style.gridRowEnd = height ? `span ${Math.ceil(height + gap)}` : "";
  }
  return items;
}

// The pages are rendered by the router after this module runs, so watch the whole body and
// (re)pack whichever grids exist; each item's own size changes are picked up by a ResizeObserver.
{
  const observer = new ResizeObserver(() => scheduleMasonry());
  let scheduled = false;
  function scheduleMasonry() {
    if (scheduled) return;
    scheduled = true;
    setTimeout(() => {
      scheduled = false;
      for (const container of document.querySelectorAll(".key-material-grid, .docs-columns")) {
        for (const item of packMasonry(container)) observer.observe(item);
      }
    }, 0);
  }
  new MutationObserver(scheduleMasonry).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  window.addEventListener("resize", scheduleMasonry);
  scheduleMasonry();
}
