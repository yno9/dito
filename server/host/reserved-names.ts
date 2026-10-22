/**
 * Names nobody may register as an identity (`{name}.did.md`).
 *
 * An identity is also a mail address (`name@did.md`, via didmail), and a name that sounds like the service itself is a name
 * to impersonate it with: `postmaster@` and `abuse@` receive what the Internet sends to a mail domain's operators, `support@`
 * and `security@` are what phishing pretends to be, `didmail@` is the mail bridge's own address, and a host name (`mx`, `app`,
 * `api` ...) is served by something else in front of this host anyway. Existing identities are not touched: this only closes the
 * door to new ones (identity-host.ts, `serveLog`, first publish of a log).
 */

const RESERVED = new Set([
  // the service and its parts
  'did', 'did-md', 'didmd', 'didmail', 'dito', 'biset', 'wallet', 'wallet-probe', 'mediator', 'oidc', 'oidc-bridge', 'oauth', 'auth', 'login', 'signin', 'signup', 'account', 'accounts', 'client', 'app', 'api', 'pds', 'relay', 'bridge', 'gateway',
  // hosts a mail domain, a website or a DNS zone has
  'www', 'web', 'mail', 'email', 'webmail', 'mx', 'mx1', 'mx2', 'smtp', 'imap', 'pop', 'pop3', 'ns', 'ns1', 'ns2', 'dns', 'ftp', 'sftp', 'ssh', 'vpn', 'cdn', 'static', 'assets', 'status', 'docs', 'blog', 'home', 'localhost', 'autoconfig', 'autodiscover',
  // the role mailboxes RFC 2142 names, and the usual ones around them
  'postmaster', 'abuse', 'hostmaster', 'webmaster', 'noc', 'security', 'info', 'contact', 'sales', 'billing', 'legal', 'privacy', 'terms', 'press', 'office', 'team', 'help', 'support', 'service', 'services', 'feedback', 'newsletter', 'news', 'marketing', 'jobs', 'careers',
  // those that act for someone else
  'admin', 'administrator', 'root', 'sys', 'system', 'daemon', 'nobody', 'operator', 'staff', 'moderator', 'owner', 'official', 'verified',
  // senders nobody can answer
  'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'mailer-daemon', 'bounce', 'bounces', 'notifications', 'notification', 'alerts', 'robot', 'bot',
])

/** Names added by the operator (comma separated, in `RESERVED_USERNAMES`), without touching the code. */
function extra(): Set<string> {
  const env = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env ?? {}
  return new Set((env.RESERVED_USERNAMES ?? '').split(',').map(name => name.trim().toLowerCase()).filter(Boolean))
}

/** Whether `name` (an identity's username, already a lower-case DNS label) is one that may not be registered. */
export function isReservedName(name: string): boolean {
  // `xn--` is punycode: a label that only looks like another name or script (the sort of thing impersonation uses).
  return RESERVED.has(name) || extra().has(name) || name.startsWith('xn--')
}
