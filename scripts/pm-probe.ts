/**
 * Password-manager probe: ordinary sign-up / log-in pages with nothing of dito in them.
 *
 *   node scripts/pm-probe.ts          # http://localhost:8794
 *
 * First step whenever a password manager (Proton Pass, ...) stops offering to save the
 * Passphrase on dito's create form (ARC.md, "Password-manager autosave"). Type an email and
 * a password into one of these pages and submit:
 *
 *   /signup       POST, the server answers 303 -> /welcome   (the classic flow)
 *   /login        the same, current-password
 *   /post200      POST, the server answers 200 on the same URL
 *   /get          GET to /welcome
 *
 * If /signup does not trigger the manager, the extension (version, settings, profile) is
 * the problem and dito's markup is not worth touching. If it does, bisect dito's own form
 * against the checklist in ARC.md.
 */
import http from "node:http";

const PORT = Number(process.env.PORT ?? 8794);

const page = (title: string, body: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title>
<style>body{font:16px/1.5 system-ui;max-width:360px;margin:48px auto;padding:0 16px}label{display:block;margin:12px 0 4px}input{width:100%;box-sizing:border-box;padding:10px;font-size:16px}button{margin-top:16px;padding:10px 16px;font-size:16px}nav a{margin-right:12px}</style></head>
<body><nav><a href="/signup">/signup</a><a href="/login">/login</a><a href="/post200">/post200</a><a href="/get">/get</a></nav>${body}</body></html>`;

const form = (title: string, method: string, action: string, autocomplete: string) => page(title, `<h1>${title}</h1>
<form method="${method}" action="${action}">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="${autocomplete === "new-password" ? "email" : "username"}" required>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="${autocomplete}" required>
  <button type="submit">Submit</button>
</form>`);

http.createServer((req, res) => {
  const html = (body: string) => res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(body);
  const url = req.url ?? "/";
  if (req.method === "POST") {
    req.resume();
    return void req.on("end", () => {
      if (url === "/post200") return html(page("Posted", "<h1>Posted</h1><p>POST received; answered 200 on the same URL.</p>"));
      res.writeHead(303, { location: "/welcome" }).end();
    });
  }
  if (url.startsWith("/get")) return html(form("GET", "get", "/welcome", "new-password"));
  if (url === "/post200") return html(form("POST, 200 reply", "post", "/post200", "new-password"));
  if (url === "/login") return html(form("Log in", "post", "/login", "current-password"));
  if (url === "/welcome") return html(page("Welcome", "<h1>Welcome</h1><p>Request received, then redirected.</p>"));
  return html(form("Sign up", "post", "/signup", "new-password"));
}).listen(PORT, "127.0.0.1", () => console.log(`pm-probe on http://localhost:${PORT}`));
