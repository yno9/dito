import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export class BridgeKeys {
  privateKey: ReturnType<typeof createPrivateKey>; publicJwk: JsonWebKey; readonly kid: string;
  constructor(path: string) {
    let pem: string;
    try { pem = readFileSync(path, "utf8"); }
    catch { mkdirSync(dirname(path), { recursive: true }); const pair = generateKeyPairSync("rsa", { modulusLength: 2048 }); pem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(); const temp = `${path}.${process.pid}.tmp`; writeFileSync(temp, pem, { mode: 0o600 }); renameSync(temp, path); }
    this.privateKey = createPrivateKey(pem); this.publicJwk = createPublicKey(this.privateKey).export({ format: "jwk" });
    this.kid = createHash("sha256").update(JSON.stringify({ e: this.publicJwk.e, kty: this.publicJwk.kty, n: this.publicJwk.n })).digest("base64url");
  }
  jwks() { return { keys: [{ ...this.publicJwk, use: "sig", alg: "RS256", kid: this.kid }] }; }
  jwt(payload: Record<string, unknown>) { const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: this.kid })).toString("base64url"); const body = Buffer.from(JSON.stringify(payload)).toString("base64url"); return `${header}.${body}.${sign("RSA-SHA256", Buffer.from(`${header}.${body}`), this.privateKey).toString("base64url")}`; }
}
