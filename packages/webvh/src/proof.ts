/**
 * Data Integrity proofs (`eddsa-jcs-2022`) over arbitrary JSON documents:
 * routing/disconnect requests, wallet grants, and log entries alike. The
 * canonicalization and hashing are didwebvh-ts's (`prepareDataForSigning`), so
 * these proofs are byte-compatible with the ones inside a did:webvh log.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { MultibaseEncoding, multibaseDecode, multibaseEncode, prepareDataForSigning } from "didwebvh-ts";
import { multikeyFromPublicKey } from "./signer.ts";

export type Proof = {
  type: string; cryptosuite: string; proofPurpose: string; verificationMethod: string; proofValue: string; created?: string;
};

function templateFor(args: { verificationMethod: string; proofPurpose: string; created?: string }) {
  return {
    type: "DataIntegrityProof" as const,
    cryptosuite: "eddsa-jcs-2022" as const,
    proofPurpose: args.proofPurpose,
    verificationMethod: args.verificationMethod,
    ...(args.created ? { created: args.created } : {}),
  };
}

/** Sign `document` with a raw 32-byte Ed25519 private key. */
export async function createDataIntegrityProof(document: object, args: {
  privateKey: Uint8Array; verificationMethod: string; proofPurpose: string; created?: string;
}): Promise<Proof> {
  if (args.privateKey.length !== 32) throw new Error("An Ed25519 private key must be 32 bytes.");
  if (!args.verificationMethod || !args.proofPurpose) throw new Error("A verification method and proof purpose are required.");
  const template = templateFor(args);
  const data = await prepareDataForSigning(document, template as never);
  const proofValue = multibaseEncode(ed25519.sign(data, args.privateKey), MultibaseEncoding.BASE58_BTC);
  return { ...template, proofValue };
}

/**
 * Signature check only: `proof` over `document` by the raw Ed25519
 * `publicKey`. Which key may sign, and how the proof names it, is the
 * caller's policy (see verifyDataIntegrityProof for the did:webvh log rule).
 */
export async function verifyProofSignature(document: object, proof: Proof, publicKey: Uint8Array): Promise<boolean> {
  if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "eddsa-jcs-2022" || typeof proof.proofValue !== "string" || !proof.proofValue.startsWith("z")) return false;
  try {
    const { bytes: signature } = multibaseDecode(proof.proofValue);
    if (signature.length !== 64) return false;
    const { proofValue: _omitted, ...config } = proof;
    return ed25519.verify(signature, await prepareDataForSigning(document, config as never), publicKey);
  } catch { return false; }
}

const DID_KEY = /^did:key:(z[1-9A-HJ-NP-Za-km-z]+)#(z[1-9A-HJ-NP-Za-km-z]+)$/;

/** Raw Ed25519 public key of a multikey (`z6Mk…`), or undefined if it is not one. */
export function publicKeyFromMultikey(multikey: string): Uint8Array | undefined {
  try {
    const { bytes } = multibaseDecode(multikey);
    if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) return undefined;
    const key = bytes.slice(2);
    return multikeyFromPublicKey(key) === multikey ? key : undefined;
  } catch { return undefined; }
}

/**
 * True when `proof` is a valid Data Integrity proof over `document` made by
 * one of `permitted` (Ed25519 multikeys), referenced as `did:key:<k>#<k>`.
 */
export async function verifyDataIntegrityProof(
  document: object, proof: Proof, permitted: string[], proofPurpose = "assertionMethod",
): Promise<boolean> {
  if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "eddsa-jcs-2022" || proof.proofPurpose !== proofPurpose) return false;
  const match = DID_KEY.exec(proof.verificationMethod);
  if (!match || match[1] !== match[2] || !permitted.includes(match[1]!)) return false;
  const publicKey = publicKeyFromMultikey(match[1]!);
  return !!publicKey && verifyProofSignature(document, proof, publicKey);
}
