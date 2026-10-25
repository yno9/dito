/** base58btc (Bitcoin alphabet), the multibase `z` encoding: SCIDs, hashes, proof values and multikeys. */
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58btc(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let number = 0n;
  for (const byte of bytes) number = number * 256n + BigInt(byte);
  let result = "";
  while (number > 0n) {
    result = ALPHABET[Number(number % 58n)] + result;
    number /= 58n;
  }
  return "1".repeat(zeros) + result;
}

export function decodeBase58btc(text: string): Uint8Array {
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") zeros++;
  let number = 0n;
  for (const character of text.slice(zeros)) {
    const value = ALPHABET.indexOf(character);
    if (value === -1) throw new Error(`Invalid base58 character: ${character}`);
    number = number * 58n + BigInt(value);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number % 256n));
    number /= 256n;
  }
  return new Uint8Array([...new Array<number>(zeros).fill(0), ...bytes]);
}

/** Multibase base58btc: `z` + base58. */
export const multibaseBase58 = (bytes: Uint8Array): string => `z${base58btc(bytes)}`;

export function decodeMultibaseBase58(text: string): Uint8Array {
  if (!text.startsWith("z")) throw new Error("Not a base58btc multibase value.");
  return decodeBase58btc(text.slice(1));
}
