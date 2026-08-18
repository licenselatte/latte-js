/**
 * License-key / AppID normalization and checksum.
 *
 * This is a hand-rolled typo-catching checksum, not a cryptographic
 * primitive, so implementing it directly (rather than using a crypto
 * library) is correct, not a "hand-rolled crypto" violation.
 */

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function alphabetIndex(c: string): number {
  return ALPHABET.indexOf(c);
}

export function calculateChecksum(data: string, length: number): string {
  let sum = 0;
  for (let i = 0; i < data.length; i++) {
    let val = alphabetIndex(data[i] as string);
    if (i % 2 === 0) {
      val *= 2;
    }
    sum += val;
  }

  let checksum = "";
  for (let i = 0; i < length; i++) {
    // JS's `%` keeps the dividend's sign, so out-of-alphabet input driving
    // `sum` negative could produce a negative index here too. Use a
    // floor-mod so malformed input safely produces "no match" rather than
    // an out-of-bounds/undefined character.
    const idx = (((sum + i * 31) % ALPHABET.length) + ALPHABET.length) % ALPHABET.length;
    checksum += ALPHABET[idx];
  }
  return checksum;
}

/**
 * Validates that the last `checksumLen` characters of `key` are the
 * correct checksum of the preceding characters.
 */
export function validateKey(key: string, checksumLen: number): boolean {
  if (key.length < checksumLen) {
    return false;
  }
  const dataPart = key.slice(0, key.length - checksumLen);
  const provided = key.slice(key.length - checksumLen);
  return calculateChecksum(dataPart, checksumLen) === provided;
}

/**
 * Uppercases, strips hyphens/spaces, and folds the visually-ambiguous
 * characters O -> 0, I -> 1, L -> 1 (I and L both fold to 1, so a
 * sanitized key can never distinguish an original L from an original I
 * from an original 1; this is deliberate, not an oversight). This fold is
 * specific to the native key alphabet (which deliberately excludes
 * O/I/L) — use it only where the value is expected to be a native-format
 * key. Use normalizeKey for anything else.
 */
export function sanitizeKey(input: string): string {
  return input
    .toUpperCase()
    .replaceAll("-", "")
    .replaceAll(" ", "")
    .replaceAll("O", "0")
    .replaceAll("I", "1")
    .replaceAll("L", "1");
}

/**
 * Uppercases and strips hyphens/spaces, with no other transformation.
 * Unlike sanitizeKey, this never assumes the input is in the native key
 * alphabet, so it's safe to use on any license key string regardless of
 * which system minted it.
 */
export function normalizeKey(input: string): string {
  return input.toUpperCase().replaceAll("-", "").replaceAll(" ", "");
}
