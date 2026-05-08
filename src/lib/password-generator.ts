import crypto from "crypto";

interface GenerateParams {
  length: number;
  minUpper: number;
  minLower: number;
  minNumbers: number;
  minSymbols: number;
  includeUpper: boolean;
  includeLower: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
}

const CHARSETS = {
  uppercase: "ABCDEFGHIJKLMNPQRSTUVWXYZ", // Excluding O
  lowercase: "abcdefghijklmnopqrstuvwxyz", // Excluding l
  numbers: "23456789", // Excluding 0 and 1
  symbols: "!@#$%^&*+-=",
};

/**
 * Creates a cryptographically-secure deterministic random byte generator from
 * a 32-byte hex-encoded seed.
 *
 * The seed is used as an AES-256 key; an AES-256-CTR keystream (zero IV,
 * deterministic for a given seed) is used to expand the seed into as many
 * random bytes as callers need.  This replaces the previous implementation
 * which cycled through the raw seed bytes sequentially — a non-expansion that
 * exposed the seed material directly and introduced severe modulo bias.
 */
function createRandomGenerator(seed: string) {
  // Ensure the seed is exactly 32 bytes (64 hex chars); pad or truncate safely.
  const keyHex = seed.padEnd(64, "0").slice(0, 64);
  const key = Buffer.from(keyHex, "hex");
  // Fixed zero IV is safe here because each seed is unique per CTRNG request.
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);

  let pool = Buffer.alloc(0);
  let poolOffset = 0;

  function ensurePool(need: number): void {
    const available = pool.length - poolOffset;
    if (available < need) {
      // Encrypt 1024 zero bytes to extend the keystream pool.
      const chunk = cipher.update(Buffer.alloc(1024, 0));
      pool = Buffer.concat([pool.slice(poolOffset), chunk]);
      poolOffset = 0;
    }
  }

  return (length: number): Uint8Array => {
    ensurePool(length);
    const result = new Uint8Array(pool.slice(poolOffset, poolOffset + length));
    poolOffset += length;
    return result;
  };
}

/**
 * Generates a password from a seed with the specified parameters
 */
export function generatePasswordFromSeed(
  seed: string,
  params: GenerateParams
): string {
  const randomValues = createRandomGenerator(seed);

  const {
    length,
    minUpper,
    minLower,
    minNumbers,
    minSymbols,
    includeUpper,
    includeLower,
    includeNumbers,
    includeSymbols,
  } = params;

  // Build available character sets based on user selection
  const availableCharsets: { [key: string]: string } = {};
  if (includeUpper) availableCharsets.uppercase = CHARSETS.uppercase;
  if (includeLower) availableCharsets.lowercase = CHARSETS.lowercase;
  if (includeNumbers) availableCharsets.numbers = CHARSETS.numbers;
  if (includeSymbols) availableCharsets.symbols = CHARSETS.symbols;

  // Ensure at least one character type is selected
  if (Object.keys(availableCharsets).length === 0) {
    throw new Error("At least one character type must be selected");
  }

  // Validate that minimum requirements don't exceed available character types
  if (minUpper > 0 && !includeUpper) {
    throw new Error(
      "Uppercase minimum requirement specified but uppercase not included"
    );
  }
  if (minLower > 0 && !includeLower) {
    throw new Error(
      "Lowercase minimum requirement specified but lowercase not included"
    );
  }
  if (minNumbers > 0 && !includeNumbers) {
    throw new Error(
      "Numbers minimum requirement specified but numbers not included"
    );
  }
  if (minSymbols > 0 && !includeSymbols) {
    throw new Error(
      "Symbols minimum requirement specified but symbols not included"
    );
  }

  // Calculate total minimum requirements ONLY for selected character types
  const totalMin =
    (includeUpper ? minUpper : 0) +
    (includeLower ? minLower : 0) +
    (includeNumbers ? minNumbers : 0) +
    (includeSymbols ? minSymbols : 0);

  if (totalMin > length) {
    throw new Error("Minimum requirements exceed password length");
  }

  /**
   * Unbiased index selection using rejection sampling.
   * The original `randomByte % charsetLen` produced modulo bias when 256 is
   * not a multiple of charsetLen.  This draws fresh bytes until the value
   * falls within a range that divides evenly.
   */
  function unbiasedIndex(charsetLen: number): number {
    const limit = 256 - (256 % charsetLen);
    while (true) {
      const byte = randomValues(1)[0];
      if (byte < limit) return byte % charsetLen;
    }
  }

  let password = "";
  const remainingLength = length - totalMin;

  // Add minimum required characters
  for (let i = 0; i < minUpper; i++) {
    password += availableCharsets.uppercase[unbiasedIndex(availableCharsets.uppercase.length)];
  }
  for (let i = 0; i < minLower; i++) {
    password += availableCharsets.lowercase[unbiasedIndex(availableCharsets.lowercase.length)];
  }
  for (let i = 0; i < minNumbers; i++) {
    password += availableCharsets.numbers[unbiasedIndex(availableCharsets.numbers.length)];
  }
  for (let i = 0; i < minSymbols; i++) {
    password += availableCharsets.symbols[unbiasedIndex(availableCharsets.symbols.length)];
  }

  // Fill remaining length with random characters from all available sets
  const allAvailableChars = Object.values(availableCharsets).join("");
  for (let i = 0; i < remainingLength; i++) {
    password += allAvailableChars[unbiasedIndex(allAvailableChars.length)];
  }

  // Fisher-Yates shuffle using unbiased index selection
  const passwordArray = password.split("");
  for (let i = passwordArray.length - 1; i > 0; i--) {
    const j = unbiasedIndex(i + 1);
    [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
  }

  return passwordArray.join("");
}
