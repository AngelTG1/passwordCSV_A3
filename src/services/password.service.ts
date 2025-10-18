import fs from "fs";
import path from "path";
import { parse } from "csv-parse";
import crypto from "crypto";

// Conjuntos de caracteres
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = `!"#$%&'()*+,-./:;<=>?@[\\]^_\`{|}~`;

export type Evaluation = {
  passwordLength: number;        // L
  alphabetSize: number;          // N
  entropyBits: number;           // E = L * log2(N)
  category: "Débil/Aceptable" | "Fuerte" | "Muy Fuerte" | "Comprometida";
  estimatedCrackTime: {
    seconds: number;
    friendly: string;            // Ejemplo: "2 años 45 días 3 horas"
    assumptions: string;         // "Tasa 1e11 intentos/seg"
  };
  notes: string[];
  dictionaryHit: boolean;
  dictionaryMatchType: "none" | "parcial" | "exacta"; // ✅ Nuevo campo agregado
};

// ===== Carga del diccionario =====
let DICT: Set<string> | null = null;

export async function loadDictionaryOnce(): Promise<void> {
  if (DICT) return;
  DICT = new Set<string>();

  const csvPath = path.resolve(process.cwd(), "wordlists", "1millionPasswords.csv");
  if (!fs.existsSync(csvPath)) {
    console.warn("⚠️ No se encontró wordlists/1millionPasswords.csv. Continuando sin diccionario.");
    return;
  }

  await new Promise<void>((resolve, reject) => {
    const stream = fs.createReadStream(csvPath, { encoding: "utf8" });
    const parser = parse({ relax_column_count: true, trim: true });

    parser.on("readable", () => {
      let record;
      while ((record = parser.read()) !== null) {
        const val = (record[1] ?? record[0] ?? "").toString().trim();
        if (val) DICT!.add(val.toLowerCase());
      }
    });
    parser.on("error", reject);
    parser.on("end", () => resolve());
    stream.pipe(parser);
  });

  console.log(`📚 Diccionario cargado (${DICT.size.toLocaleString()} entradas).`);
}

// ===== Cálculos base =====
export function calculate_L(password: string): number {
  return [...password].length;
}

export function calculate_N(password: string): number {
  let n = 0;
  const hasLower = [...password].some((c) => LOWER.includes(c));
  const hasUpper = [...password].some((c) => UPPER.includes(c));
  const hasDigit = [...password].some((c) => DIGITS.includes(c));
  const hasSymbol = [...password].some((c) => SYMBOLS.includes(c));

  if (hasLower) n += LOWER.length;
  if (hasUpper) n += UPPER.length;
  if (hasDigit) n += DIGITS.length;
  if (hasSymbol) n += SYMBOLS.length;

  const hasOther = [...password].some(
    (c) => !LOWER.includes(c) && !UPPER.includes(c) && !DIGITS.includes(c) && !SYMBOLS.includes(c)
  );
  if (hasOther) n += 100;

  return Math.max(n, 1);
}

export function calculate_entropy(password: string): number {
  const L = calculate_L(password);
  const N = calculate_N(password);
  const entropy = L * Math.log2(N);
  return Number(entropy.toFixed(2));
}

// ===== Estimación de crackeo =====
const ATTEMPTS_PER_SEC = 1e11;

export function estimateCrackSeconds(password: string): number {
  const L = calculate_L(password);
  const N = calculate_N(password);
  const totalSpace = Math.pow(N, L);
  const expectedTries = totalSpace / 2;
  const seconds = expectedTries / ATTEMPTS_PER_SEC;
  if (!Number.isFinite(seconds)) return Number.POSITIVE_INFINITY;
  return seconds;
}

export function friendlyDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return "muchísimos años (≈ infinito con supuestos actuales)";
  const units = [
    { s: 365 * 24 * 3600, name: "años" },
    { s: 24 * 3600, name: "días" },
    { s: 3600, name: "horas" },
    { s: 60, name: "minutos" },
    { s: 1, name: "segundos" },
  ];
  let rem = Math.max(0, Math.floor(seconds));
  const parts: string[] = [];
  for (const u of units) {
    if (rem >= u.s) {
      const v = Math.floor(rem / u.s);
      rem = rem % u.s;
      parts.push(`${v} ${u.name}`);
      if (parts.length >= 3) break;
    }
  }
  return parts.length ? parts.join(" ") : "menos de 1 segundo";
}

// ===== Reglas de entropía =====
export function categorizeByEntropy(E: number): "Débil/Aceptable" | "Fuerte" | "Muy Fuerte" {
  if (E < 60) return "Débil/Aceptable";
  if (E < 80) return "Fuerte";
  return "Muy Fuerte";
}

// ===== Heurísticas =====
function hasSimplePatterns(pw: string): string[] {
  const notes: string[] = [];
  if (/([a-zA-Z0-9])\1{2,}/.test(pw)) notes.push("Repeticiones de caracteres detectadas.");
  if (/(0123|1234|2345|3456|4567|5678|6789)/.test(pw)) notes.push("Secuencias numéricas comunes.");
  if (/(abcd|qwer|asdf|zxcv)/i.test(pw)) notes.push("Patrones de teclado probables.");
  return notes;
}

// ===== Diccionario: exactaa o parcial =====
type DictMatch = { type: "none" } | { type: "exacta"; word: string } | { type: "parcial"; word: string };

function checkDictionary(pw: string): DictMatch {
  if (!DICT) return { type: "none" };
  const low = pw.toLowerCase();

  // exactaa
  if (DICT.has(low)) return { type: "exacta", word: low };

  // Parcial (mínimo 4 caracteres)
  const MIN_parcial = 4;
  if (low.length < MIN_parcial) return { type: "none" };

  for (const word of DICT) {
    if (word.length < MIN_parcial) continue;
    if (word.includes(low)) return { type: "parcial", word };
    if (low.includes(word)) return { type: "parcial", word };
  }

  return { type: "none" };
}

// ===== Evaluación principal =====
export function evaluatePassword(password: string): Evaluation {
  const L = calculate_L(password);
  const N = calculate_N(password);
  const E = calculate_entropy(password);
  const secs = estimateCrackSeconds(password);

  let category: Evaluation["category"] = categorizeByEntropy(E);
  const notes = [...hasSimplePatterns(password)];

  const dictCheck = checkDictionary(password);
  let dictHit = false;
  let dictType: "none" | "parcial" | "exacta" = dictCheck.type;

  if (dictCheck.type === "exacta") {
    dictHit = true;
    category = "Comprometida";
    notes.push(`Aparece exactaamente en el diccionario de contraseñas comunes: "${dictCheck.word}" (penalizada).`);
  } else if (dictCheck.type === "parcial") {
    notes.push(
      `Coincidencia parcial con palabra común: "${dictCheck.word}". ` +
      `La contraseña contiene o está contenida por una palabra común (posible variante).`
    );
  }

  if (L < 12) notes.push("Longitud recomendada: 12+ caracteres.");
  if (N < 36) notes.push("Usa mayúsculas, minúsculas, números y símbolos para mayor N.");

  return {
    passwordLength: L,
    alphabetSize: N,
    entropyBits: E,
    category,
    estimatedCrackTime: {
      seconds: Number.isFinite(secs) ? Number(secs.toFixed(2)) : secs,
      friendly: friendlyDuration(secs),
      assumptions: "Tasa de ataque asumida: 10^11 intentos/segundo (offline)."
    },
    notes,
    dictionaryHit: dictHit,
    dictionaryMatchType: dictType // ✅ visible en la respuesta
  };
}

// ===== Hash opcional =====
export function sha256Hex(str: string): string {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}
