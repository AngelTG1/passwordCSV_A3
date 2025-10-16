import fs from "fs";
import path from "path";
import { parse } from "csv-parse";
import crypto from "crypto";

// Conjuntos de caracteres (ASCII imprimibles comunes)
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = `!"#$%&'()*+,-./:;<=>?@[\\]^_\`{|}~`; // 32 símbolos visibles + backtick

export type Evaluation = {
  passwordLength: number;        // L
  alphabetSize: number;          // N
  entropyBits: number;           // E = L * log2(N)
  category: "Débil/Aceptable" | "Fuerte" | "Muy Fuerte" | "Comprometida";
  estimatedCrackTime: {
    seconds: number;
    friendly: string;            // "X años Y días Z horas"…
    assumptions: string;         // tasa 1e11 intentos/seg
  };
  notes: string[];
  dictionaryHit: boolean;
};

// ===== Carga del diccionario (solo columna 2) =====
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
        // Se pide limpiar el archivo y usar solo la COLUMNA 2
        // (índice 1 si la 1era es índice/rank)
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

// ===== Cálculos base: L, N, Entropía =====
export function calculate_L(password: string): number {
  return [...password].length; // soporta Unicode
}

export function calculate_N(password: string): number {
  // Suma los tamaños de los grupos presentes en la contraseña
  let n = 0;
  const hasLower = [...password].some((c) => LOWER.includes(c));
  const hasUpper = [...password].some((c) => UPPER.includes(c));
  const hasDigit = [...password].some((c) => DIGITS.includes(c));
  const hasSymbol = [...password].some((c) => SYMBOLS.includes(c));

  if (hasLower) n += LOWER.length; // 26
  if (hasUpper) n += UPPER.length; // 26
  if (hasDigit) n += DIGITS.length; // 10
  if (hasSymbol) n += SYMBOLS.length; // 32

  // Si usa otros Unicode (ej. emojis), amplía el alfabeto de forma conservadora
  const hasOther = [...password].some(
    (c) => !LOWER.includes(c) && !UPPER.includes(c) && !DIGITS.includes(c) && !SYMBOLS.includes(c)
  );
  if (hasOther) n += 100; // aproximación conservadora

  return Math.max(n, 1);
}

export function calculate_entropy(password: string): number {
  const L = calculate_L(password);
  const N = calculate_N(password);
  const entropy = L * Math.log2(N);
  return Number(entropy.toFixed(2));
}

// ===== Estimación de tiempo de crackeo =====
// Ataque asumido: 1e11 intentos/seg (10^11)
const ATTEMPTS_PER_SEC = 1e11;

export function estimateCrackSeconds(password: string): number {
  const L = calculate_L(password);
  const N = calculate_N(password);
  const totalSpace = Math.pow(N, L);
  const expectedTries = totalSpace / 2; // promedio
  const seconds = expectedTries / ATTEMPTS_PER_SEC;
  // Evitar overflow en números enormes
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
      if (parts.length >= 3) break; // no saturar
    }
  }
  return parts.length ? parts.join(" ") : "menos de 1 segundo";
}

// ===== Reglas de fuerza por entropía =====
export function categorizeByEntropy(E: number): "Débil/Aceptable" | "Fuerte" | "Muy Fuerte" {
  if (E < 60) return "Débil/Aceptable";
  if (E < 80) return "Fuerte";
  return "Muy Fuerte";
}

// ===== Heurísticas simples (repeticiones, secuencias) =====
function hasSimplePatterns(pw: string): string[] {
  const notes: string[] = [];
  if (/([a-zA-Z0-9])\1{2,}/.test(pw)) notes.push("Repeticiones de caracteres detectadas.");
  if (/(0123|1234|2345|3456|4567|5678|6789)/.test(pw)) notes.push("Secuencias numéricas comunes.");
  if (/(abcd|qwer|asdf|zxcv)/i.test(pw)) notes.push("Patrones de teclado probables.");
  return notes;
}

// ===== Diccionario =====
function inDictionary(pw: string): boolean {
  if (!DICT) return false;
  const low = pw.toLowerCase();
  if (DICT.has(low)) return true;
  // penaliza si contiene palabra muy común de 6+ chars
  for (const word of DICT) {
    if (word.length >= 6 && low.includes(word)) return true;
  }
  return false;
}

// ===== Evaluación principal =====
export function evaluatePassword(password: string): Evaluation {
  const L = calculate_L(password);
  const N = calculate_N(password);
  const E = calculate_entropy(password);
  const secs = estimateCrackSeconds(password);

  let category: Evaluation["category"] = categorizeByEntropy(E);
  const notes = [...hasSimplePatterns(password)];
  let dictHit = inDictionary(password);
  if (dictHit) {
    category = "Comprometida";
    notes.push("Aparece en diccionario de contraseñas comunes (penalizada).");
  }

  // Bonus/penalizaciones leves
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
    dictionaryHit: dictHit
  };
}

// ===== Utilidad opcional: hash sin revelar =====
export function sha256Hex(str: string): string {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}
