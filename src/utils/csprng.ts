/**
 * Principios CSPRNG (resumen):
 * - Debe ser impredecible incluso con conocimiento parcial del estado.
 * - Debe resistir ataques de predicción hacia atrás/adelante.
 * - Debe sembrarse desde fuentes de alta entropía del sistema.
 * En Node.js, 'crypto.randomBytes' y 'crypto.randomInt' usan el CSPRNG del SO.
 */

import crypto from "crypto";

// Ejemplo: generar una contraseña segura con CSPRNG
export function generateSecurePassword(length = 20): string {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
                  `!"#$%&'()*+,-./:;<=>?@[\\]^_\`{|}~`;
  const chars = [...charset];
  let out = "";
  for (let i = 0; i < length; i++) {
    const idx = crypto.randomInt(0, chars.length);
    out += chars[idx];
  }
  return out;
}
