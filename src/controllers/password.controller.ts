import { Request, Response } from "express";
import { evaluatePassword } from "../services/password.service.js";

export async function evaluatePasswordHandler(req: Request, res: Response) {
  // NUNCA registres contraseñas en logs.
  const { password } = req.body as { password?: string };

  // Respuesta determinística y sin persistencia
  const result = evaluatePassword(password!);

  return res.status(200).json({
    ok: true,
    data: result
  });
}
