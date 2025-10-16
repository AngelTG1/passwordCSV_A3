import { Router } from "express";
import { evaluatePasswordHandler } from "../controllers/password.controller.js";
import { z } from "zod";

const router = Router();

const bodySchema = z.object({
  password: z.string().min(1, "password requerido").max(4096, "muy larga")
});

router.post("/api/v1/password/evaluate", (req, res, next) => {
  const parse = bodySchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ ok: false, error: parse.error.flatten() });
  return evaluatePasswordHandler(req, res).catch(next);
});

export default router;
