import express from "express";
import helmet from "helmet";
import passwordRoutes from "./routes/password.route.js";
import { loadDictionaryOnce } from "./services/password.service.js";
import swaggerUi from "swagger-ui-express";
import fs from "fs";
import path from "path";

const app = express();

// Seguridad básica
app.use(helmet());
app.disable("x-powered-by");

// Parseo seguro
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

// Cargar diccionario (no bloquea si no existe)
loadDictionaryOnce().catch((e) => console.error("Error cargando diccionario:", e));

// Rutas
app.use(passwordRoutes);

// Swagger/OpenAPI
const openapiPath = path.resolve(process.cwd(), "src", "docs", "openapi.yaml");
if (fs.existsSync(openapiPath)) {
  const yaml = fs.readFileSync(openapiPath, "utf8");
  // swagger-ui-express acepta objetos; aquí una carga rápida:
  // Para simplificar en tiempo real, reusamos swagger-ui con YAML vía paquete si quisieras.
  // Pero podemos servir el YAML como estático y/o convertir a JSON si prefieres.
  // Para no complicar, lo montamos en /docs con una mínima UI:
  import("yaml").then(({ parse }) => {
    const spec = parse(yaml);
    app.use("/docs", swaggerUi.serve, swaggerUi.setup(spec));
    console.log("📄 Swagger UI en /docs");
  });
} else {
  console.warn("⚠️ No se encontró src/docs/openapi.yaml; sin Swagger UI.");
}

// Manejador de errores sin filtrar inputs
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("❌ Error:", err?.message);
  return res.status(500).json({ ok: false, error: "Error interno" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 API escuchando en http://localhost:${PORT}`);
});
