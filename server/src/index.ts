import { fileURLToPath } from "node:url";
import { buildApp } from "./app.js";
import { databaseFromEnv } from "./db.js";

const db = databaseFromEnv();
await db.migrate();
const app = await buildApp(db, {
  bootstrapToken: process.env.BOOTSTRAP_TOKEN || undefined,
  staticDir: process.env.STATIC_DIR ?? fileURLToPath(new URL("../../web/dist", import.meta.url)),
  logger: process.env.LOG_LEVEL !== "silent",
});
const port = Number(process.env.PORT ?? 3000);
await app.listen({ port, host: process.env.HOST ?? "0.0.0.0" });

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, async () => {
    await app.close();
    await db.close();
    process.exit(0);
  });
}
