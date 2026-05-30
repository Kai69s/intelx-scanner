import express from "express";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocket, WebSocketServer } from "ws";
import { PORT_PRESETS, runScan } from "./scanner.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");
const isProduction = process.env.NODE_ENV === "production" || process.argv.includes("--production");
const port = Number(process.env.PORT || 5173);

const app = express();
const server = http.createServer(app);

app.use(express.json({ limit: "1mb" }));

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    name: "sentinel-network-scanner",
    mode: "live",
    presets: PORT_PRESETS
  });
});

app.post("/api/scan", async (req, res) => {
  const scanId = randomUUID();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);
  const events = [];
  let result = null;

  try {
    await runScan({
      scanId,
      options: req.body,
      signal: controller.signal,
      emit: (event) => {
        events.push(event);
        if (event.type === "scan-complete") {
          result = event.payload;
        }
      }
    });

    res.json({
      ok: true,
      mode: "live",
      events,
      result
    });
  } catch (error) {
    res.status(400).json({
      ok: false,
      mode: "live",
      message: error instanceof Error ? error.message : "Scan failed."
    });
  } finally {
    clearTimeout(timeout);
  }
});

if (isProduction) {
  const distDir = path.join(rootDir, "dist");
  app.use(express.static(distDir));
  app.use(async (req, res, next) => {
    if (req.method !== "GET") {
      next();
      return;
    }
    res.type("html").send(await fs.readFile(path.join(distDir, "index.html"), "utf-8"));
  });
} else {
  const { createServer: createViteServer } = await import("vite");
  const vite = await createViteServer({
    root: rootDir,
    server: {
      middlewareMode: true,
      hmr: false
    },
    appType: "custom"
  });

  app.use(vite.middlewares);
  app.use(async (req, res, next) => {
    if (req.method !== "GET") {
      next();
      return;
    }
    try {
      const url = req.originalUrl;
      const templatePath = path.join(rootDir, "index.html");
      const template = await fs.readFile(templatePath, "utf-8");
      const html = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(html);
    } catch (error) {
      vite.ssrFixStacktrace(error);
      next(error);
    }
  });
}

const wss = new WebSocketServer({ server, path: "/ws" });
const activeScans = new Map();

function send(socket, message) {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message));
  }
}

wss.on("connection", (socket) => {
  const socketScans = new Map();

  send(socket, {
    type: "hello",
    payload: {
      presets: PORT_PRESETS,
      serverTime: new Date().toISOString()
    }
  });

  socket.on("message", (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      send(socket, { type: "scan-error", payload: { message: "Invalid message payload." } });
      return;
    }

    if (message.type === "start-scan") {
      const controller = new AbortController();
      const scanId = randomUUID();
      activeScans.set(scanId, controller);
      socketScans.set(scanId, controller);

      runScan({
        scanId,
        options: message.payload,
        signal: controller.signal,
        emit: (event) => send(socket, event)
      })
        .catch((error) => {
          send(socket, {
            type: "scan-error",
            payload: {
              scanId,
              message: error instanceof Error ? error.message : "Scan failed."
            }
          });
        })
        .finally(() => {
          activeScans.delete(scanId);
          socketScans.delete(scanId);
        });
      return;
    }

    if (message.type === "cancel-scan") {
      const scanId = message.payload?.scanId;
      const controller = scanId ? socketScans.get(scanId) : undefined;
      if (controller) {
        controller.abort();
        send(socket, { type: "scan-log", payload: { scanId, level: "warn", text: "Scan cancelled." } });
      }
    }
  });

  socket.on("close", () => {
    for (const controller of socketScans.values()) {
      controller.abort();
    }
  });
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Sentinel Network Scanner listening on http://127.0.0.1:${port}`);
});
