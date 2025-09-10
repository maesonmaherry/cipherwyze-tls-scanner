import express from "express";
import cors from "cors";
import { scanTls } from "./scan.js";

const app = express();
app.use(express.json());
app.use(cors({ origin: "*", methods: ["GET"] }));

const API_KEY = process.env.SCANNER_API_KEY || "";
const PORT = Number(process.env.PORT || 8080);

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// simple API key guard
app.use((req, res, next) => {
  const key = req.header("x-scanner-key") || "";
  if (!API_KEY || key !== API_KEY) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
});

app.get("/scan", async (req, res) => {
  const domain = String(req.query.domain || "");
  const timeout = Number(req.query.timeout || 8000);
  try {
    const result = await scanTls(domain, timeout);
    res.json(result);
  } catch (e: any) {
    const status = e.status || 502;
    res.status(status).json({ error: e.message || "scan failed" });
  }
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`scanner listening on :${PORT}`);
});
