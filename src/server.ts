import express from "express";
import cors from "cors";
import { scanDomain } from "./scan";

const app = express();
app.use(express.json());
app.use(cors({ origin: "*", methods: ["GET"] }));

const API_KEY = process.env.SCANNER_API_KEY || "";
const PORT = Number(process.env.PORT || 8080);

app.get("/health", (_req, res) => res.json({ ok: true }));

app.use((req, res, next) => {
  const key = req.header("x-scanner-key") || "";
  if (!API_KEY || key !== API_KEY) return res.status(401).json({ error: "unauthorized" });
  next();
});

app.get("/scan", async (req, res) => {
  try {
    const domain = String(req.query.domain || "");
    const timeout = Number(req.query.timeout || 8000);
    const result = await scanDomain(domain, timeout);
    res.json(result);
  } catch (e: any) {
    res.status(502).json({ error: e?.message || "scan failed" });
  }
});

app.listen(PORT, () => console.log(`scanner listening on :${PORT}`));
