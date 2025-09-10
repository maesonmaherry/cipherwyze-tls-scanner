import tls from "tls";
import dns from "dns/promises";
import { X509Certificate } from "crypto";
import type { TlsScanResult } from "./types.js";

const isAsciiHostname = (host: string) =>
  /^[A-Za-z0-9.-]{1,255}$/.test(host) &&
  !/^\d{1,3}(\.\d{1,3}){3}$/.test(host) && // no IPv4
  !/^[0-9a-f:]+$/i.test(host); // no IPv6

export async function scanTls(domain: string, timeoutMs = 8000): Promise<TlsScanResult> {
  if (!isAsciiHostname(domain)) {
    throw Object.assign(new Error("Invalid domain"), { status: 400 });
  }

  const addrs = await dns.lookup(domain, { all: true }).catch((e) => {
    const err = new Error(`DNS lookup failed: ${e.message}`);
    (err as any).status = 502;
    throw err;
  });

  // Prefer IPv4 first to reduce IPv6 edge issues; then IPv6
  const sorted = [
    ...addrs.filter((a) => a.family === 4),
    ...addrs.filter((a) => a.family === 6),
  ];
  if (sorted.length === 0) {
    throw Object.assign(new Error("No A/AAAA records"), { status: 502 });
  }

  const resolvedIPs = sorted.map((a) => a.address);
  const scannedAt = new Date().toISOString();

  // Try addresses in order until one succeeds
  let lastErr: any;
  for (const ip of resolvedIPs) {
    try {
      const result = await connectOnce(domain, ip, timeoutMs);
      return { ...result, resolvedIPs, scannedAt };
    } catch (e: any) {
      lastErr = e;
      continue;
    }
  }
  const err = new Error(lastErr?.message || "TLS connect failed");
  (err as any).status = lastErr?.status || 502;
  throw err;
}

async function connectOnce(domain: string, ip: string, timeoutMs: number) {
  return new Promise<TlsScanResult>((resolve, reject) => {
    const socket = tls.connect({
      host: ip,
      port: 443,
      servername: domain, // SNI
      ALPNProtocols: ["h2", "http/1.1"]
    });

    const onTimeout = () => {
      socket.destroy(new Error("timeout"));
    };
    const timeoutHandle = setTimeout(onTimeout, timeoutMs);

    socket.once("secureConnect", () => {
      clearTimeout(timeoutHandle);

      const tlsVersion = socket.getProtocol(); // e.g., TLSv1.3
      // @ts-expect-error Node typings lag: alpnProtocol is there at runtime
      const alpn: string | null = (socket as any).alpnProtocol || null;
      const cipherObj = socket.getCipher();
      const cipherSuite = cipherObj?.name || null;

      const peer = socket.getPeerCertificate(true);
      // 'raw' is available when passing 'true' to getPeerCertificate
      const raw: Buffer | undefined = (peer as any).raw;

      let cn: string | null = null;
      let issuer: string | null = null;
      let notBefore: string | null = null;
      let notAfter: string | null = null;
      let san: string[] = [];
      let signatureAlgorithm: string | null = null;
      let keyType: "rsa" | "ec" | "ed25519" | "ed448" | "unknown" = "unknown";
      let keyBitsOrCurve: string | null = null;
      let fingerprint256: string | null = null;

      try {
        if (raw) {
          const x = new X509Certificate(raw);
          fingerprint256 = x.fingerprint256.replace(/:/g, "");
          issuer = x.issuer || null;
          notBefore = x.validFrom ? new Date(x.validFrom).toISOString() : null;
          notAfter = x.validTo ? new Date(x.validTo).toISOString() : null;
          signatureAlgorithm = x.signatureAlgorithm || null;

          // Subject CN and SAN parsing
          cn = extractCN(x.subject) || null;
          san = extractSANs(x) || [];
          // Public key
          const pk = x.publicKey;
          // @ts-ignore: Node publicKey.asymmetricKeyType exists
          const ktype: string | undefined = (pk as any).asymmetricKeyType;
          if (ktype === "rsa") {
            keyType = "rsa";
            // @ts-ignore
            keyBitsOrCurve = String((pk as any).asymmetricKeyDetails?.modulusLength ?? "");
          } else if (ktype === "ec") {
            keyType = "ec";
            // @ts-ignore
            keyBitsOrCurve = (pk as any).asymmetricKeyDetails?.namedCurve ?? null;
          } else if (ktype === "ed25519") {
            keyType = "ed25519";
          } else if (ktype === "ed448") {
            keyType = "ed448";
          } else {
            keyType = "unknown";
          }
        } else {
          // Fallback to parsed strings from getPeerCertificate summary
          cn = peer.subject?.CN ?? null;
          issuer = peer.issuer?.CN ?? null;
          notBefore = peer.valid_from ? new Date(peer.valid_from).toISOString() : null;
          notAfter = peer.valid_to ? new Date(peer.valid_to).toISOString() : null;
        }
      } catch (e) {
        // continue with partial data
      } finally {
        socket.end();
      }

      const tls_ok = !!tlsVersion && (tlsVersion === "TLSv1.3" || tlsVersion === "TLSv1.2");
      const weak_alg =
        (keyType === "rsa" && (Number(keyBitsOrCurve) || 0) < 2048) ||
        (signatureAlgorithm || "").toLowerCase().includes("sha1") ||
        (cipherSuite || "").toUpperCase().includes("RC4") ||
        (cipherSuite || "").toUpperCase().includes("3DES");
      const pqc_ready: "no" | "partial" | "unknown" =
        keyType === "ec" || keyType === "rsa" ? "no" : "unknown";

      resolve({
        domain,
        resolvedIPs: [ip],
        tlsVersion,
        alpn,
        cipherSuite,
        cert: {
          cn,
          issuer,
          notBefore,
          notAfter,
          san,
          signatureAlgorithm,
          keyType,
          keyBitsOrCurve,
          fingerprint256
        },
        posture: { tls_ok, weak_alg, pqc_ready },
        scannedAt: new Date().toISOString()
      });
    });

    socket.once("error", (e) => {
      clearTimeout(timeoutHandle);
      const err: any = new Error(`TLS error: ${e.message}`);
      err.status = /timeout/i.test(e.message) ? 504 : 502;
      reject(err);
    });
  });
}

function extractCN(subject: string): string | null {
  // subject like "CN=example.com,O=...,C=.."
  const m = /CN=([^,]+)/.exec(subject);
  return m ? m[1] : null;
}

function extractSANs(x: X509Certificate): string[] {
  try {
    const ext = x.subjectAltName; // "DNS:example.com, DNS:www.example.com"
    if (!ext) return [];
    return ext
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.startsWith("DNS:"))
      .map((s) => s.slice(4));
  } catch {
    return [];
  }
}
