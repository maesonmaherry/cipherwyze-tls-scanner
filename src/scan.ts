import tls from "tls";
import dns from "dns/promises";
import { X509Certificate } from "crypto";

const isAsciiHostname = (host: string) =>
  /^[A-Za-z0-9.-]{1,255}$/.test(host) &&
  !/^\d{1,3}(\.\d{1,3}){3}$/.test(host) &&
  !/^[0-9a-f:]+$/i.test(host);

export async function scanDomain(domain: string, timeoutMs = 8000) {
  if (!isAsciiHostname(domain)) throw new Error("Invalid domain");

  const records = await dns.lookup(domain, { all: true });
  const addresses = [
    ...records.filter((r) => r.family === 4),
    ...records.filter((r) => r.family === 6),
  ].map((r) => r.address);
  if (!addresses.length) throw new Error("No A/AAAA records");

  let lastErr: any;
  for (const ip of addresses) {
    try {
      return await connectOnce(domain, ip, timeoutMs);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("TLS connection failed");
}

function connectOnce(domain: string, ip: string, timeoutMs: number) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({
      host: ip,
      port: 443,
      servername: domain, // SNI
      ALPNProtocols: ["h2", "http/1.1"],
    });

    const t = setTimeout(() => sock.destroy(new Error("timeout")), timeoutMs);

    sock.once("secureConnect", () => {
      clearTimeout(t);

      const tlsVersion = sock.getProtocol(); // e.g., "TLSv1.3"
      // Node typings don’t declare alpnProtocol; it exists at runtime
      const alpn: string | null = (sock as any).alpnProtocol || null;
      const cipherSuite = sock.getCipher()?.name || null;

      const peer = sock.getPeerCertificate(true);
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

          // Subject CN + SANs
          cn = /CN=([^,]+)/.exec(x.subject)?.[1] || null;
          const sanStr = x.subjectAltName || "";
          san = sanStr
            .split(",")
            .map((s) => s.trim())
            .filter((s) => s.startsWith("DNS:"))
            .map((s) => s.slice(4));

          // Typings omission: access via 'any' at runtime; fallback to peer summary
          signatureAlgorithm =
            ((x as any).signatureAlgorithm as string | undefined) ??
            ((peer as any).signatureAlgorithm as string | undefined) ??
            null;

          // Public key details
          const pk = (x as any).publicKey;
          const ktype = pk?.asymmetricKeyType as string | undefined;
          if (ktype === "rsa") {
            keyType = "rsa";
            keyBitsOrCurve = String(pk?.asymmetricKeyDetails?.modulusLength ?? "");
          } else if (ktype === "ec") {
            keyType = "ec";
            keyBitsOrCurve = pk?.asymmetricKeyDetails?.namedCurve ?? null;
          } else if (ktype === "ed25519") {
            keyType = "ed25519";
          } else if (ktype === "ed448") {
            keyType = "ed448";
          } else {
            keyType = "unknown";
          }
        } else {
          // Fallback if no raw cert
          cn = peer.subject?.CN ?? null;
          issuer = peer.issuer?.CN ?? null;
          notBefore = peer.valid_from ? new Date(peer.valid_from).toISOString() : null;
          notAfter = peer.valid_to ? new Date(peer.valid_to).toISOString() : null;
          signatureAlgorithm = (peer as any).signatureAlgorithm ?? null;
        }
      } catch {
        // continue with partial data
      } finally {
        sock.end();
      }

      const tls_ok = tlsVersion === "TLSv1.3" || tlsVersion === "TLSv1.2";
      const weak_alg =
        (keyType === "rsa" && (Number(keyBitsOrCurve) || 0) < 2048) ||
        (signatureAlgorithm || "").toLowerCase().includes("sha1") ||
        (cipherSuite || "").toUpperCase().includes("RC4") ||
        (cipherSuite || "").toUpperCase().includes("3DES");
      const pqc_ready = keyType === "rsa" || keyType === "ec" ? "no" : "unknown";

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
          fingerprint256,
        },
        posture: { tls_ok, weak_alg, pqc_ready },
        scannedAt: new Date().toISOString(),
      });
    });

    sock.once("error", (e) => {
      clearTimeout(t);
      reject(e);
    });
  });
}
