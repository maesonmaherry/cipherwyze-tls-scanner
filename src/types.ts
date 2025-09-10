export type TlsScanResult = {
  domain: string;
  resolvedIPs: string[];
  tlsVersion: string | null;
  alpn: string | null;
  cipherSuite: string | null;
  cert: {
    cn: string | null;
    issuer: string | null;
    notBefore: string | null;
    notAfter: string | null;
    san: string[];
    signatureAlgorithm: string | null;
    keyType: "rsa" | "ec" | "ed25519" | "ed448" | "unknown";
    keyBitsOrCurve: string | null; // bits for RSA, curve name for EC
    fingerprint256: string | null;
  };
  posture: {
    tls_ok: boolean;
    weak_alg: boolean;
    pqc_ready: "no" | "partial" | "unknown";
  };
  scannedAt: string;
};
