// ─── x402 Protocol Types ────────────────────────────────────

export interface PaymentRequirement {
  scheme: string;
  network: string;
  maxAmountRequired: string;
  resource: string;
  description?: string;
  payTo: string;
  asset?: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
}

export interface PaymentRequired {
  x402Version: number;
  accepts: PaymentRequirement[];
  error?: string;
}

export interface XrplPaymentPayload {
  x402Version: number;
  scheme: string;
  network: string;
  payload: {
    txBlob: string;
    txHash: string;
  };
}

export interface PaymentResponse {
  success: boolean;
  transaction?: string;
  network?: string;
  payer?: string;
  errorReason?: string | null;
}

// ─── XRPL Network Constants (CAIP-2 style) ──────────────────

export const XRPL_NETWORKS: Record<string, string> = {
  'xrpl:0': 'wss://xrplcluster.com',
  'xrpl:1': 'wss://s.altnet.rippletest.net:51233',
};

// ─── Header Parsing ──────────────────────────────────────────

export function parsePaymentRequired(headers: Headers): PaymentRequired | null {
  // V2: PAYMENT-REQUIRED, V1 fallback: X-PAYMENT
  const raw = headers.get('payment-required') || headers.get('x-payment');
  if (!raw) return null;
  try {
    return JSON.parse(Buffer.from(raw, 'base64').toString('utf8')) as PaymentRequired;
  } catch {
    return null;
  }
}

export function encodePaymentSignature(payload: XrplPaymentPayload): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

export function parsePaymentResponse(headers: Headers): PaymentResponse | null {
  const raw = headers.get('payment-response') || headers.get('x-payment-response');
  if (!raw) return null;
  try {
    return JSON.parse(Buffer.from(raw, 'base64').toString('utf8')) as PaymentResponse;
  } catch {
    return null;
  }
}

// ─── Helpers ─────────────────────────────────────────────────

export function findXrplRequirement(req: PaymentRequired): PaymentRequirement | null {
  return req.accepts.find(a => a.network.startsWith('xrpl:')) ?? null;
}

export function dropsToXrp(drops: string | number): string {
  return (Number(drops) / 1_000_000).toFixed(6).replace(/\.?0+$/, '');
}
