// src/polyfills.ts
/* eslint-disable @typescript-eslint/no-explicit-any */
import { webcrypto } from 'node:crypto';

if (typeof globalThis.crypto === 'undefined') {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  (globalThis as any).crypto = webcrypto;
}
