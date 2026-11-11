// Copyright (c) 2025 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { z } from 'zod';

export const QWDTT_DEFAULT_WG_SUBNET = '10.68.0.0/16';
export const QWDTT_DEFAULT_RAW_SUBNET = '10.70.0.0/16';

const PRIVATE_V4: Array<[number, number]> = [
  [0x0a000000, 8],
  [0xac100000, 12],
  [0xc0a80000, 16],
];

function maskOf(bits: number): number {
  return bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
}

// Mirrors parseQwdttSubnet (internal/lucx/tunnel/qwdtt_subnets.go); overlap
// with the other pool and panel-reserved ranges is checked server-side.
export function isQwdttSubnet(value: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(value.trim());
  if (!m) return false;
  const octets = m.slice(1, 5).map(Number);
  const bits = Number(m[5]);
  if (octets.some((o) => o > 255) || bits < 16 || bits > 24) return false;
  const addr = octets.reduce((acc, o) => ((acc << 8) | o) >>> 0, 0);
  if ((addr & maskOf(bits)) >>> 0 !== addr) return false;
  return PRIVATE_V4.some(([net, len]) => (addr & maskOf(len)) >>> 0 === net);
}

export const QwdttSubnetSchema = z
  .string()
  .refine(isQwdttSubnet, { error: 'pages.inbounds.form.qwdttSubnetInvalid' });

export const QwdttInboundSettingsSchema = z.object({
  listenAddr: z.string().default('0.0.0.0:56000'),
  wgPort: z.number().int().min(1).max(65535).default(56001),
  password: z.string().default(''),
  dns: z.string().default('8.8.8.8'),
  configDir: z.string().default(''),
  listenRaw: z.string().default('0.0.0.0:56003'),
  listenDirect: z.string().default(''),
  wgSubnet: QwdttSubnetSchema.default(QWDTT_DEFAULT_WG_SUBNET),
  rawSubnet: QwdttSubnetSchema.default(QWDTT_DEFAULT_RAW_SUBNET),
  subHost: z.string().default(''),
  vkHashes: z.string().default(''),
  clientPort: z.number().int().min(1).max(65535).default(9000),
  workers: z.number().int().min(1).max(64).default(16),
  routeThroughXray: z.boolean().default(true),
  outboundTag: z.string().default(''),
  perClient: z.boolean().default(false),
  adminPort: z.number().int().min(0).max(65535).default(0),
});
export type QwdttInboundSettings = z.infer<typeof QwdttInboundSettingsSchema>;
