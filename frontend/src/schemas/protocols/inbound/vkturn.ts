// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { z } from 'zod';

// Релей VK TURN (iOS, anton48): клиенты — пиры выбранного WireGuard-инбаунда.
export const VkturnInboundSettingsSchema = z.object({
  wgInboundId: z.number().int().min(0).default(0),
  subHost: z.string().default(''),
  vkHashes: z.string().default(''),
  dns: z.string().default('1.1.1.1'),
  numConnections: z.number().int().min(1).max(50).default(30),
});
export type VkturnInboundSettings = z.infer<typeof VkturnInboundSettingsSchema>;
