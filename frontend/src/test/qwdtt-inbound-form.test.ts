// Copyright (c) 2025 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { describe, it, expect } from 'vitest';
import { InboundFormSchema } from '@/schemas/forms/inbound-form';
import { createDefaultQwdttInboundSettings } from '@/lib/xray/inbound-defaults';
import { formValuesToWirePayload } from '@/lib/xray/inbound-form-adapter';
import { QwdttSubnetSchema } from '@/schemas/protocols/inbound/qwdtt';

function base(over: Record<string, unknown> = {}) {
  return {
    remark: 'test',
    enable: true,
    port: 12345,
    listen: '',
    tag: '',
    expiryTime: 0,
    sniffing: {
      enabled: false,
      destOverride: ['http', 'tls', 'quic', 'fakedns'],
      metadataOnly: false,
      routeOnly: false,
      ipsExcluded: [],
      domainsExcluded: [],
    },
    streamSettings: { network: 'tcp', security: 'none', tcpSettings: {} },
    up: 0,
    down: 0,
    total: 0,
    trafficReset: 'never' as const,
    trafficResetDay: 1,
    lastTrafficResetTime: 0,
    nodeId: null,
    shareAddrStrategy: 'node' as const,
    shareAddr: '',
    subSortIndex: 1,
    protocol: 'qwdtt' as const,
    settings: createDefaultQwdttInboundSettings(),
    ...over,
  };
}

describe('qwdtt inbound form', () => {
  it('parses default add-mode shape', () => {
    const r = InboundFormSchema.safeParse(base());
    expect(r.success, JSON.stringify(r.success ? null : r.error.issues)).toBe(true);
  });

  it('parses transportless stream', () => {
    const r = InboundFormSchema.safeParse(base({ streamSettings: { security: 'none' } }));
    expect(r.success, JSON.stringify(r.success ? null : r.error.issues)).toBe(true);
  });

  it('parses without streamSettings', () => {
    const r = InboundFormSchema.safeParse(base({ streamSettings: undefined }));
    expect(r.success, JSON.stringify(r.success ? null : r.error.issues)).toBe(true);
  });

  it('rejects null InputNumber fields', () => {
    const settings = { ...createDefaultQwdttInboundSettings(), wgPort: null, workers: null };
    const r = InboundFormSchema.safeParse(base({ settings }));
    expect(r.success).toBe(false);
  });

  it('wire payload has protocol qwdtt and empty stream', () => {
    const parsed = InboundFormSchema.parse(base());
    const wire = formValuesToWirePayload(parsed);
    expect(wire.protocol).toBe('qwdtt');
    expect(JSON.parse(wire.settings).listenAddr).toBe('0.0.0.0:56000');
  });

  it('parses transportless stream after sidecar protocol switch shape', () => {
    const r = InboundFormSchema.safeParse(
      base({
        port: 56000,
        streamSettings: { security: 'none' },
      }),
    );
    expect(r.success, JSON.stringify(r.success ? null : r.error.issues)).toBe(true);
  });

  it('sends the default client subnets so the sidecar keeps its pools', () => {
    const wire = formValuesToWirePayload(InboundFormSchema.parse(base()));
    const settings = JSON.parse(wire.settings);
    expect(settings.wgSubnet).toBe('10.68.0.0/16');
    expect(settings.rawSubnet).toBe('10.70.0.0/16');
  });

  it.each([
    ['192.168.77.0/24', true],
    ['172.20.0.0/20', true],
    ['10.68.0.0', false],
    ['10.68.5.0/16', false],
    ['10.0.0.0/8', false],
    ['10.70.0.0/25', false],
    ['8.8.0.0/16', false],
    ['10.300.0.0/16', false],
  ])('subnet %s valid=%s', (value, ok) => {
    const r = QwdttSubnetSchema.safeParse(value);
    expect(r.success).toBe(ok);
    if (!r.success) expect(r.error.issues[0].message).toBe('pages.inbounds.form.qwdttSubnetInvalid');
  });
});
