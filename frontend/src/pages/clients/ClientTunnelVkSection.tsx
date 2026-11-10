// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { useEffect, useImperativeHandle, useMemo, useState, type Ref } from 'react';
import { useTranslation } from 'react-i18next';
import { Form, Input, Tag, Typography } from 'antd';

import { HttpUtil } from '@/utils';
import type { InboundOption } from '@/schemas/client';

interface TunnelMemberStatus {
  inboundId: number;
  remark: string;
  protocol: string;
  ready: boolean;
  error?: string;
}

interface ClientVkResponse {
  vkHashes: string;
  members: TunnelMemberStatus[];
}

interface ApiMsg<T> {
  success?: boolean;
  msg?: string;
  obj?: T;
}

export interface ClientTunnelVkHandle {
  save: (email: string) => Promise<void>;
}

interface Props {
  ref?: Ref<ClientTunnelVkHandle>;
  open: boolean;
  // Email сохранённого клиента; пусто для нового.
  email: string;
  inbounds: InboundOption[];
  inboundIds: number[] | undefined;
}

const VK_PROTOCOLS = new Set(['qwdtt', 'csqtt']);
const PROTOCOL_LABELS: Record<string, string> = {
  qwdtt: 'qWDTT',
  csqtt: 'CSQTT',
  vkturn: 'VK TURN (iOS)',
};

function statusText(m: TunnelMemberStatus, t: (key: string) => string): string {
  if (m.protocol === 'vkturn') {
    return m.ready ? t('pages.clients.tunnelVkturnReady') : t('pages.clients.tunnelVkturnNotReady');
  }
  return m.ready ? t('pages.clients.tunnelMemberReady') : t('pages.clients.tunnelMemberPending');
}

function clientVkUrl(email: string): string {
  return `/panel/api/tunnel/clientVk/${encodeURIComponent(email)}`;
}

// Индивидуальные VK-хеши клиента для qWDTT/CSQTT и статус его паролей.
export default function ClientTunnelVkSection({ ref, open, email, inbounds, inboundIds }: Props) {
  const { t } = useTranslation();
  const [value, setValue] = useState('');
  const [initial, setInitial] = useState('');
  const [members, setMembers] = useState<TunnelMemberStatus[]>([]);

  // WireGuard-инбаунд тоже: его клиенты получают vkturnproxy://, если в
  // панели есть релей VK TURN.
  const visible = useMemo(() => {
    const hasRelay = (inbounds || []).some((row) => row.protocol === 'vkturn');
    return (inboundIds || []).some((id) => {
      const ib = (inbounds || []).find((row) => row.id === id);
      if (!ib) return false;
      return VK_PROTOCOLS.has(ib.protocol ?? '') || (hasRelay && ib.protocol === 'wireguard');
    });
  }, [inboundIds, inbounds]);

  // Сброс при открытии делаем во время рендера, эффект только грузит данные.
  const openKey = open ? email : null;
  const [syncedKey, setSyncedKey] = useState<string | null>(openKey);
  if (openKey !== syncedKey) {
    setSyncedKey(openKey);
    setValue('');
    setInitial('');
    setMembers([]);
  }

  useEffect(() => {
    if (!open || !email) return;
    let cancelled = false;
    void (async () => {
      const msg = (await HttpUtil.get(clientVkUrl(email))) as ApiMsg<ClientVkResponse> | null;
      if (cancelled || !msg?.success || !msg.obj) return;
      setValue(msg.obj.vkHashes || '');
      setInitial(msg.obj.vkHashes || '');
      setMembers(Array.isArray(msg.obj.members) ? msg.obj.members : []);
    })();
    return () => {
      cancelled = true;
    };
  }, [open, email]);

  useImperativeHandle(
    ref,
    () => ({
      save: async (savedEmail: string) => {
        const next = value.trim();
        // Переименование переносит хеши на новый email.
        if (!savedEmail || (next === initial.trim() && savedEmail === email)) return;
        await HttpUtil.post(
          clientVkUrl(savedEmail),
          { vkHashes: next },
          {
            headers: { 'Content-Type': 'application/json' },
          },
        );
      },
    }),
    [value, initial, email],
  );

  if (!visible) return null;
  return (
    <Form.Item
      label={t('pages.clients.tunnelVkHashes')}
      extra={t('pages.clients.tunnelVkHashesHint')}
    >
      <Input.TextArea
        rows={2}
        value={value}
        placeholder="hash1,hash2"
        onChange={(e) => setValue(e.target.value)}
      />
      {members.length > 0 && (
        <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {members.map((m) => (
            <Typography.Text key={m.inboundId} type={m.ready && !m.error ? undefined : 'warning'}>
              <Tag color={m.ready ? 'green' : 'orange'}>
                {PROTOCOL_LABELS[m.protocol] ?? m.protocol}
              </Tag>
              {m.remark || `#${m.inboundId}`}
              {': '}
              {statusText(m, t)}
              {m.error ? ` — ${m.error}` : ''}
            </Typography.Text>
          ))}
        </div>
      )}
    </Form.Item>
  );
}
