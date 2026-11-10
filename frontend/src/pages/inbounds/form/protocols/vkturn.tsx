// Copyright (c) 2026 LucX-UI Project.
// Licensed under the PolyForm Noncommercial License 1.0.0.
// LucX-UI Component. Free for personal and educational use.
// Commercial use (including VPN resale) requires explicit written permission from the author.
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import { useTranslation } from 'react-i18next';
import { Alert, Input, InputNumber, Select } from 'antd';

import { FormField } from '@/components/form/rhf';
import { useInboundOptions } from '@/api/queries/useInboundOptions';
import { formatInboundLabel } from '@/lib/inbounds/label';

export default function VkturnFields() {
  const { t } = useTranslation();
  const { data: inbounds } = useInboundOptions();
  const wgOptions = (inbounds || [])
    .filter((ib) => ib.protocol === 'wireguard')
    .map((ib) => ({
      value: ib.id,
      label: `${formatInboundLabel(ib.tag, ib.remark)} (:${ib.port ?? ''})`,
    }));
  return (
    <>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message={t('pages.inbounds.form.vkturnNote')}
      />
      <FormField
        name={['settings', 'wgInboundId']}
        label={t('pages.inbounds.form.vkturnWgInbound')}
        tooltip={t('pages.inbounds.form.vkturnWgInboundHint')}
      >
        <Select
          options={wgOptions}
          placeholder={t('pages.inbounds.form.vkturnWgInboundPlaceholder')}
          notFoundContent={t('pages.inbounds.form.vkturnNoWgInbound')}
        />
      </FormField>
      <FormField
        name={['settings', 'subHost']}
        label={t('pages.inbounds.form.vkturnSubHost')}
        tooltip={t('pages.inbounds.form.vkturnSubHostHint')}
      >
        <Input placeholder="1.2.3.4" />
      </FormField>
      <FormField
        name={['settings', 'vkHashes']}
        label={t('pages.inbounds.form.qwdttVkHashes')}
        tooltip={t('pages.inbounds.form.vkturnVkHashesHint')}
      >
        <Input.TextArea rows={2} placeholder="hash1,hash2" />
      </FormField>
      <FormField name={['settings', 'dns']} label="DNS">
        <Input placeholder="1.1.1.1" />
      </FormField>
      <FormField
        name={['settings', 'numConnections']}
        label={t('pages.inbounds.form.vkturnNumConnections')}
        tooltip={t('pages.inbounds.form.vkturnNumConnectionsHint')}
      >
        <InputNumber min={1} max={50} style={{ width: '100%' }} />
      </FormField>
    </>
  );
}
