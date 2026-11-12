import { useCallback, useEffect, useState } from 'react';

import { HttpUtil } from '@/utils';
import type { PanelUpdateInfo } from './PanelUpdateModal';

export type PanelUpdateCheckState = 'checking' | 'ok' | 'failed';

const NO_INFO: PanelUpdateInfo = { currentVersion: '', latestVersion: '', updateAvailable: false };

async function requestUpdateInfo(): Promise<PanelUpdateInfo | null> {
  const msg = await HttpUtil.get<PanelUpdateInfo>(
    '/panel/api/server/getPanelUpdateInfo',
    undefined,
    { silent: true },
  );
  return msg?.success && msg.obj ? msg.obj : null;
}

export function usePanelUpdateInfo() {
  const [info, setInfo] = useState<PanelUpdateInfo>(NO_INFO);
  const [checkState, setCheckState] = useState<PanelUpdateCheckState>('checking');

  const apply = useCallback((fresh: PanelUpdateInfo | null) => {
    if (fresh) setInfo(fresh);
    setCheckState(fresh ? 'ok' : 'failed');
  }, []);

  useEffect(() => {
    let cancelled = false;
    void requestUpdateInfo().then((fresh) => {
      if (!cancelled) apply(fresh);
    });
    return () => {
      cancelled = true;
    };
  }, [apply]);

  const recheck = useCallback(() => {
    setCheckState('checking');
    void requestUpdateInfo().then(apply);
  }, [apply]);

  return { info, checkState, recheck };
}
