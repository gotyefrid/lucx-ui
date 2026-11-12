import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import PanelUpdateModal from '@/pages/index/PanelUpdateModal';
import { usePanelUpdateInfo } from '@/pages/index/usePanelUpdateInfo';
import { HttpUtil, Msg } from '@/utils';
import { renderWithProviders } from './test-utils';

const UPDATE_INFO_URL = '/panel/api/server/getPanelUpdateInfo';

function Harness() {
  const { info, checkState, recheck } = usePanelUpdateInfo();
  return (
    <PanelUpdateModal
      open
      info={info}
      checkState={checkState}
      onCheck={recheck}
      onClose={() => {}}
      onBusy={() => {}}
    />
  );
}

let updateInfoReply: Msg<unknown> = new Msg(false, '');

function answerUpdateInfo(reply: Msg<unknown>) {
  updateInfoReply = reply;
  vi.mocked(HttpUtil.get).mockImplementation(async (url: string) =>
    url === UPDATE_INFO_URL ? updateInfoReply : new Msg(true, '', {}),
  );
}

const upToDate = { currentVersion: '3.11.0-lucx.359', latestVersion: 'v3.11.0-lucx.359' };

describe('panel update check', () => {
  afterEach(() => {
    vi.mocked(HttpUtil.get).mockImplementation(async () => new Msg(true, '', {}));
  });

  it('finds a release published after the page loaded when the admin re-checks', async () => {
    answerUpdateInfo(new Msg(true, '', { ...upToDate, updateAvailable: false }));
    renderWithProviders(<Harness />);
    await screen.findAllByText('Panel is up to date');
    answerUpdateInfo(
      new Msg(true, '', { ...upToDate, latestVersion: 'v3.11.0-lucx.360', updateAvailable: true }),
    );

    const check = screen.getByRole('button', { name: /Check for updates/ });
    // AntD drops the loading class a tick late and swallows clicks until then.
    await waitFor(() => expect(check.classList.contains('ant-btn-loading')).toBe(false));
    await act(async () => {
      fireEvent.click(check);
    });

    expect(await screen.findByText('v3.11.0-lucx.360')).toBeTruthy();
    const update = screen.getByRole('button', { name: /Update Panel/ });
    expect(update.hasAttribute('disabled')).toBe(false);
  });

  it('reports a failed check instead of claiming the panel is up to date', async () => {
    answerUpdateInfo(new Msg(false, ''));
    renderWithProviders(<Harness />);

    expect(await screen.findByText('Could not check for updates')).toBeTruthy();
    expect(screen.queryByText('Panel is up to date')).toBeNull();
  });
});
