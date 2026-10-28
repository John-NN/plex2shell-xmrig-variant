# 02: Stage 2, the installer (`plex_deploy.sh`)

**Not recovered.** On 28 Oct at 10:43 UTC all three download servers were offline (130.94.112.118, 130.94.112.197, 89.125.187.222 on port 18899), and both mirrors returned 404 (`files.catbox.moe/b6r6tt.sh`, `d.uguu.se/swTOlsRc.sh`). The local copies (`/var/tmp/pd.sh*`) were empty. 550 `NOSCRIPT` lines in the system journal show it kept failing after its servers went down.

## What it did, reconstructed from what it left behind
- Installed the XMRig miner as `/var/tmp/plexd`, plus a disguised copy at `<Plex>/Cache/PlexMediaScanner`. Both are in `04_Mining_and_Payout/`.
- Wrote the miner configs `/var/tmp/plex_exp.json` (older) and `plex_exp_proxy.json` (active).
- Wrote a host profile, `/var/tmp/.pxinfo`: worker ID, thread count (14 of 16), RAM.
- Replaced the stage-1 crontab line with the watchdog line, and installed the watchdog and launcher (see `03_Persistence/`).
- Created `/var/tmp/.deployed`, the "install finished" flag that silences the stage-1 retry line.

## Files
- `download_attempts_2026-10-28/`: what came back when stage 2 was fetched on 28 Oct (timeouts, 404 pages).
- `files_it_left/plex_exp.json`: older config with MoneroOcean pools, `bore.pub` tunnels and wallet `8AB1pyof…`.
- `files_it_left/plex_exp_proxy.json`: the active config, using TLS proxy 185.146.232.55:443 and wallet `874yo479…`.
- `files_it_left/DOT.pxinfo.REDACTED.txt`: the host profile (victim hostname redacted).
- `files_it_left/DOT.wget-hsts.txt`: wget left a trace of downloading from `d.uguu.se` on 26 Oct 05:23.
