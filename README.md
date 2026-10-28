# Plex2Shell in the wild: XMRig miner variant with cron persistence

> **If you run Plex Media Server older than 1.43.3.10861 and it has ever been reachable from the internet, assume it may be compromised and check it.**
> This repo documents a real infection (26–28 Oct 2026) by a Plex2Shell variant that is **not** covered by the existing public write-ups: different operator, different servers, and a **cron + watchdog persistence** layer that survives killing the miner.

## Am I affected?

Run the read-only check (it changes nothing; please read it first, it's short):

```sh
curl -fsSLO https://raw.githubusercontent.com/John-NN/plex2shell-xmrig-variant/main/check_plex2shell.sh
less check_plex2shell.sh          # review it
sudo sh check_plex2shell.sh
```

Or check by hand:

| Check | Infected if… |
|---|---|
| `ls "<Plex data>/Plex Media Server/Codecs/"*/` | any `zz*.so` (or other file not named `lib*_decoder.so` / `lib*_encoder.so`) |
| `sudo crontab -u plex -l` | a line tagged `# plex_deploy_bootstrap` |
| `ls -la /var/tmp/` | `.pxwd.sh`, `.pxagent.sh`, `plexd`, `.pxcfg_*.b64`, `plex_exp*.json`, `.pxinfo`, `.deployed` |
| `ps aux \| grep -i plexmediascanner` | a process running from `…/Plex Media Server/Cache/PlexMediaScanner` (the real scanner lives in `/usr/lib/plexmediaserver/`) |
| `top` | a "Plex" process using all your CPU while nothing is playing |
| `grep TranscoderH264Options Preferences.xml` | contains `dump-yuv=` |

**Debian/Ubuntu trap:** if `/etc/apt/sources.list.d/plexmediaserver.list` still points to `downloads.plex.tv/repo/deb`, that repo now returns **404**, so `apt upgrade` silently **never updates Plex** and you are stuck on a vulnerable version. That is exactly how the server in this report stayed on 1.42.2. See [the fix](#if-youre-affected).

## What happens (TL;DR)

**Plex bug → fake codec → downloads installer → installs miner + watchdog → your CPU mines Monero for the attacker.**

| Stage | What | Details |
|---|---|---|
| 0. Break-in | SSRF steals the owner token; `TranscoderH264Options=dump-yuv` makes the transcoder write a `zz*.so` into the Codecs folder | [stages/00_Break_In](stages/00_Break_In/) |
| 1. Fake codec | Plex loads every `.so` in Codecs; the implant's constructor runs a hidden shell script that writes miner configs and downloads stage 2 | [stages/01_Stage1_Fake_Codec](stages/01_Stage1_Fake_Codec/) |
| 2. Installer | `plex_deploy.sh` (not recovered, servers dead) installs XMRig as `/var/tmp/plexd`, disguised as `<Plex>/Cache/PlexMediaScanner` | [stages/02_Stage2_Installer](stages/02_Stage2_Installer/) |
| 3. Persistence | cron (every minute) → `.pxwd.sh` watchdog → `.pxagent.sh` relaunches the miner every 45 s; the codec re-infects on every Plex start or transcode | [stages/03_Persistence](stages/03_Persistence/) |
| 4. Payout | XMRig 6.26.0, 14 threads, TLS proxy `185.146.232.55:443`; ~3.7 MH/s, roughly 500–800 infected machines | [stages/04_Mining_and_Payout](stages/04_Mining_and_Payout/) |

Full technical report: [REPORT.md](REPORT.md). Files named `DOT.something` inside `stages/` were originally hidden files (`.something`); attacker scripts are stored as inert `.txt`.

## How this differs from the published Plex2Shell cases
- **Same** implant technique (`zz*.so`, 1,036,800 bytes) and the **byte-identical miner** (`b20f39fc…4b49`, the public "x12345").
- **Different operator infrastructure:** C2 `130.94.112.197` / `130.94.112.118` / `89.125.187.222` on TCP 18899 (`/plex_deploy.sh`); mining via a TLS proxy on `185.146.232.55:443`.
- **Adds persistence:** a plex-user crontab plus a watchdog and launcher in `/var/tmp`. Killing the miner is undone within 45 s.
- **Disguise:** the miner runs as `PlexMediaScanner` inside Plex's own Cache folder.
- **Active exploitation continued after the infection:** on 28 Oct, `176.65.149.174` and `43.108.122.170` ran the full chain again. The second also read `/proc/self/environ` and `Preferences.xml` (which holds the Plex token) first, and sprayed Docker, Synology and QNAP paths.

## If you're affected
1. **Stop Plex**: `sudo systemctl stop plexmediaserver` (otherwise the implant re-runs).
2. **Remove persistence**: `sudo crontab -u plex -r` (check it first with `-l`), then kill the remaining `plex` user processes.
3. **Delete the implant and files**: the whole `Codecs/<id>-linux-x86_64/` folder (Plex re-downloads the real codecs), `<Plex>/Cache/PlexMediaScanner`, and `/var/tmp/{plexd,.pxwd.sh,.pxagent.sh,.pxcfg_*,plex_exp*.json,.pxinfo,.pxlog,.pxalive,.pxwd.pid,.deployed,pd.sh*}`. Keep copies first if you want to report it.
4. **Make sure `TranscoderH264Options` is empty** in `Preferences.xml`.
5. **Update Plex to ≥ 1.43.3.10861.** On Debian/Ubuntu, fix the dead repo first:
   ```sh
   curl -fsSL https://downloads.plex.tv/plex-keys/PlexSign.v2.key | gpg --dearmor | sudo tee /usr/share/keyrings/plexmediaserver.gpg >/dev/null
   echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/plexmediaserver.gpg] https://repo.plex.tv/deb public main' | sudo tee /etc/apt/sources.list.d/plexmediaserver.list
   sudo apt update && sudo apt install --only-upgrade plexmediaserver
   ```
6. **Rotate your Plex account**: change the password and use "sign out of all devices" (the exploit steals your owner token). Then re-claim your server.
7. **Block the IOCs** below and don't expose port 32400 to the internet unless you need to.
8. Plex runs as the unprivileged `plex` user. In this case there was no sign of privilege escalation, but check what that user could read or write (world-readable files, world-writable media folders).

## Indicators of compromise
Full list: [iocs/iocs.csv](iocs/iocs.csv) · YARA: [yara/plex2shell_xmrig_variant.yar](yara/plex2shell_xmrig_variant.yar) (matches all 3 loaders and both scripts; no false positives on 58 genuine Plex libraries).

| Type | Value |
|---|---|
| C2 (`/plex_deploy.sh`, TCP 18899) | `130.94.112.197`, `130.94.112.118`, `89.125.187.222` |
| Mining proxies | `185.146.232.55:443` (TLS), `130.94.112.197:10002`, `130.94.112.118:10002` |
| Exploiting hosts (2026-10-28) | `176.65.149.174`, `43.108.122.170` |
| Stage-2 mirrors | `files.catbox.moe/b6r6tt.sh`, `d.uguu.se/swTOlsRc.sh` |
| Cron tag | `# plex_deploy_bootstrap` |
| Wallets | `874yo479WPRgjWLXNyTvxmjdz3iwgMP4dD85h4hGPaB1jNAgjQx3zSzXfeZJq1uykg3x2c3HSfXYBcVYzz8fFfhPT7j7y2i` (active), `8AB1pyofQxnfjU7UXcVEbXWVbSeTM3jdmXxGgKTUMYJYXJEnZvfdE1VSaZZ85LeuHf7UX6HfDoouQdFK5mfstQ23P9aCSE5` |

### Samples (MalwareBazaar)
Binaries are deliberately **not** stored in this repo.
| SHA256 | What |
|---|---|
| [`5a006b1059104180198e2488c54d53f048ae79acc5e67762cb308c13257c7a94`](https://bazaar.abuse.ch/sample/5a006b1059104180198e2488c54d53f048ae79acc5e67762cb308c13257c7a94/) | loader variant 1 (`zz92113.so`) |
| [`edab20185f73dd8aff3dace3e552d4cc07bb16583ef7b9cdec02d81d1d1e52fe`](https://bazaar.abuse.ch/sample/edab20185f73dd8aff3dace3e552d4cc07bb16583ef7b9cdec02d81d1d1e52fe/) | loader variant 2 (`zz95748.so`) |
| [`046a9efb637f66be75f85a4748742520390382566e1c0a8b34f38ec166e39b5b`](https://bazaar.abuse.ch/sample/046a9efb637f66be75f85a4748742520390382566e1c0a8b34f38ec166e39b5b/) | loader variant 3 (`zz41257.so` = `zz83494.so`) |
| [`b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49`](https://bazaar.abuse.ch/sample/b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49/) | XMRig 6.26.0 miner (mislabelled "Mirai" on MalwareBazaar) |

## References
- Plex2Shell: CVE-2026-96652 / -96654 / -96655 / -96656, fixed in Plex Media Server **1.43.3.10861**; listed in CISA KEV.
- Earlier incident write-up (same implant and miner, different operator): https://github.com/a3igner/plex-codec-cache-implant
- Community detection script: https://github.com/ChrisLPJones/plex2shell-check

---
Victim-identifying data (hostname, IPs, Plex identifiers, account names) has been replaced with `<victim-…>` placeholders throughout. Times are UTC.
