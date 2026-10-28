# 01: Stage 1, the fake codec (`zz*.so`)

A 1,036,800-byte Linux shared library. It exports one function (`go`) and has a constructor in `.init_array`, so **its code runs the moment Plex loads it**. The constructor runs a `/bin/sh` script stored as text inside the file (`.rodata`).

## What the hidden script does
1. Writes base64-encoded miner configs to `/var/tmp/.pxcfg_{auto,light,proxy,proxy_light}.b64` (`light` is for low-RAM machines).
2. Downloads stage 2 (`plex_deploy.sh`), trying `wget`, `curl`, `busybox wget` and `perl` in turn so it works on any Linux, NAS or container.
3. Checks that the download is genuine: it must contain the attacker's wallet and pool, and must not contain retired servers. Otherwise it prints `NOSCRIPT` and stops.
4. Installs a per-minute crontab line tagged `# plex_deploy_bootstrap`.
5. Runs stage 2.

## The four variants
| File | Planted (UTC) | Downloads stage 2 from | Notes |
|---|---|---|---|
| `zz92113.so` | 26 Oct 05:21 | 130.94.112.118, 89.125.187.222, catbox.moe, uguu.se | first wave; checks for the `BADWALLET` marker |
| `zz95748.so` | 26 Oct 06:22 | 130.94.112.118 | 4 configs; checks wallet `8AB1pyof…` and pool .118:10002 |
| `zz41257.so` = `zz83494.so` | 26 Oct 19:00 / 27 Oct 06:44 | 130.94.112.197 | new wallet `874yo479…`, TLS proxy 185.146.232.55:443, config written as plain JSON |

## Files
- Binaries are **not** in this repo; download them from MalwareBazaar (links in the main README).
- `payload_readable/*_payload.sh.txt`: **start here.** The hidden script of each variant as readable text. `*_FULL.txt` is the complete raw `.rodata`, with full base64 blobs.
- `binary_analysis/`: `file`, `readelf` and `strings` output for each binary.
- `configs_it_writes/`: the base64 config files (`DOT.pxcfg_*.b64.txt`), their decoded JSON, and `*.decoded_b64.txt` (the blobs decoded straight out of each `.so`).
