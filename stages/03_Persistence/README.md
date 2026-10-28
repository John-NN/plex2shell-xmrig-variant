# 03: Persistence (how it stays alive)

```
cron (every minute)  →  .pxwd.sh (watchdog, one copy only)
                           └─ every 45 s → .pxagent.sh (launcher)
                                              └─ miner not running? → copy it back from /var/tmp/plexd and start it
Plex start / transcode  →  loads the zz*.so codecs again  →  stage 1 re-runs (re-infection)
```

**Killing the miner alone does nothing:** it is back within 45 seconds. Clearing the cron job and the miner isn't enough either, because the next Plex restart or transcode re-runs the fake codecs. Removal needs the codecs, the cron job, the files in `/var/tmp`, and a patched Plex (at least 1.43.3.10861).

## Files
- `plex_crontab_entry.txt`: `* * * * * /bin/sh "/var/tmp/.pxwd.sh" >/dev/null 2>&1 # plex_deploy_bootstrap`
- `DOT.pxwd.sh.txt`: the watchdog (`/var/tmp/.pxwd.sh`).
- `DOT.pxagent.sh.txt`: the launcher (`/var/tmp/.pxagent.sh`).
- `DOT.pxlog.txt`: the miner's log (only "Killed"/"Terminated" lines, from restarts).
- `payload_execution_events.txt`: system journal timestamps of every payload run: **799** crontab rewrites and **550** `NOSCRIPT` lines, 26–28 Oct.
