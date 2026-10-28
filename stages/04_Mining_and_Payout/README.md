# 04: Mining and payout

- **Miner:** XMRig **6.26.0**, statically linked, 8,350,992 bytes, SHA256 `b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49`. This is the same binary as the `x12345` miner in the public Plex2Shell write-ups.
- **Disguise:** runs as `<Plex>/Cache/PlexMediaScanner`, which looks like Plex's real scanner in a process list. It ran as the `plex` user at about 780% CPU (14 threads).
- **Where the work goes:** a TLS mining proxy at `185.146.232.55:443` (the active connection was captured live), with fallbacks `130.94.112.197:10002`, `130.94.112.118:10002`, `139.99.69.109:10001`, `bore.pub:625xx` tunnels, and the public pool `*.moneroocean.stream`.

## Wallets (public MoneroOcean stats, 28 Oct ~11:00 UTC)
| Wallet | Status | Hashrate | Paid out |
|---|---|---|---|
| `874yo479WPRgjWLXNyTvxmjdz3iwgMP4dD85h4hGPaB1jNAgjQx3zSzXfeZJq1uykg3x2c3HSfXYBcVYzz8fFfhPT7j7y2i` | **active** | 3.74 MH/s (peak 5.0) | 0.343 XMR in 4 payouts since 27 Oct |
| `8AB1pyofQxnfjU7UXcVEbXWVbSeTM3jdmXxGgKTUMYJYXJEnZvfdE1VSaZZ85LeuHf7UX6HfDoouQdFK5mfstQ23P9aCSE5` | stopped 27 Oct | 0 (peak 3.3 MH/s) | 0.037 XMR in 1 payout |

3.7 MH/s is roughly **500–800 infected machines**. The worker names include other victims' Plex and NAS boxes (`P_Plex_300`, `P_plex_983`, `P_Joca471NAS_076`, `P_Tower_856`).
Live stats: `https://moneroocean.stream/#/dashboard?addr=<wallet>`

## Files
- Miner binary: not in this repo; see MalwareBazaar `b20f39fc…4b49`.
- `active_miner_config_plex_exp_proxy.json`: the config it was running with.
- `miner_egress_185.146.232.55_summary.txt`: 2 minutes of live miner ↔ proxy traffic (victim IP masked).
- `miner_version.txt`: version string extracted from the binary.
