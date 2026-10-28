#!/bin/sh
# check_plex2shell.sh: READ-ONLY check for Plex2Shell exploitation and the
# "plex_deploy_bootstrap" XMRig variant on Linux Plex Media Server hosts.
# It changes nothing. Run it as root for the full picture (crontab and Plex prefs).
#   sudo sh check_plex2shell.sh
# Exit code: 0 = nothing found, 1 = indicators found, 2 = vulnerable version only.

FOUND=0; VULN=0
red(){ printf '\033[31m[!] %s\033[0m\n' "$*"; FOUND=1; }
ylw(){ printf '\033[33m[?] %s\033[0m\n' "$*"; }
grn(){ printf '\033[32m[ok] %s\033[0m\n' "$*"; }
wrn(){ printf '\033[31m[!] %s\033[0m\n' "$*"; }   # risk, not an infection indicator

PMS_DIR="${PLEX_MEDIA_SERVER_APPLICATION_SUPPORT_DIR:-/var/lib/plexmediaserver/Library/Application Support}/Plex Media Server"
[ -d "$PMS_DIR" ] || for d in "/config/Library/Application Support/Plex Media Server" \
  "/var/packages/PlexMediaServer/shares/PlexMediaServer/AppData" \
  /share/*/.qpkg/PlexMediaServer/Library/Plex\ Media\ Server; do [ -d "$d" ] && PMS_DIR="$d" && break; done
echo "Plex data dir: $PMS_DIR"
[ "$(id -u)" -eq 0 ] || ylw "not running as root: crontab and Preferences.xml checks may be incomplete"

# 1. version (fixed in 1.43.3.10861)
V=$(curl -s --max-time 5 http://127.0.0.1:32400/identity 2>/dev/null | sed -n 's/.*version="\([0-9][0-9.]*\)-.*/\1/p')
[ -z "$V" ] && V=$(dpkg-query -W -f='${Version}' plexmediaserver 2>/dev/null | cut -d- -f1)
[ -z "$V" ] && V=$(rpm -q --qf '%{VERSION}' plexmediaserver 2>/dev/null)
if [ -n "$V" ]; then
  if [ "$(printf '%s\n1.43.3.10861\n' "$V" | sort -V | head -1)" = "1.43.3.10861" ]; then grn "Plex version $V (>= 1.43.3.10861, patched)"
  else wrn "Plex version $V is VULNERABLE to Plex2Shell (fixed in 1.43.3.10861)"; VULN=1; fi
else ylw "could not determine Plex version"; fi

# 2. dead apt repo (installs stuck on old versions)
if grep -rqs 'downloads.plex.tv/repo/deb' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
  wrn "apt source points to downloads.plex.tv/repo/deb (returns 404, so Plex NEVER updates). Switch to https://repo.plex.tv/deb with the PlexSign.v2 key"
fi

# 3. implanted codecs
ODD=$(find "$PMS_DIR/Codecs" -type f \( -name '*.so' -o -name '*.dll' \) 2>/dev/null | grep -vE '/lib[a-z0-9_]+_(de|en)coder\.so$|EasyAudioEncoder')
[ -n "$ODD" ] && { red "unexpected libraries in the Plex Codecs folder (Plex2Shell implants are zz*.so):"; echo "$ODD" | sed 's/^/      /'; } || grn "Codecs folder: no unexpected .so/.dll"

# 4. transcoder preference used by the exploit
P="$PMS_DIR/Preferences.xml"
if [ -r "$P" ]; then
  T=$(sed -n 's/.*TranscoderH264Options="\([^"]*\)".*/\1/p' "$P")
  [ -n "$T" ] && red "TranscoderH264Options is set: '$T' (dump-yuv here = active exploit)" || grn "TranscoderH264Options empty/unset"
fi

# 5. this variant's files
for f in /var/tmp/.pxwd.sh /var/tmp/.pxagent.sh /var/tmp/plexd /var/tmp/plex_exp.json /var/tmp/plex_exp_proxy.json \
         /var/tmp/.pxinfo /var/tmp/.deployed /tmp/.pxinfo /tmp/.deployed "$PMS_DIR/Cache/PlexMediaScanner"; do
  [ -e "$f" ] && red "variant file present: $f"
done
ls /var/tmp/.pxcfg_* /tmp/.pxcfg_* /var/tmp/pd.sh* 2>/dev/null | sed 's/^/[!] variant file present: /' | grep . && FOUND=1
# public x12345 / mylovelyminer / myawesomeproxy variants
ls /tmp/x12345 /tmp/sh.lock 2>/dev/null | sed 's/^/[!] known Plex2Shell file: /' | grep . && FOUND=1

# 6. crontab persistence
CR=$(crontab -u plex -l 2>/dev/null; cat /var/spool/cron/crontabs/plex /var/spool/cron/plex 2>/dev/null)
echo "$CR" | grep -qE 'plex_deploy|pxwd|/var/tmp/|/tmp/|curl|wget' && { red "suspicious crontab for user plex:"; echo "$CR" | grep -vE '^#' | sed 's/^/      /'; }

# 7. processes
PS=$(ps -eo user,pid,pcpu,args 2>/dev/null | grep -E 'Cache/PlexMediaScanner|/var/tmp/plexd|/var/tmp/\.pxwd\.sh|/var/tmp/\.pxagent\.sh|(^|[ /])(x12345|mylovelyminer|myawesomeproxy|xmrig)( |$)|--cpu-max-threads-hint' | grep -vE 'check_plex2shell|grep -E')
[ -n "$PS" ] && { red "suspicious processes:"; echo "$PS" | sed 's/^/      /'; } || grn "no known miner/proxy processes"

# 8. connections to known infrastructure
IOC='130\.94\.112\.(197|118)|89\.125\.187\.222|185\.146\.232\.55|176\.65\.149\.174|43\.108\.122\.170|77\.90\.185\.205|217\.60\.194\.116'
NC=$( (ss -tn 2>/dev/null || netstat -tn 2>/dev/null) | grep -E "$IOC")
[ -n "$NC" ] && { red "connections to known Plex2Shell infrastructure:"; echo "$NC" | sed 's/^/      /'; } || grn "no connections to known infrastructure"

# 9. exploit traces in Plex logs (only as far back as Plex keeps logs)
L=$(grep -haE 'TranscoderH264Options=dump-yuv|resources/x\?resource_name=|player/timeline/subscribe\?[^ ]*protocol=http' "$PMS_DIR"/Logs/*.log 2>/dev/null | head -5)
[ -n "$L" ] && { red "Plex2Shell exploitation ATTEMPTS found in Plex logs (attempt != infection; check the items above) (first 5):"; echo "$L" | cut -c1-200 | sed 's/^/      /'; }

echo
if [ $FOUND -eq 1 ]; then echo "RESULT: indicators found. See https://github.com/John-NN/plex2shell-xmrig-variant#if-youre-affected"; exit 1
elif [ $VULN -eq 1 ]; then echo "RESULT: no infection indicators, but Plex is VULNERABLE: update now"; exit 2
else echo "RESULT: nothing found"; exit 0; fi
