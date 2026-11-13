#!/bin/sh
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#-----------------------------------------------------------------------------#
# SPDX-License-Identifier: AGPL-3.0-or-later
# eFa-next rspamd configuration. Replaces opendkim (8891) and opendmarc (8893) in
# the Postfix milter chain with rspamd (11332). Other milters keep their position.
#-----------------------------------------------------------------------------#
set -e

RSPAMD_LOCAL=/etc/rspamd/local.d
MAIN_CF=/etc/postfix/main.cf
BACKUP=/etc/postfix/main.cf.pre-rspamd

# Requirement: rspamd is installed
command -v rspamd >/dev/null 2>&1 || { echo "ERROR: rspamd not installed"; exit 1; }

mkdir -p "$RSPAMD_LOCAL"

# Milter worker: Postfix talks to rspamd directly
cat > "$RSPAMD_LOCAL/worker-proxy.inc" <<'CONF'
bind_socket = "127.0.0.1:11332";
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
CONF

# DKIM signing: efactl manages keys and configuration, never overwrite.
[ -f "$RSPAMD_LOCAL/dkim_signing.conf" ] || echo 'enabled = false;' > "$RSPAMD_LOCAL/dkim_signing.conf"

# DMARC: enforce the policy from DNS
cat > "$RSPAMD_LOCAL/dmarc.conf" <<'CONF'
# Enforce the DMARC policy from DNS: reject rejects, quarantine marks as spam.
# TODO: check the reporting option against the rspamd docs
actions {
  reject = "reject";
  quarantine = "add_header";
}
CONF

# The policy published in DNS decides, no separate brand list
cat > "$RSPAMD_LOCAL/whitelist_group.conf" <<'CONF'
symbols {
  "BLACKLIST_DMARC" {
    weight = 0.0;
  }
}
CONF

# Set Authentication-Results and X-Auth-Failed, optionally tag the subject
cat > "$RSPAMD_LOCAL/milter_headers.conf" <<'CONF'
use = ["authentication-results", "efa-auth-failed", "x-spam-status"];
custom {
  efa-auth-failed = <<EOD
return function(task, common_meta)
  local checks = {
    {'R_SPF_FAIL', 'spf=fail', true}, {'R_SPF_SOFTFAIL', 'spf=softfail'},
    {'R_SPF_PERMFAIL', 'spf=permerror'}, {'R_SPF_DNSFAIL', 'spf=temperror'},
    {'R_DKIM_REJECT', 'dkim=fail', true}, {'R_DKIM_PERMFAIL', 'dkim=permerror'}, {'R_DKIM_TEMPFAIL', 'dkim=temperror'},
    {'DMARC_POLICY_REJECT', 'dmarc=fail (p=reject)', true},
    {'DMARC_POLICY_QUARANTINE', 'dmarc=fail (p=quarantine)', true},
    {'DMARC_POLICY_SOFTFAIL', 'dmarc=fail (p=none)'}, {'DMARC_DNSFAIL', 'dmarc=temperror'},
  }
  local failed, hard = {}, false
  for _, c in ipairs(checks) do
    if task:has_symbol(c[1]) then
      failed[#failed + 1] = c[2]
      hard = hard or c[3]
    end
  end
  -- Senders must not be able to forge or hide the marker.
  local remove = {['X-Auth-Failed'] = 0}
  if #failed == 0 then return nil, {}, remove, {} end
  local add = {['X-Auth-Failed'] = table.concat(failed, ', ')}
  -- Softfail, temporary errors and p=none stay in the header only.
  if not hard then return nil, add, remove, {} end
  -- Subject tagging is active if the file contains text (written by efactl).
  local f = io.open('/etc/rspamd/efa-auth-subject-tag', 'r')
  if f then
    local tag = f:read('*l')
    f:close()
    if tag and tag ~= '' then
      add['Subject'] = tag .. ' ' .. (task:get_header_raw('Subject') or '')
      remove['Subject'] = 0
    end
  end
  return nil, add, remove, {}
end
EOD;
}
CONF

# Redis for Bayes, greylisting and DMARC reports
cat > "$RSPAMD_LOCAL/redis.conf" <<'CONF'
servers = "127.0.0.1";
CONF

# Virus scanning directly through clamd; the limits of efactl scan-limits-set (C7) stay
[ -f /etc/eFa/scan-limits.json ] || cat > "$RSPAMD_LOCAL/antivirus.conf" <<'CONF'
clamav {
  type = "clamav";
  servers = "/run/clamd.scan/clamd.sock";
  symbol = "CLAM_VIRUS";
  action = "reject";
  scan_mime_parts = false;
}
CONF

# Spam subject as before with MailScanner; changes from efactl are kept
[ -f "$RSPAMD_LOCAL/actions.conf" ] || cat > "$RSPAMD_LOCAL/actions.conf" <<'CONF'
rewrite_subject = 6;
subject = "{Spam?} %s";
CONF

# Bayes learns automatically
cat > "$RSPAMD_LOCAL/classifier-bayes.conf" <<'CONF'
autolearn = true;
CONF

# Internal senders like IgnoreHosts in opendmarc. override.d, because local.d only extends the
# rspamd default, which treats all private networks as internal.
mkdir -p /etc/rspamd/override.d
NETS="$(postconf -h mynetworks | tr ' ,' '\n' | grep -E '^[0-9]' | sed -E 's/.*/"&"/' | paste -sd, -)"
printf 'local_addrs = [%s];\n' "$NETS" > /etc/rspamd/override.d/options.inc

# Attachment rules and sender lists. The allow list only lowers the score,
# so DMARC and virus scanning still apply to allowed senders.
mkdir -p "$RSPAMD_LOCAL/maps.d"
[ -f "$RSPAMD_LOCAL/maps.d/efa-sender-allow.map" ] || : > "$RSPAMD_LOCAL/maps.d/efa-sender-allow.map"
[ -f "$RSPAMD_LOCAL/maps.d/efa-sender-block.map" ] || : > "$RSPAMD_LOCAL/maps.d/efa-sender-block.map"
cat > "$RSPAMD_LOCAL/maps.d/efa-bad-filenames.map" <<'CONF'
/.{150,}/i
/\.ico$/i
/\.ani$/i
/\.cur$/i
/pretty\s+park\.exe$/i
/happy99\.exe$/i
/\.ceo$/i
/webpage\.rar$/i
/\.cab$/i
/\.chm$/i
/\.cnf$/i
/\.hta$/i
/\.ins$/i
/\.jse?$/i
/\.job$/i
/\.lnk$/i
/\.ma[dfgmqrsvw]$/i
/\.pif$/i
/\.scf$/i
/\.sct$/i
/\.shb$/i
/\.shs$/i
/\.vb[es]$/i
/\.ws[cfh]$/i
/\.xnk$/i
/\.its$/i
/\.mau$/i
/\.md[az]$/i
/\.prf$/i
/\.pst$/i
/\.vsmacros$/i
/\.vs[stw]$/i
/\.ws$/i
/\.com$/i
/\.exe$/i
/\.scr$/i
/\.bat$/i
/\.cmd$/i
/\.cpl$/i
/\.mhtml$/i
/\{[a-hA-H0-9-]{25,}\}/i
/\s{10,}/i
/\.[a-z][a-z0-9]{2,3}\s*\.[a-z0-9]{3,4}$/i
CONF
cat > "$RSPAMD_LOCAL/multimap.conf" <<'CONF'
EFA_BAD_FILENAME {
  type = "filename";
  map = "$LOCAL_CONFDIR/local.d/maps.d/efa-bad-filenames.map";
  regexp = true;
  prefilter = true;
  action = "reject";
  message = "Attachment type not allowed";
}
EFA_SENDER_BLOCK {
  type = "from";
  filter = "email:addr";
  map = "$LOCAL_CONFDIR/local.d/maps.d/efa-sender-block.map";
  prefilter = true;
  action = "reject";
  message = "Sender blocked";
}
EFA_SENDER_ALLOW {
  type = "from";
  filter = "email:addr";
  map = "$LOCAL_CONFDIR/local.d/maps.d/efa-sender-allow.map";
  score = -6.0;
}
EFA_SENDER_BLOCK_DOMAIN {
  type = "from";
  filter = "email:domain";
  map = "$LOCAL_CONFDIR/local.d/maps.d/efa-sender-block.map";
  prefilter = true;
  action = "reject";
  message = "Sender blocked";
}
EFA_SENDER_ALLOW_DOMAIN {
  type = "from";
  filter = "email:domain";
  map = "$LOCAL_CONFDIR/local.d/maps.d/efa-sender-allow.map";
  score = -6.0;
}
CONF

# Sender rules the simple lists do not cover: IPs, patterns, only for certain recipients.
cat > /etc/rspamd/rspamd.local.lua <<'LUA'
local rules = {}
local f = io.open('/etc/rspamd/local.d/maps.d/efa-sender-rules.map', 'r')
local options = rspamd_config:get_all_opt('options') or {}
local relay_networks = options.local_addrs and require('lua_maps').map_add_from_ucl(options.local_addrs, 'radix', 'eFa-next relay networks')

local function matcher(text)
  text = text:lower()
  if not text:find('[@.:*]') then text = '*' .. text .. '*' end
  local pattern = text:gsub('[%^%$%(%)%%%.%[%]%+%-%?]', '%%%0'):gsub('%*', '.*')
  return '^' .. pattern .. '$'
end

if f then
  for line in f:lines() do
    local list, from, to = line:match('^(%a+)|([^|]+)|([^|]+)$')
    if list then
      rules[#rules + 1] = {list = list, from = matcher(from), to = to:lower()}
    end
  end
  f:close()
end

local function recipient_matches(to, rcpts)
  if to == 'default' then return true end
  if not rcpts or #rcpts == 0 then return false end
  -- shortcut: one verdict per mail, so a rule counts only if it fits every recipient; upgrade if mixed mail matters
  for _, r in ipairs(rcpts) do
    if (r.addr or ''):lower() ~= to and (r.domain or ''):lower() ~= to then return false end
  end
  return true
end

local function check(task)
  local from = task:get_from('smtp')
  local sender = from and from[1] and (from[1].addr or ''):lower() or ''
  local domain = from and from[1] and (from[1].domain or ''):lower() or ''
  local ip = task:get_from_ip()
  ip = ip and ip:is_valid() and ip:to_string() or ''
  local rcpts = task:get_recipients('smtp')
  for _, rule in ipairs(rules) do
    if (sender:match(rule.from) or domain:match(rule.from) or ip:match(rule.from)) and recipient_matches(rule.to, rcpts) then
      -- Own servers and authenticated users send with their own domain, that is not spoofing.
      local trusted = task:get_user() or (task:get_from_ip() and (task:get_from_ip():is_local()
        or (relay_networks and relay_networks:get_key(task:get_from_ip()))))
      if rule.list == 'block' and not trusted then
        task:insert_result('EFA_SENDER_RULE_BLOCK', 1.0)
        task:set_pre_result('reject', 'Sender blocked', 'efa_sender_rules')
        return
      end
      if rule.list == 'allow' then task:insert_result('EFA_SENDER_RULE_ALLOW', 1.0) end
    end
  end
end

rspamd_config:register_symbol({name = 'EFA_SENDER_RULE', type = 'prefilter', callback = check, priority = 10})
rspamd_config:register_symbol({name = 'EFA_SENDER_RULE_BLOCK', type = 'virtual', parent = -1, score = 0.0})
rspamd_config:register_symbol({name = 'EFA_SENDER_RULE_ALLOW', type = 'virtual', parent = -1, score = -6.0})
rspamd_config:set_metric_symbol({name = 'EFA_SENDER_RULE_ALLOW', score = -6.0, group = 'efa'})
LUA
: >> "$RSPAMD_LOCAL/maps.d/efa-sender-rules.map"

# Mail log: rspamd reports every mail to efa-maillog
cat > "$RSPAMD_LOCAL/metadata_exporter.conf" <<'CONF'
rules {
  EFA_MAILLOG {
    backend = "http";
    url = "http://127.0.0.1:8906/";
    formatter = "json";
    selector = "default";
  }
}
CONF

# SPF: rspamd module instead of pyspf
cat > "$RSPAMD_LOCAL/spf.conf" <<'CONF'
spf_cache_size = 1k;
CONF

# Valkey replaces Redis on EL10 (same port and protocol).
systemctl enable --now "$([ -e /usr/lib/systemd/system/valkey.service ] && echo valkey || echo redis)"
systemctl enable rspamd
systemctl restart rspamd
# rspamd replaces opendkim and opendmarc
systemctl disable --now opendkim opendmarc 2>/dev/null || true

# Switch the Postfix milters. Create a backup only if none exists yet,
# so a second run does not overwrite the original.
[ -f "$BACKUP" ] || cp "$MAIN_CF" "$BACKUP"

replace_milters() {
  # $1 = postconf parameter (smtpd_milters | non_smtpd_milters)
  OLD="$(postconf -h "$1" | tr -d ' ')"
  [ -n "$OLD" ] || return 0
  NEW="$(echo "$OLD" | tr ',' '\n' | awk '
    /127\.0\.0\.1:(8891|8893|11332)$/ { if (!done) { print "inet:127.0.0.1:11332"; done=1 }; next }
    { print }' | paste -sd, - | sed 's/,/, /g')"
  # Change only if opendkim/opendmarc are in this list
  echo "$OLD" | grep -q -E '127\.0\.0\.1:(8891|8893)$|127\.0\.0\.1:(8891|8893),' || return 0
  echo "$NEW" | grep -q 'inet:127.0.0.1:11332' || { echo "ERROR: rspamd not added to $1"; exit 1; }
  postconf -e "$1 = $NEW"
}

# rspamd must always be in the chain, even without opendkim/opendmarc enabled.
MILTERS="$(postconf -h smtpd_milters)"
case "$MILTERS" in
  *127.0.0.1:8891*|*127.0.0.1:8893*|*127.0.0.1:11332*) ;;
  *) postconf -e "smtpd_milters = inet:127.0.0.1:11332${MILTERS:+, $MILTERS}" ;;
esac

replace_milters smtpd_milters
replace_milters non_smtpd_milters

# Add the health milter if installed
if systemctl cat efa-milter-health >/dev/null 2>&1; then
  MILTERS="$(postconf -h smtpd_milters)"
  case "$MILTERS" in
    *127.0.0.1:8999*) ;;
    *) postconf -e "smtpd_milters = $MILTERS, inet:127.0.0.1:8999" ;;
  esac
fi

# milter_default_action is deliberately NOT changed; efa-milter-health marks outages.
postfix check
systemctl try-reload-or-restart postfix

echo "rspamd configuration (step 1) applied. Backup: $BACKUP. Test run required."
