#!/bin/bash

fail2ban() {
  # Update and install Fail2ban
  apt update && apt install -y fail2ban

  # Uncomment 'allowipv6 = auto' in fail2ban.conf
  sed -i 's/#allowipv6 = auto/allowipv6 = auto/g' /etc/fail2ban/fail2ban.conf

  # Change backend to systemd in jail.conf for Debian 12+
  sed -i '0,/action =/s/backend = auto/backend = systemd/' /etc/fail2ban/jail.conf

  # Declare Variables
  log_folder="${V2RAY_STAT_LOG_FOLDER:=/var/log}"
  iplimit_log_path="${log_folder}/v2ray-stat.log"
  iplimit_banned_log_path="${log_folder}/v2ray-stat-banned.log"

  # Use default bantime if not passed => 30 minutes
  local bantime="${1:-30}"

  # Check if log file exists
  if ! test -f "${iplimit_banned_log_path}"; then
    touch ${iplimit_banned_log_path}
  fi

  # Check if service log file exists so fail2ban won't return error
  if ! test -f "${iplimit_log_path}"; then
    touch ${iplimit_log_path}
  fi

  cat << EOF > /etc/fail2ban/jail.d/v2ray-stat.conf
[v2ray-stat]
enabled=true
backend=auto
filter=v2ray-stat
action=v2ray-stat
logpath=${iplimit_log_path}
maxretry=2
findtime=92
bantime=${bantime}m
EOF

  cat << EOF > /etc/fail2ban/filter.d/v2ray-stat.conf
[Definition]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
failregex   = \[LIMIT_IP\]\s*Email\s*=\s*<F-USER>.+</F-USER>\s*\|\|\s*SRC\s*=\s*<ADDR>
ignoreregex =
EOF

  cat << EOF > /etc/fail2ban/action.d/v2ray-stat.conf
[INCLUDES]
before = iptables-allports.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -j f2b-<name>

actionstop = <iptables> -D <chain> -p <protocol> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   BAN   [Email] = <F-USER> [IP] = <ip> banned for <bantime> seconds." >> ${iplimit_banned_log_path}

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
              echo "\$(date +"%%Y/%%m/%%d %%H:%%M:%%S")   UNBAN   [Email] = <F-USER> [IP] = <ip> unbanned." >> ${iplimit_banned_log_path}

[Init]
name = default
protocol = tcp
chain = INPUT
EOF

  systemctl restart fail2ban
}

fail2ban "$1"
