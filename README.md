NodeZero Setup Script

A single installer to prep a fresh Linux host for NodeZero.

What it does

Detects & supports: Ubuntu 20.04/22.04/24.04, Debian 11/12, AlmaLinux/Rocky/RHEL 9/10.

Installs essentials + Docker (CE, CLI, Compose plugin).

Configures MOTD/banner and SSH Banner/PrintMotd.

Prompts for an SSH public key (always creates ~/.ssh/authorized_keys).

Prompts for H3 API key (visible) and writes export H3_API_KEY="..." to ~/.bash_profile.

Creates ~/.h3 and /home/nodezeo/.h3.

Downloads h3-cli and the n0 utility; sets H3_CLI_HOME=$HOME/h3-cli and adds it to PATH.

Backs up & updates ~/.profile, ~/.bash_profile, ~/.bashrc, ~/.bash_logout (no sudo in login files).

Sets hostname to nodezero, enables NTP, adds user to docker group, reloads sshd, then reboots.

Disables ufw/firewalld and sets SELinux=permissive (RHEL-like).

⚠️ Security note: Firewall is disabled and SELinux relaxed. Use in controlled/lab environments or adjust the script before production use.

Quick start
curl -fsSLo nodezero-setup.sh https://raw.githubusercontent.com/tal-hash1/nodezero-setup/refs/heads/v1.0.0/nodezero-setup.sh chmod +x nodezero-setup.sh && ./nodezero-setup.sh


Interactive prompts

SSH key: paste a valid ssh-ed25519/ssh-rsa/ecdsa-sha2-* public key, or type skip.

H3 API key: visible input; saved to ~/.bash_profile as H3_API_KEY.

Environment knobs

ENFORCE_PUBKEY=1 → after adding a key, sets PasswordAuthentication no in sshd.

Files touched (backups with timestamps)

~/.profile, ~/.bash_profile, ~/.bashrc, ~/.bash_logout, ~/.ssh/authorized_keys, /etc/ssh/sshd_config, /etc/issue, /etc/issue.net, /etc/update-motd.d/* (Debian/Ubuntu), /usr/lib/motd.d/* (RHEL-like), /etc/nodezero-build.

Troubleshooting

Docker “permission denied”: log out/in (new group takes effect), or newgrp docker.

.bash_profile not applied: ensure a bash login shell; .profile covers non-bash shells.

Lost SSH password login (if ENFORCE_PUBKEY=1): console in, set PasswordAuthentication yes in sshd_config, restart sshd.
