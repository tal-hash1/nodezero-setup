#!/bin/bash

SCRIPT_VERSION="1959656877"

OS="UNKNOWN"
OS_FAMILY="UNKNOWN"   # "DEB" or "RHEL"
ID_LIKE_VAL=""
ID_VAL=""
VER="UNKNOWN"
VER_MAJOR="UNKNOWN"
CODENAME=""

USERNAME=$(whoami)
# if [ ! -z "$SUDO_USER" ]; then USERNAME=$SUDO_USER; fi

# Resolve the user's home directory robustly (works in su/sudo edge cases too)
home_dir="$(getent passwd "$USERNAME" | cut -d: -f6)"
[ -z "$home_dir" ] && home_dir="$(eval echo "~$USERNAME")"
[ -z "$home_dir" ] && home_dir="/home/$USERNAME"

banner_file="banner"
n0_utility="n0-ubuntu"
tmp_advisory_file="/tmp/update-motd-advisory"
tmp_banner_file="/tmp/${banner_file}"

download_url="https://downloads.horizon3ai.com"
download_cli_url="https://downloads.horizon3ai.com/utilities/cli/h3-cli.zip"
h3_cli_zip="h3cli.zip"
h3_cli="h3-cli"

# Colors
if which tput &>/dev/null; then
  BOLD=$(tput bold); NORMAL=$(tput sgr0)
  RED=$(tput setaf 1); YELLOW=$(tput setaf 3)
  MAGENTA=$(tput setaf 5); CYAN=$(tput setaf 6); WHITE=$(tput setaf 7)
fi
HeaderMsg(){ echo -ne "\n${BOLD}[${CYAN}+${NORMAL}${BOLD}]${CYAN} $@${NORMAL}\n"; }
InfoMsg(){ echo -ne "${BOLD}[${WHITE}+${NORMAL}${BOLD}]${WHITE} $@${NORMAL}\n"; }
FailMsg(){ echo -ne "${BOLD}[${RED}!${NORMAL}${BOLD}] ${RED}FAILED: $@${NORMAL}\n"; }
WarnMsg(){ echo -ne "${BOLD}[${YELLOW}!${NORMAL}${BOLD}] ${YELLOW}WARNING: $@${NORMAL}\n"; }
AskMsg(){ echo -ne "${BOLD}[${MAGENTA}-${NORMAL}${BOLD}] ${MAGENTA}CONFIRM: $@${NORMAL}"; }

# Guardrails
if [ "$USERNAME" == "root" ]; then FailMsg "Run as a non-root user with sudo privileges."; exit 1; fi
if [ ! -z "$SUDO_USER" ]; then FailMsg "Do not use 'sudo' to run this script; it will use sudo where needed."; exit 1; fi

yes_no_validation(){
  local question=$@
  AskMsg "$question (y|n)? "; read input
  lower_input=$(echo "$input" | tr '[:upper:]' '[:lower:]') &>/dev/null
  case $lower_input in
    "") return 0 ;; y|yes) return 1 ;; n|no) return 2 ;; q) exit 0 ;;
    *) FailMsg "Invalid option. Enter q to exit."; yes_no_validation $question;;
  esac
}

# Change/add a config line in sshd_config safely
set_sshd_config() {
  local key="$1" val="$2" file="${3:-/etc/ssh/sshd_config}"
  if [ ! -f "$file" ]; then sudo touch "$file"; sudo chmod 600 "$file"; fi
  if sudo grep -Eiq "^\s*#?\s*${key}\b" "$file"; then
    sudo sed -i -E "s|^\s*#?\s*${key}\b.*|${key} ${val}|g" "$file"
  else
    echo "${key} ${val}" | sudo tee -a "$file" >/dev/null
  fi
}

set_build(){
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    ID_VAL="${ID}"; ID_LIKE_VAL="${ID_LIKE}"
    OS="$NAME"; VER="$VERSION_ID"; VER_MAJOR="${VER%%.*}"
    CODENAME="${VERSION_CODENAME}"
  fi
  case "$ID_VAL" in
    ubuntu|debian) OS_FAMILY="DEB" ;;
    rhel|rocky|almalinux) OS_FAMILY="RHEL" ;;
    *)
      if echo "$ID_LIKE_VAL" | grep -qiE "(rhel|fedora|centos)"; then OS_FAMILY="RHEL"
      elif echo "$ID_LIKE_VAL" | grep -qi "debian"; then OS_FAMILY="DEB"
      else OS_FAMILY="UNKNOWN"; fi ;;
  esac

  if [ "$OS_FAMILY" = "RHEL" ]; then
    if ! [[ "$VER_MAJOR" =~ ^[0-9]+$ ]]; then
      FailMsg "Unrecognized version format: $VER"
      yes_no_validation "Continue anyway?"; [ $? -ne 1 ] && exit 1
    elif [ "$VER_MAJOR" -lt 9 ] || [ "$VER_MAJOR" -gt 10 ]; then
      FailMsg "Unsupported $OS version: $VER"
      yes_no_validation "Continue anyway?"; [ $? -ne 1 ] && exit 1
    fi
    BUILD="NodeZero-${SCRIPT_VERSION}-${OS}-${VER_MAJOR}"
  elif [ "$OS_FAMILY" = "DEB" ]; then
    if [ "$ID_VAL" = "ubuntu" ]; then
      case "$VER" in 20.04|22.04|24.04) : ;; *)
        FailMsg "Unsupported Ubuntu version: $VER"
        yes_no_validation "Continue anyway?"; [ $? -ne 1 ] && exit 1 ;;
      esac
    elif [ "$ID_VAL" = "debian" ]; then
      case "$VER_MAJOR" in 11|12) : ;; *)
        FailMsg "Unsupported Debian version: $VER"
        yes_no_validation "Continue anyway?"; [ $? -ne 1 ] && exit 1 ;;
      esac
    fi
    BUILD="NodeZero-${SCRIPT_VERSION}-${OS}-${VER}"
  else
    WarnMsg "Unsupported OS; proceeding with CUSTOM build."
    BUILD="NodeZero-${SCRIPT_VERSION}-CUSTOM"
  fi
}

download(){
  local filename=${1} destination=${2}
  local endpoint_url="${download_url}/utilities/${filename}"
  if ! curl -L -I ${endpoint_url} 2>&1 | grep "HTTP.*200" >/dev/null; then
    FailMsg "Failed to connect to ${endpoint_url}"; return 1; fi
  local tmpdir; tmpdir="$(mktemp -d)"
  pushd "${tmpdir}" >/dev/null
  rm -f ${filename}.*
  curl -s -o ${filename} ${endpoint_url} &>/dev/null
  curl -s -o ${filename}.sha256.checksum ${endpoint_url}.sha256.checksum &>/dev/null
  if sha256sum -c ${filename}.sha256.checksum &>/dev/null; then
    rm -f ${filename}.sha256.checksum
    sudo mv ${filename} ${destination}
    popd >/dev/null; rm -rf "${tmpdir}"
  else
    FailMsg "Checksum invalid for ${filename}"
    rm -f ${filename}.*
    popd >/dev/null; rm -rf "${tmpdir}"; exit 1
  fi
}

install_deb_packages(){
  local deb_id="$1"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -o Acquire::Check-Valid-Until=false -o Acquire::Check-Date=false --fix-missing
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    wget curl sudo nano openssh-server nmap tcpdump dnsutils unzip jq \
    net-tools cloud-init telnet traceroute zmap ca-certificates gnupg lsb-release
  # Docker repo
  sudo install -m 0755 -d /etc/apt/keyrings
  local distro_path codename
  if [ "$deb_id" = "ubuntu" ]; then distro_path="ubuntu"; codename="$VERSION_CODENAME"
  else distro_path="debian"; codename="$VERSION_CODENAME"; fi
  sudo curl -fsSL "https://download.docker.com/linux/${distro_path}/gpg" -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${distro_path} ${codename} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || { FailMsg "Docker install failed"; exit 1; }
  # Virtualization helpers
  if [ "$deb_id" = "ubuntu" ]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      linux-virtual linux-cloud-tools-virtual linux-tools-virtual \
      linux-cloud-tools-common linux-image-virtual open-vm-tools virtualbox-guest-utils ec2-instance-connect || true
  else
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends open-vm-tools || true
  fi
}

install_rhel_like_packages(){
  sudo dnf -y makecache || true
  sudo dnf upgrade -y || true
  sudo dnf distro-sync -y || true
  sudo dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %rhel).noarch.rpm" || true
  sudo dnf install -y wget curl sudo nano openssh-server nmap tcpdump bind-utils unzip jq net-tools cloud-init telnet traceroute
  sudo dnf install -y dnf-plugins-core
  sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || { FailMsg "Add docker-ce.repo failed"; exit 1; }
  sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || { FailMsg "Docker install failed"; exit 1; }
  sudo dnf install -y hyperv-daemons open-vm-tools || true
}

install_packages(){
  if [ "$OS_FAMILY" = "DEB" ]; then
    if [ "$ID_VAL" = "ubuntu" ] ; then install_deb_packages "ubuntu"; else install_deb_packages "debian"; fi
  elif [ "$OS_FAMILY" = "RHEL" ]; then
    install_rhel_like_packages
  else
    FailMsg "Unsupported OS family: $OS_FAMILY"; exit 1
  fi
}

configure_firewall(){
  if [ "$OS_FAMILY" = "DEB" ]; then
    sudo systemctl stop ufw || true; sudo systemctl disable ufw || true
  elif [ "$OS_FAMILY" = "RHEL" ]; then
    sudo systemctl stop firewalld || true; sudo systemctl disable firewalld || true
    if command -v setenforce >/dev/null 2>&1; then sudo setenforce 0 || true; fi
    if [ -f /etc/selinux/config ]; then sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config; fi
  fi
}

deb_special_sauce(){
  local banner_location=$1 advisory_location=$2
  local n0_ip_and_runners="nodezero-show-ip-and-runners"
  local n0_set_region="nodezero-set-region"
  local n0_gateway_connect="nodezero-gateway-connect"
  download ${n0_set_region} /etc/profile.d/20-nodezero-set-region.sh; sudo chmod +x /etc/profile.d/20-nodezero-set-region.sh
  download ${n0_ip_and_runners} /etc/profile.d/40-nodezero-show-ip-and-runners.sh; sudo chmod +x /etc/profile.d/40-nodezero-show-ip-and-runners.sh
  download ${n0_gateway_connect} /etc/profile.d/60-nodezero-gateway-connect.sh; sudo chmod +x /etc/profile.d/60-nodezero-gateway-connect.sh
  sudo mv ${banner_location} /etc/nodezero_banner
  sudo mkdir -p /etc/update-motd.d
  { echo "#!/bin/bash"; echo "cat /etc/nodezero_banner"; } | sudo tee /etc/update-motd.d/00-banner >/dev/null
  sudo chmod 755 /etc/update-motd.d/00-banner
  if [ -d /usr/lib/update-notifier ]; then
    sudo mv ${advisory_location} /usr/lib/update-notifier/update-motd-advisory; sudo chmod 755 /usr/lib/update-notifier/update-motd-advisory
    cat /usr/lib/update-notifier/update-motd-advisory | sudo tee /etc/issue >/dev/null
    cat /usr/lib/update-notifier/update-motd-advisory | sudo tee /etc/issue.net >/dev/null
    cat >/tmp/99-advisory <<'EOT'
#!/bin/bash
[ -x /usr/lib/update-notifier/update-motd-advisory ] && cat /usr/lib/update-notifier/update-motd-advisory
EOT
    sudo mv /tmp/99-advisory /etc/update-motd.d/99-advisory; sudo chmod 755 /etc/update-motd.d/99-advisory
  else
    sudo mv ${advisory_location} /etc/nodezero_advisory
    cat /etc/nodezero_advisory | sudo tee /etc/issue >/dev/null
    cat /etc/nodezero_advisory | sudo tee /etc/issue.net >/dev/null
    cat >/tmp/99-advisory <<'EOT'
#!/bin/bash
[ -f /etc/nodezero_advisory ] && cat /etc/nodezero_advisory
EOT
    sudo mv /tmp/99-advisory /etc/update-motd.d/99-advisory; sudo chmod 755 /etc/update-motd.d/99-advisory
  fi
  set_sshd_config "PrintMotd" "yes" "/etc/ssh/sshd_config"
  set_sshd_config "Banner" "/etc/issue.net" "/etc/ssh/sshd_config"
}

rhel_special_sauce(){
  local banner_location=$1 advisory_location=$2
  local n0_ip_and_runners="nodezero-show-ip-and-runners"
  local n0_set_region="nodezero-set-region"
  local n0_gateway_connect="nodezero-gateway-connect"
  download ${n0_set_region} /etc/profile.d/20-nodezero-set-region.sh; sudo chmod +x /etc/profile.d/20-nodezero-set-region.sh
  download ${n0_ip_and_runners} /etc/profile.d/40-nodezero-show-ip-and-runners.sh; sudo chmod +x /etc/profile.d/40-nodezero-show-ip-and-runners.sh
  download ${n0_gateway_connect} /etc/profile.d/60-nodezero-gateway-connect.sh; sudo chmod +x /etc/profile.d/60-nodezero-gateway-connect.sh
  sudo mv ${advisory_location} /usr/lib/motd.d/10-update-motd-advisory; sudo chmod 644 /usr/lib/motd.d/10-update-motd-advisory
  cat /usr/lib/motd.d/10-update-motd-advisory | sudo tee /etc/issue >/dev/null
  cat /usr/lib/motd.d/10-update-motd-advisory | sudo tee /etc/issue.net >/dev/null
  sudo mv ${banner_location} /usr/lib/motd.d/11-nodezero-banner; sudo chmod 644 /usr/lib/motd.d/11-nodezero-banner
  set_sshd_config "Banner" "/etc/issue.net" "/etc/ssh/sshd_config"
}

# --- Dotfiles ---

write_login_profiles_all() {
  local prof="$home_dir/.profile"
  local bprof="$home_dir/.bash_profile"
  local ts; ts=$(date +%Y%m%d%H%M%S)

read -r -d '' H3BLOCK <<'EOT'
# >>> H3_PROFILE_BLOCK (managed by NodeZero installer)
# Login shell init for bash/posix.

# If running bash, load .bashrc for interactive niceties
if [ -n "$BASH_VERSION" ]; then
  if [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
  fi
fi

# Append user bins to PATH
[ -d "$HOME/bin" ]        && PATH="$HOME/bin:$PATH"
[ -d "$HOME/.local/bin" ] && PATH="$HOME/.local/bin:$PATH"

export H3_CLI_HOME="$HOME/h3-cli"
export PATH="$H3_CLI_HOME/bin:$PATH"
# <<< H3_PROFILE_BLOCK
EOT

  # ~/.profile
  if [ -f "$prof" ]; then cp -a "$prof" "$prof.bak-$ts"; fi
  if ! grep -q '>>> H3_PROFILE_BLOCK' "$prof" 2>/dev/null; then
    touch "$prof"; printf "\n%s\n" "$H3BLOCK" >> "$prof"; InfoMsg "Updated $prof"
  else
    InfoMsg "H3 block already in $prof"
  fi

  # ~/.bash_profile (+ ensure it sources ~/.profile)
  if [ -f "$bprof" ]; then cp -a "$bprof" "$bprof.bak-$ts"; fi
  if ! grep -Eq '(^|\s)(\.|source)\s+("?\$HOME"?|~)/\.profile' "$bprof" 2>/dev/null; then
    printf '# Ensure .profile is sourced for login shells\n[ -r "$HOME/.profile" ] && . "$HOME/.profile"\n' >> "$bprof"
  fi
  if ! grep -q '>>> H3_PROFILE_BLOCK' "$bprof" 2>/dev/null; then
    touch "$bprof"; printf "\n%s\n" "$H3BLOCK" >> "$bprof"; InfoMsg "Updated $bprof"
  else
    InfoMsg "H3 block already in $bprof"
  fi

  chown "$USERNAME":"$USERNAME" "$prof" "$bprof" 2>/dev/null || true
}

ensure_bash_login_sources_profile() {
  local blogin="$home_dir/.bash_login"; [ ! -f "$blogin" ] && return 0
  local ts; ts=$(date +%Y%m%d%H%M%S)
  if grep -Eq '(^|\s)(\.|source)\s+("?\$HOME"?|~)/\.profile' "$blogin"; then
    InfoMsg ".bash_login already sources .profile; leaving it."
  else
    cp -a "$blogin" "$blogin.bak-$ts"
    printf '\n# Added by NodeZero installer\n[ -r "$HOME/.profile" ] && . "$HOME/.profile"\n' >> "$blogin"
    InfoMsg "Patched $blogin to source .profile"
  fi
}

write_bashrc(){
  local bashrc="$home_dir/.bashrc" ts; ts=$(date +%Y%m%d%H%M%S)
  if [ -f "$bashrc" ]; then cp -a "$bashrc" "${bashrc}.bak-${ts}"; InfoMsg "Backed up $bashrc"; fi
  cat > "$bashrc" <<'EOT'
# ~/.bashrc: executed by bash(1) for non-login shells.
case $- in *i*) ;; *) return;; esac

HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s checkwinsize
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
  debian_chroot=$(cat /etc/debian_chroot)
fi

case "$TERM" in xterm-color|*-256color) color_prompt=yes;; esac
if [ -n "$force_color_prompt" ]; then
  if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then color_prompt=yes; else color_prompt=; fi
fi
if [ "$color_prompt" = yes ]; then
  PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
  PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

case "$TERM" in
  xterm*|rxvt*) PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1" ;;
  *) ;;
esac

if [ -x /usr/bin/dircolors ]; then
  test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
  alias ls='ls --color=auto'
  alias grep='grep --color=auto'
  alias fgrep='fgrep --color=auto'
  alias egrep='egrep --color=auto'
fi

alias ll='ls -alF'; alias la='ls -A'; alias l='ls -CF'
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

[ -f ~/.bash_aliases ] && . ~/.bash_aliases

if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ] ; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ] ; then
    . /etc/bash_completion
  fi
fi
EOT
  chown "$USERNAME":"$USERNAME" "$bashrc" 2>/dev/null || true
  InfoMsg "Wrote new $bashrc"
}

write_bash_logout(){
  local logout_file="$home_dir/.bash_logout" ts; ts=$(date +%Y%m%d%H%M%S)
  if [ -f "$logout_file" ]; then cp -a "$logout_file" "${logout_file}.bak-${ts}"; InfoMsg "Backed up $logout_file"; fi
  cat > "$logout_file" <<'EOT'
# ~/.bash_logout: executed by bash(1) when login shell exits.
if [ "$SHLVL" = 1 ]; then
  [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
EOT
  chown "$USERNAME":"$USERNAME" "$logout_file" 2>/dev/null || true
  InfoMsg "Wrote new $logout_file"
}

warn_if_shell_not_bash() {
  local shell_path; shell_path="$(getent passwd "$USERNAME" | awk -F: '{print $7}')"
  if ! echo "$shell_path" | grep -q '/bash$'; then
    WarnMsg "User '$USERNAME' login shell is '$shell_path' (not bash). .bash_profile is ignored by non-bash shells. ~/.profile still applies."
  fi
}

# Create .h3 directories (user + exact /home/nodezeo)
create_h3_dirs() {
  mkdir -p "$home_dir/.h3"
  chmod 700 "$home_dir/.h3"
  chown -R "$USERNAME":"$USERNAME" "$home_dir/.h3" 2>/dev/null || true

  sudo mkdir -p "/home/nodezeo/.h3"
  sudo chmod 700 "/home/nodezeo/.h3"
  if id -u nodezeo >/dev/null 2>&1; then
    sudo chown -R nodezeo:nodezeo "/home/nodezeo/.h3"
  fi
  InfoMsg "Ensured .h3 directories exist."
}

# VISIBLE input; write/replace export H3_API_KEY in ~/.bash_profile
prompt_and_store_api_key() {
  local bprof="$home_dir/.bash_profile"
  local ts; ts=$(date +%Y%m%d%H%M%S)
  [ -f "$bprof" ] && cp -a "$bprof" "$bprof.bak-$ts"
  touch "$bprof"

  echo
  echo "Enter your H3 API key (visible input). Leave empty or type 'skip' to skip."
  printf "H3_API_KEY: "
  read -r key
  key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"

  if [ -z "$key" ] || [ "$key" = "skip" ] || [ "$key" = "SKIP" ]; then
    WarnMsg "No API key provided. Skipping H3_API_KEY export."
    return
  fi

  # Remove previous export, then append the new one
  if grep -qE '^\s*export\s+H3_API_KEY=' "$bprof"; then
    sed -i -E 's|^\s*export\s+H3_API_KEY=.*$||' "$bprof"
  fi
  printf 'export H3_API_KEY=%q\n' "$key" >> "$bprof"

  chmod 600 "$bprof" 2>/dev/null || true
  chown "$USERNAME":"$USERNAME" "$bprof" 2>/dev/null || true
  InfoMsg "H3_API_KEY exported in $bprof"
}

# Always create ~/.ssh/authorized_keys; then (optionally) add a key
install_authorized_keys() {
  local ssh_dir="$home_dir/.ssh"
  local auth_file="$ssh_dir/authorized_keys"

  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  touch "$auth_file"
  chmod 600 "$auth_file"

  echo
  echo "Paste an SSH PUBLIC key for '$USERNAME' (ssh-ed25519 / ssh-rsa / ecdsa-sha2-*)."
  echo "Press Enter to paste the single-line key, or type 'skip' to continue without adding a key."
  local key attempt=0
  while true; do
    printf "> "
    read -r key
    key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"
    if [ -z "$key" ] || [ "$key" = "skip" ] || [ "$key" = "SKIP" ]; then
      InfoMsg "Created $auth_file (empty). Add keys later with:  cat yourkey.pub >> \"$auth_file\""
      break
    fi
    if echo "$key" | grep -Eq '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+'; then
      if ! grep -qxF "$key" "$auth_file"; then
        printf "%s\n" "$key" >> "$auth_file"
        InfoMsg "Added SSH key to $auth_file"
      else
        InfoMsg "SSH key already present in $auth_file"
      fi
      break
    else
      attempt=$((attempt+1))
      FailMsg "That did not look like a valid SSH public key. Try again or type 'skip'."
      [ $attempt -ge 5 ] && { WarnMsg "Too many attempts; keeping $auth_file as-is."; break; }
    fi
  done

  chown -R "$USERNAME":"$USERNAME" "$ssh_dir" 2>/dev/null || true
  set_sshd_config "PubkeyAuthentication" "yes" "/etc/ssh/sshd_config"

  local ENFORCE_PUBKEY="${ENFORCE_PUBKEY:-0}"
  if [ "$ENFORCE_PUBKEY" = "1" ] && grep -qE '^(ssh-|ecdsa-)' "$auth_file"; then
    set_sshd_config "PasswordAuthentication" "no" "/etc/ssh/sshd_config"
    InfoMsg "PasswordAuthentication disabled (pubkey-only)."
  fi
}

# Change hostname to "nodezero" and adjust /etc/hosts
set_hostname_nodezero(){
  local new="nodezero" current; current=$(hostnamectl --static 2>/dev/null || hostname 2>/dev/null)
  [ "$current" = "$new" ] && { InfoMsg "Hostname already '$new'."; return; }
  InfoMsg "Setting hostname to '$new'..."
  sudo hostnamectl set-hostname "$new" || { FailMsg "hostnamectl failed"; return; }
  if [ "$OS_FAMILY" = "DEB" ]; then
    if grep -qE '^\s*127\.0\.1\.1\b' /etc/hosts; then sudo sed -i -E "s|^(\s*127\.0\.1\.1\s+).*|\1${new}|g" /etc/hosts
    else echo "127.0.1.1 ${new}" | sudo tee -a /etc/hosts >/dev/null; fi
    [ -n "$current" ] && sudo sed -i -E "s/\b${current}\b/${new}/g" /etc/hosts
  else
    if grep -qE "^\s*127\.0\.0\.1\b.*\b${current}\b" /etc/hosts; then sudo sed -i -E "s/\b${current}\b/${new}/g" /etc/hosts
    elif ! grep -qE "\b${new}\b" /etc/hosts; then echo "127.0.0.1 ${new}" | sudo tee -a /etc/hosts >/dev/null; fi
  fi
  InfoMsg "Hostname set to '$new'."
}

# ---------------- Main ----------------
set_build
echo; echo "> Build Version: ${BUILD}"
echo "${BUILD}" > /tmp/nodezero-build
sudo bash -c 'mv /tmp/nodezero-build /etc/nodezero-build'
echo "> Detected OS: $OS $VER (family: $OS_FAMILY)"
echo "> Home Directory: $home_dir"

echo; echo "> Disabling journald (to reduce disk usage)..."
sudo systemctl stop systemd-journald &>/dev/null || true
sudo systemctl disable systemd-journald &>/dev/null || true

echo; echo "> Disabling OS firewall / relaxing SELinux..."
configure_firewall

echo; echo "> Updating OS packages..."
install_packages

# Enable NTP here (not in user profile)
if command -v timedatectl >/dev/null 2>&1; then sudo timedatectl set-ntp true || true; fi

# Download the NodeZero banner
download ${banner_file} ${tmp_banner_file}

# Advisory content
cat > ${tmp_advisory_file} << 'EOT'


WARNING : Unauthorized access to this system is forbidden and will be
prosecuted by law. By accessing this system, you agree that your actions
may be monitored if unauthorized usage is suspected.


EOT

# MOTD/Banner per family
if [ "$OS_FAMILY" = "DEB" ]; then
  deb_special_sauce $tmp_banner_file $tmp_advisory_file
elif [ "$OS_FAMILY" = "RHEL" ]; then
  rhel_special_sauce $tmp_banner_file $tmp_advisory_file
fi

# Shell dotfiles (backups + writes)
write_login_profiles_all
ensure_bash_login_sources_profile
write_bashrc
write_bash_logout
warn_if_shell_not_bash

# Create .h3 directories
create_h3_dirs

# SSH public key prompt/install (always creates authorized_keys)
install_authorized_keys

# API key prompt -> export H3_API_KEY in ~/.bash_profile (visible input)
prompt_and_store_api_key

# Hostname -> nodezero
set_hostname_nodezero

# Fetch h3-cli
CURRENT_DIR=$(pwd)
echo "> Switching to ${home_dir} to download h3-cli..."
cd "$home_dir" || { FailMsg "Cannot cd to ${home_dir}"; exit 1; }

echo; echo "> Checking connection to downloads.horizon3ai.com..."
if curl -L -I ${download_cli_url} 2>&1 | grep "HTTP.*200" >/dev/null; then
  [ -d ${h3_cli} ] && { echo "> Removing existing h3-cli..."; rm -rf ${h3_cli}; }
  echo "> Downloading h3-cli..."; curl -L ${download_cli_url} -o ${h3_cli_zip} || { FailMsg "h3-cli download failed"; exit 1; }
  echo "> Unzipping h3-cli..."; unzip ${h3_cli_zip} -d ${h3_cli} &>/dev/null || { FailMsg "h3-cli unzip failed"; exit 1; }
  rm -f ${h3_cli_zip}
else
  echo; echo -e "${RED}ERROR: Failed to connect to ${download_url}${NORMAL}"
  echo -e "${RED}ERROR: Unable to download latest h3-cli${NORMAL}"
fi

echo; echo "> Downloading n0 utility script..."
download ${n0_utility} /tmp/${n0_utility} || { echo -e "${RED}ERROR: Unable to download ${n0_utility}${NORMAL}"; exit 1; }
sudo mv /tmp/${n0_utility} /usr/local/bin/n0
sudo chmod a+rx /usr/local/bin/n0

echo; echo "> Enabling Docker..."
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker "$USERNAME"

# Apply sshd changes (support both service names)
sudo systemctl reload sshd 2>/dev/null || \
sudo systemctl reload ssh  2>/dev/null || \
sudo systemctl restart sshd 2>/dev/null || \
sudo systemctl restart ssh  2>/dev/null || true

echo "> Rebooting system to apply changes..."
secs=10; while [ $secs -gt 0 ]; do echo -ne "$secs\n"; sleep 1; : $((secs--)); done
sudo reboot