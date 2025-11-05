#!/bin/bash

# ABOUTME: Creates a temporary Ubuntu EC2 terminal with SSH and NoVNC access.
# ABOUTME: On Ctrl+C, terminates the instance and deletes all related resources.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
STATE_FILE="$SCRIPT_DIR/.aws-terminal-state"

# Defaults (will be overridden by .env or prompts)
AWS_REGION="us-west-2"
INSTANCE_TYPE="t3.small"
DISPLAY_GEOMETRY="1920x1080"
NO_VNC_PORT="6080"
VNC_DISPLAY=":1" # VNC :1 -> TCP 5901
AMI_ID=""        # Resolved to latest Ubuntu 22.04
USE_PRESET=1     # Build and use a pre-baked AMI for fast startup
CUSTOM_AMI_ID=""
CUSTOM_AMI_NAME="awsterminal-preset-ubuntu-22.04-v1"
PRESET_FORCE_REBUILD=0

KEY_NAME="temp-terminal-key-$(date +%s)"
SECURITY_GROUP_NAME="temp-terminal-sg-$(date +%s)"
INSTANCE_NAME="temp-terminal-$(date +%Y%m%d-%H%M%S)"
TARGET_AZ=""
USE_ENC_VOL=0
VOL_NAME=""
VOL_SIZE_GB=
CLEANUP_CALLED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" 1>&2; }
log_stage() { echo -e "\033[0;36m[STAGE]\033[0m $*"; }

require_bin() {
	command -v "$1" >/dev/null 2>&1 || {
		log_error "Missing dependency: $1"
		return 1
	}
}

# Verify PEM file exists, non-empty, and ssh-keygen can read it
is_valid_pem() {
    local pem="$1"
    [ -s "$pem" ] || return 1
    ssh-keygen -y -f "$pem" >/dev/null 2>&1
}

prompt_value() {
	local prompt="$1" default="$2" var
	read -p "$prompt [$default]: " var || true
	echo "${var:-$default}"
}

validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
validate_geometry() { [[ "$1" =~ ^[0-9]+x[0-9]+$ ]]; }

write_env() {
	cat >"$ENV_FILE" <<EOF
# ABOUTME: Configuration for aws-terminal-run.sh (region/type/geometry/port)
# ABOUTME: Values are read on startup to provision the temporary terminal.
AWS_REGION="$AWS_REGION"
INSTANCE_TYPE="$INSTANCE_TYPE"
DISPLAY_GEOMETRY="$DISPLAY_GEOMETRY"
NO_VNC_PORT="$NO_VNC_PORT"
USE_PRESET="$USE_PRESET"
CUSTOM_AMI_ID="$CUSTOM_AMI_ID"
CUSTOM_AMI_NAME="$CUSTOM_AMI_NAME"
PRESET_FORCE_REBUILD="$PRESET_FORCE_REBUILD"
USE_ENC_VOL="1"
VOL_SIZE_GB="${VOL_SIZE_GB}"
EOF
	log_info "Saved configuration to $ENV_FILE"
}

update_env_kv() {
	local k="$1" v="$2"
	if [ -f "$ENV_FILE" ]; then
		if grep -q "^${k}=" "$ENV_FILE"; then
			awk -F= 'BEGIN{OFS="="} $1=="'"$k"'"{$2="'"$v"'";print;next} {print}' "$ENV_FILE" >"$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
		else
			echo "${k}=${v}" >>"$ENV_FILE"
		fi
	else
		echo "${k}=${v}" >"$ENV_FILE"
	fi
}

price_hour() {
	local region="$1" itype="$2"
	aws pricing get-products --region us-east-1 --service-code AmazonEC2 --filters Type=TERM_MATCH,Field=instanceType,Value=$itype Type=TERM_MATCH,Field=regionCode,Value=$region Type=TERM_MATCH,Field=operatingSystem,Value=Linux Type=TERM_MATCH,Field=tenancy,Value=Shared Type=TERM_MATCH,Field=preInstalledSw,Value=NA Type=TERM_MATCH,Field=capacitystatus,Value=Used --query 'PriceList' --output json | jq -r 'map(fromjson)[]? | .terms.OnDemand | to_entries[]? | .value.priceDimensions | to_entries[]? | .value.pricePerUnit.USD' | head -n1
}

select_region() {
	local list
	list=($(aws ec2 describe-regions --all-regions --query "Regions[?OptInStatus=='opt-in-not-required' || OptInStatus=='opted-in'].RegionName" --output text))
	echo "사용 가능한 리전:"
	local i=1
	for r in "${list[@]}"; do
		printf " %2d) %s\n" "$i" "$r"
		i=$((i + 1))
	done
	read -p "리전 선택(번호 또는 코드) [$AWS_REGION]: " sel
	sel=${sel:-$AWS_REGION}
	if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#list[@]} ]; then AWS_REGION="${list[$((sel - 1))]}"; else AWS_REGION="$sel"; fi
}

select_instance_type() {
	local candidates=(t3.small t3.medium t3.large t3.xlarge t3a.medium m5.large m5.xlarge c6i.xlarge) p ph pd idx=1
	echo "추천 인스턴스 (대략 1일 비용):"
	for it in "${candidates[@]}"; do
		p=$(price_hour "$AWS_REGION" "$it" || true)
		ph=${p:-}
		if [[ "$ph" =~ ^[0-9.]+$ ]]; then
			pd=$(awk -v v="$ph" 'BEGIN{printf "%.4f", v*24}')
			printf " %2d) %-11s ~ $%s/day\n" "$idx" "$it" "$pd"
		else printf " %2d) %-11s ~ N/A\n" "$idx" "$it"; fi
		idx=$((idx + 1))
	done
	read -p "인스턴스 타입 선택(번호 또는 타입) [$INSTANCE_TYPE]: " s
	s=${s:-$INSTANCE_TYPE}
	if [[ "$s" =~ ^[0-9]+$ ]] && [ "$s" -ge 1 ] && [ "$s" -le ${#candidates[@]} ]; then INSTANCE_TYPE="${candidates[$((s - 1))]}"; else INSTANCE_TYPE="$s"; fi
}

# Always enable encrypted volume, no prompt
prompt_encrypted_volume() {
    USE_ENC_VOL=1
    update_env_kv USE_ENC_VOL 1
}

# Ensure encrypted volume size is set; ask once and persist
ensure_enc_volume_config() {
    USE_ENC_VOL=1
    update_env_kv USE_ENC_VOL 1
    # If VOL_SIZE_GB not set or invalid, ask once and save
    if ! [[ "${VOL_SIZE_GB:-}" =~ ^[0-9]+$ ]] || [ "${VOL_SIZE_GB:-0}" -le 0 ]; then
        echo "암호화 데이터 볼륨 용량을 선택하세요: 1)32 2)64 3)128 4)256 (GB)"
        read -p "선택 [2]: " s
        s=${s:-2}
        case "$s" in
            1) VOL_SIZE_GB=32 ;;
            2) VOL_SIZE_GB=64 ;;
            3) VOL_SIZE_GB=128 ;;
            4) VOL_SIZE_GB=256 ;;
            *) VOL_SIZE_GB=64 ;;
        esac
        update_env_kv VOL_SIZE_GB "$VOL_SIZE_GB"
        log_info "Encrypted data volume size set: ${VOL_SIZE_GB}GB (saved to .env)"
    fi
}

derive_volume_from_key() {
	local pem="$SCRIPT_DIR/${KEY_NAME}.pem"
	if ! is_valid_pem "$pem"; then
		log_error "Invalid or empty PEM: $pem"
		echo "해결: .env의 KEY_NAME를 새로 생성하도록 변경하거나, AWS에서 해당 키 페어를 삭제 후 재생성하세요."
		return 1
	fi
	local hash short
	hash=$(shasum -a 256 "$pem" | awk '{print $1}')
	VOL_PASS="$hash"
	short=$(printf "%s" "$hash" | cut -c1-12)
	VOL_NAME="temp-terminal-enc-$short"
	echo "볼륨 이름: $VOL_NAME"
}

find_existing_volume() {
	[ "$USE_ENC_VOL" -eq 1 ] || return 1
	VOLUME_ID=$(aws ec2 describe-volumes --region "$AWS_REGION" --filters Name=tag:Name,Values="$VOL_NAME" Name=status,Values=available,in-use --query 'Volumes[0].VolumeId' --output text 2>/dev/null || echo None)
	if [ -n "$VOLUME_ID" ] && [ "$VOLUME_ID" != "None" ]; then
		VOLUME_AZ=$(aws ec2 describe-volumes --region "$AWS_REGION" --volume-ids "$VOLUME_ID" --query 'Volumes[0].AvailabilityZone' --output text)
		TARGET_AZ="$VOLUME_AZ"
		return 0
	fi
	return 1
}

load_or_init_env() { if [ -f "$ENV_FILE" ]; then
	set -a
	. "$ENV_FILE"
	set +a
	AWS_REGION="${AWS_REGION:-us-west-2}"
	INSTANCE_TYPE="${INSTANCE_TYPE:-t3.small}"
	DISPLAY_GEOMETRY="${DISPLAY_GEOMETRY:-1920x1080}"
	NO_VNC_PORT="${NO_VNC_PORT:-6080}"
	USE_PRESET="${USE_PRESET:-1}"
	CUSTOM_AMI_ID="${CUSTOM_AMI_ID:-}"
	CUSTOM_AMI_NAME="${CUSTOM_AMI_NAME:-$CUSTOM_AMI_NAME}"
    PRESET_FORCE_REBUILD="${PRESET_FORCE_REBUILD:-0}"
    VOL_SIZE_GB="${VOL_SIZE_GB:-$VOL_SIZE_GB}"
	log_info "Loaded configuration from $ENV_FILE"
else
	echo "초기 설정을 진행합니다 (.env 생성)."
	select_region
	select_instance_type
	local g
	g=$(prompt_value "Display Geometry (WIDTHxHEIGHT)" "$DISPLAY_GEOMETRY")
	validate_geometry "$g" && DISPLAY_GEOMETRY="$g" || log_warn "Invalid geometry; using $DISPLAY_GEOMETRY"
	local p
	p=$(prompt_value "NoVNC Port" "$NO_VNC_PORT")
	validate_port "$p" && NO_VNC_PORT="$p" || log_warn "Invalid port; using $NO_VNC_PORT"
	USE_PRESET=1
	write_env
fi; }

check_dependencies() {
	log_info "Checking dependencies..."
	for b in aws jq base64 curl; do require_bin "$b"; done
	aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1 || {
		log_error "AWS credentials not configured or invalid (region=$AWS_REGION)."
		exit 1
	}
	log_info "Dependencies OK."
}

get_my_ip() {
	MY_IP=$(curl -fsS https://checkip.amazonaws.com | tr -d '\n' || true)
	[ -n "${MY_IP:-}" ] || {
		log_error "Unable to determine public IP via checkip.amazonaws.com"
		exit 1
	}
	echo "$MY_IP"
}

get_latest_ubuntu_ami() {
	log_info "Resolving latest Ubuntu 22.04 AMI in $AWS_REGION..."
	AMI_ID=$(aws ec2 describe-images --region "$AWS_REGION" --owners 099720109477 --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" "Name=state,Values=available" --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)
	[ -n "$AMI_ID" ] && [ "$AMI_ID" != "None" ] || {
		log_error "Failed to find Ubuntu 22.04 AMI."
		exit 1
	}
	log_info "AMI: $AMI_ID"
}

create_key_pair() {
    # Reuse if AWS key and local PEM both exist and PEM is valid
    if aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
        local pem="$SCRIPT_DIR/${KEY_NAME}.pem"
        if [ -f "$pem" ] && is_valid_pem "$pem"; then
            chmod 600 "$pem" || true
            log_info "Reusing existing key pair: $KEY_NAME"
            echo "KEY_NAME=$KEY_NAME" >>"$STATE_FILE"
            return 0
        fi
        if [ -f "$pem" ] && ! is_valid_pem "$pem"; then
            log_warn "Local PEM exists but invalid: $pem"
        else
            log_warn "AWS key pair exists but local PEM missing: $KEY_NAME"
        fi
        # Pick a new unique key name to avoid collision and preserve flow
        local new_name="${KEY_NAME}-$(date +%s)"
        log_info "Creating a new key pair instead: $new_name"
        KEY_NAME="$new_name"
    fi

    log_info "Creating temporary key pair: $KEY_NAME"
    aws ec2 create-key-pair --key-name "$KEY_NAME" --region "$AWS_REGION" --query 'KeyMaterial' --output text >"$SCRIPT_DIR/${KEY_NAME}.pem"
    chmod 600 "$SCRIPT_DIR/${KEY_NAME}.pem"
    echo "KEY_NAME=$KEY_NAME" >>"$STATE_FILE"
    # Persist key name in .env for user visibility
    if [ -f "$ENV_FILE" ]; then
        if grep -q '^KEY_NAME=' "$ENV_FILE"; then
            awk -F= 'BEGIN{OFS="="} $1=="KEY_NAME"{$2="'"$KEY_NAME"'";print;next} {print}' "$ENV_FILE" >"$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
        else
            echo "KEY_NAME=$KEY_NAME" >>"$ENV_FILE"
        fi
    else
        echo "KEY_NAME=$KEY_NAME" >"$ENV_FILE"
    fi
}

create_security_group() {
	log_info "Creating security group..."
	VPC_ID=$(aws ec2 describe-vpcs --region "$AWS_REGION" --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text)
	SG_ID=$(aws ec2 create-security-group --group-name "$SECURITY_GROUP_NAME" --description "Temporary terminal security group" --vpc-id "$VPC_ID" --region "$AWS_REGION" --query 'GroupId' --output text)
	MY_IP=$(get_my_ip)
	aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr "${MY_IP}/32" --region "$AWS_REGION" >/dev/null
	aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port "$NO_VNC_PORT" --cidr "${MY_IP}/32" --region "$AWS_REGION" >/dev/null
	echo "SECURITY_GROUP_ID=$SG_ID" >>"$STATE_FILE"
	log_info "Security group created: $SG_ID (22,$NO_VNC_PORT open to $MY_IP/32)"
}

generate_vnc_password() { echo "$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)"; }

attach_and_mount_volume() {
    [ "$USE_ENC_VOL" -eq 1 ] || return 0
    INSTANCE_AZ=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)
    if [ -z "${VOLUME_ID:-}" ] || [ "$VOLUME_ID" = "None" ]; then
        VOLUME_ID=$(aws ec2 describe-volumes --region "$AWS_REGION" --filters Name=tag:Name,Values="$VOL_NAME" Name=status,Values=available,in-use --query 'Volumes[0].VolumeId' --output text 2>/dev/null || echo None)
    fi
	if [ -n "$VOLUME_ID" ] && [ "$VOLUME_ID" != "None" ]; then
		VOLUME_AZ=$(aws ec2 describe-volumes --region "$AWS_REGION" --volume-ids "$VOLUME_ID" --query 'Volumes[0].AvailabilityZone' --output text)
		ATTACHED_TO=$(aws ec2 describe-volumes --region "$AWS_REGION" --volume-ids "$VOLUME_ID" --query 'Volumes[0].Attachments[0].InstanceId' --output text 2>/dev/null || echo None)
		if [ "$VOLUME_AZ" != "$INSTANCE_AZ" ]; then
			log_warn "Existing encrypted volume in different AZ ($VOLUME_AZ). Creating a new one in $INSTANCE_AZ."
			VOLUME_ID=""
		elif [ -n "$ATTACHED_TO" ] && [ "$ATTACHED_TO" != "None" ] && [ "$ATTACHED_TO" != "$INSTANCE_ID" ]; then
			echo "볼륨이 다른 인스턴스($ATTACHED_TO)에 연결되어 있습니다. 분리 후 연결할까요? (y/N): "
			read -r yn
			[[ "$yn" =~ ^[Yy]$ ]] || return 1
			aws ec2 detach-volume --volume-id "$VOLUME_ID" --region "$AWS_REGION" >/dev/null || true
			aws ec2 wait volume-available --volume-ids "$VOLUME_ID" --region "$AWS_REGION" 2>/dev/null || true
		fi
	fi
    if [ -z "${VOLUME_ID:-}" ] || [ "$VOLUME_ID" = "None" ]; then
        # Ensure VOL_SIZE_GB is available (ask once earlier)
        if ! [[ "${VOL_SIZE_GB:-}" =~ ^[0-9]+$ ]] || [ "${VOL_SIZE_GB:-0}" -le 0 ]; then
            VOL_SIZE_GB=64
            update_env_kv VOL_SIZE_GB "$VOL_SIZE_GB"
        fi
        log_info "Creating encrypted EBS volume: size=${VOL_SIZE_GB}GB az=${INSTANCE_AZ}"
        VOLUME_ID=$(aws ec2 create-volume --size "$VOL_SIZE_GB" --availability-zone "$INSTANCE_AZ" --volume-type gp3 --encrypted \
            --tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=$VOL_NAME},{Key=Purpose,Value=temp-terminal-enc}]" \
            --region "$AWS_REGION" --query 'VolumeId' --output text)
        aws ec2 wait volume-available --volume-ids "$VOLUME_ID" --region "$AWS_REGION"
    fi
	echo "VOLUME_ID=$VOLUME_ID" >>"$STATE_FILE"
	echo "VOLUME_NAME=$VOL_NAME" >>"$STATE_FILE"
	aws ec2 attach-volume --volume-id "$VOLUME_ID" --instance-id "$INSTANCE_ID" --device /dev/sdf --region "$AWS_REGION" >/dev/null
	aws ec2 wait volume-in-use --volume-ids "$VOLUME_ID" --region "$AWS_REGION" 2>/dev/null || true
	# Remote mount with LUKS; passphrase via STDIN (no echo)
	ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SCRIPT_DIR/${KEY_NAME}.pem" ubuntu@"$PUBLIC_IP" \
		"set -e; DEV=\$(readlink -f /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${VOLUME_ID} 2>/dev/null || echo /dev/xvdf); read -rs PASS; sudo apt-get update >/dev/null 2>&1 || true; command -v cryptsetup >/dev/null 2>&1 || sudo apt-get install -y cryptsetup >/dev/null 2>&1; if ! sudo test -b \"\$DEV\"; then DEV=/dev/xvdf; fi; if ! sudo test -b \"\$DEV\"; then DEV=/dev/nvme1n1; fi; if ! sudo cryptsetup isLuks \"\$DEV\" >/dev/null 2>&1; then umask 077; printf '%s' \"\$PASS\" | sudo tee /dev/shm/.luks.pass >/dev/null; sudo cryptsetup luksFormat --type luks2 -q \"\$DEV\" -d /dev/shm/.luks.pass; else umask 077; printf '%s' \"\$PASS\" | sudo tee /dev/shm/.luks.pass >/dev/null; fi; sudo cryptsetup luksOpen \"\$DEV\" cryptlocal -d /dev/shm/.luks.pass; sudo rm -f /dev/shm/.luks.pass; if ! sudo blkid /dev/mapper/cryptlocal >/dev/null 2>&1; then sudo mkfs.ext4 -F /dev/mapper/cryptlocal >/dev/null; fi; sudo mkdir -p /mnt/local; sudo mount /dev/mapper/cryptlocal /mnt/local || true" <<<"$VOL_PASS"
	unset VOL_PASS
}

create_user_data_script() {
	local vnc_pass="$1"
	cat <<EOF
#!/bin/bash
set -euxo pipefail
trap 'echo "[UD] ERROR at line $LINENO"' ERR
exec > >(tee -a /var/log/terminal-setup.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
echo "[UD] Begin full-setup"
echo "[UD] Install desktop + vnc + novnc"
apt-get update && apt-get install -y \
  xfce4 xfce4-goodies xfce4-terminal xterm dbus-x11 software-properties-common \
  tightvncserver novnc websockify \
  xdg-utils exo-utils autocutsel xclip \
  x11-apps xauth xfonts-base fontconfig cryptsetup wget gpg

# Install CJK fonts for proper Korean/JP/CN rendering
echo "[UD] Install CJK fonts"
apt-get install -y fonts-noto-cjk fonts-noto-cjk-extra fonts-nanum fonts-noto-color-emoji || true
fc-cache -f -v || true

# Prefer Firefox ESR (deb) over Snap firefox, and install Chrome as fallback
echo "[UD] Configure browsers"
snap remove firefox >/dev/null 2>&1 || true
add-apt-repository -y ppa:mozillateam/ppa || true
apt-get update || true
apt-get install -y firefox-esr || true

# Install Google Chrome stable from official repo
if [ ! -f /usr/share/keyrings/google-chrome.gpg ]; then
  echo "[UD] Add Google Chrome key"
  wget -qO- https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor | tee /usr/share/keyrings/google-chrome.gpg >/dev/null
fi
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list
apt-get update && apt-get install -y google-chrome-stable || true

echo "[UD] Configure VNC for ubuntu user"
VNC_HOME="/home/ubuntu"
install -o ubuntu -g ubuntu -d "\$VNC_HOME/.vnc"
printf '%s' "$vnc_pass" | vncpasswd -f > "\$VNC_HOME/.vnc/passwd"
chown ubuntu:ubuntu "\$VNC_HOME/.vnc/passwd"
chmod 600 "\$VNC_HOME/.vnc/passwd"
cat > "\$VNC_HOME/.vnc/xstartup" <<'XSU'
#!/bin/sh
export MOZ_DISABLE_RDD_SANDBOX=1
export MOZ_ENABLE_WAYLAND=0
[ -f "$HOME/.Xresources" ] && xrdb "$HOME/.Xresources"
autocutsel -fork -selection CLIPBOARD
autocutsel -fork -selection PRIMARY
if command -v startxfce4 >/dev/null 2>&1; then
  dbus-launch --exit-with-session startxfce4 &
else
  xterm &
fi
XSU
chown ubuntu:ubuntu "\$VNC_HOME/.vnc/xstartup"
chmod +x "\$VNC_HOME/.vnc/xstartup"
echo "[UD] Starting vncserver as ubuntu..."
sudo -u ubuntu -H bash -lc 'vncserver '"$VNC_DISPLAY"' -geometry '"$DISPLAY_GEOMETRY"' -depth 24'
echo "[UD] Starting websockify on $NO_VNC_PORT -> 5901"
websockify -D --web=/usr/share/novnc/ $NO_VNC_PORT localhost:5901 || true
ss -tulpn || true
touch /tmp/terminal-ready
echo "[UD] Full-setup done"
EOF
}

# Lightweight runtime user-data (for preset AMI): ensure tools exist, set VNC password and start services
create_runtime_user_data() {
	local vnc_pass="$1"
	cat <<EOF
#!/bin/bash
set -euxo pipefail
trap 'echo "[UD] ERROR at line $LINENO"' ERR
exec > >(tee -a /var/log/terminal-setup.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
echo "[UD] Begin runtime-setup"
if ! command -v vncserver >/dev/null 2>&1; then
  echo "[UD] Installing vnc + deps"
  until apt-get update; do sleep 2; done
  apt-get install -y tightvncserver autocutsel xclip xauth xfonts-base fontconfig dbus-x11 xterm || true
fi
if ! command -v websockify >/dev/null 2>&1; then
  echo "[UD] Installing novnc/websockify"
  until apt-get update; do sleep 2; done
  apt-get install -y novnc websockify || true
fi
echo "[UD] Ensure CJK fonts present"
if ! command -v fc-list >/dev/null 2>&1; then
  until apt-get update; do sleep 2; done
  apt-get install -y fontconfig || true
fi
if ! fc-list | grep -qi "Noto.*CJK"; then
  until apt-get update; do sleep 2; done
  apt-get install -y fonts-noto-cjk fonts-noto-cjk-extra fonts-nanum fonts-noto-color-emoji || true
  fc-cache -f -v || true
fi
echo "[UD] Configure VNC for ubuntu user"
VNC_HOME="/home/ubuntu"
install -o ubuntu -g ubuntu -d "\$VNC_HOME/.vnc"
printf '%s' "$vnc_pass" | vncpasswd -f > "\$VNC_HOME/.vnc/passwd"
chown ubuntu:ubuntu "\$VNC_HOME/.vnc/passwd"
chmod 600 "\$VNC_HOME/.vnc/passwd"
if [ ! -f "\$VNC_HOME/.vnc/xstartup" ]; then
cat > "\$VNC_HOME/.vnc/xstartup" <<'XSU'
#!/bin/sh
export MOZ_DISABLE_RDD_SANDBOX=1
export MOZ_ENABLE_WAYLAND=0
[ -f "$HOME/.Xresources" ] && xrdb "$HOME/.Xresources"
autocutsel -fork -selection CLIPBOARD
autocutsel -fork -selection PRIMARY
if command -v startxfce4 >/dev/null 2>&1; then
  dbus-launch --exit-with-session startxfce4 &
else
  xterm &
fi
XSU
chmod +x "\$VNC_HOME/.vnc/xstartup"
fi
chown ubuntu:ubuntu "\$VNC_HOME/.vnc/xstartup"
echo "[UD] Starting vncserver as ubuntu..."
sudo -u ubuntu -H bash -lc 'vncserver '"$VNC_DISPLAY"' -geometry '"$DISPLAY_GEOMETRY"' -depth 24'
echo "[UD] Starting websockify on $NO_VNC_PORT -> 5901"
websockify -D --web=/usr/share/novnc/ $NO_VNC_PORT localhost:5901 || true
ss -tulpn || true
touch /tmp/terminal-ready
echo "[UD] Runtime-setup done"
EOF
}

## removed ensure_remote_services to keep script concise


launch_instance() {
	log_info "Launching EC2 instance..."
	local UD IMAGE_TO_USE
	if [ -n "$CUSTOM_AMI_ID" ]; then
		UD=$(create_runtime_user_data "$VNC_PASSWORD" | base64)
		IMAGE_TO_USE="$CUSTOM_AMI_ID"
	else
		UD=$(create_user_data_script "$VNC_PASSWORD" | base64)
		IMAGE_TO_USE="$AMI_ID"
	fi
	log_info "Using AMI: $IMAGE_TO_USE (preset=$([ -n "$CUSTOM_AMI_ID" ] && echo yes || echo no))"
	local placement=""
	[ -n "$TARGET_AZ" ] && placement=(--placement AvailabilityZone=$TARGET_AZ)
	INSTANCE_ID=$(aws ec2 run-instances --image-id "$IMAGE_TO_USE" --instance-type "$INSTANCE_TYPE" --key-name "$KEY_NAME" --security-group-ids "$SG_ID" --user-data "$UD" ${placement[@]} --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME},{Key=Purpose,Value=temp-terminal}]" --region "$AWS_REGION" --query 'Instances[0].InstanceId' --output text)
	[ -n "${INSTANCE_ID:-}" ] || {
		log_error "Failed to launch instance"
		exit 1
	}
	log_info "Instance: $INSTANCE_ID (waiting for running)"
	echo "INSTANCE_ID=$INSTANCE_ID" >>"$STATE_FILE"
	aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$AWS_REGION"
	PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
	INSTANCE_AZ=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)
	echo -e "PUBLIC_IP=$PUBLIC_IP" >>"$STATE_FILE"
	echo -e "IMAGE_ID=$IMAGE_TO_USE" >>"$STATE_FILE"
	log_info "Public IP: $PUBLIC_IP"
	echo -e "INSTANCE_AZ=$INSTANCE_AZ" >>"$STATE_FILE"
}

# Build or reuse a preset AMI with all packages installed
ensure_custom_ami() {
    [ "$USE_PRESET" = "1" ] || return 0
    log_stage "Preset/Check: Resolve custom AMI"
    # Reuse if exists and available
    if [ -z "$PRESET_FORCE_REBUILD" ] || [ "$PRESET_FORCE_REBUILD" != "1" ]; then
      if [ -n "$CUSTOM_AMI_ID" ]; then
        local st
        st=$(aws ec2 describe-images --image-ids "$CUSTOM_AMI_ID" --region "$AWS_REGION" --query 'Images[0].State' --output text 2>/dev/null || echo none)
        if [ "$st" = "available" ]; then
            AMI_ID="$CUSTOM_AMI_ID"
            log_stage "Preset/Reuse: $AMI_ID"
            return 0
        fi
      fi
    fi
    # Search by name
    if [ -z "$PRESET_FORCE_REBUILD" ] || [ "$PRESET_FORCE_REBUILD" != "1" ]; then
      local found
      found=$(aws ec2 describe-images --owners self --region "$AWS_REGION" --filters "Name=name,Values=$CUSTOM_AMI_NAME" --query 'Images[0].ImageId' --output text 2>/dev/null || echo None)
      if [ -n "$found" ] && [ "$found" != "None" ] && [ "$found" != "null" ]; then
          CUSTOM_AMI_ID="$found"
          update_env_kv CUSTOM_AMI_ID "$CUSTOM_AMI_ID"
          AMI_ID="$CUSTOM_AMI_ID"
          log_stage "Preset/FoundByName: $AMI_ID"
          return 0
      fi
    fi
    # Build new preset AMI
    # If force rebuild, generate a unique name to avoid name conflicts
    if [ "$PRESET_FORCE_REBUILD" = "1" ]; then
      CUSTOM_AMI_NAME="${CUSTOM_AMI_NAME}-v$(date +%Y%m%d-%H%M%S)"
      update_env_kv CUSTOM_AMI_NAME "$CUSTOM_AMI_NAME"
    fi
    log_stage "Preset/BuildStart: $CUSTOM_AMI_NAME"
    get_latest_ubuntu_ami
    local BLD_ID BLD_IP USER_DATA_B64
    USER_DATA_B64=$(create_user_data_script "preset" | base64)
    BLD_ID=$(aws ec2 run-instances --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" --key-name "$KEY_NAME" --security-group-ids "$SG_ID" --user-data "$USER_DATA_B64" --region "$AWS_REGION" --query 'Instances[0].InstanceId' --output text)
    aws ec2 wait instance-running --instance-ids "$BLD_ID" --region "$AWS_REGION"
    BLD_IP=$(aws ec2 describe-instances --instance-ids "$BLD_ID" --region "$AWS_REGION" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    # Wait for setup flag
    for i in $(seq 1 120); do
        ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SCRIPT_DIR/${KEY_NAME}.pem" ubuntu@"$BLD_IP" "test -f /tmp/terminal-ready" 2>/dev/null && break || true
        printf "."
        sleep 5
    done
    echo
    # Prepare instance for imaging: clean cloud-init so user-data runs on next boots
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SCRIPT_DIR/${KEY_NAME}.pem" ubuntu@"$BLD_IP" \
      'sudo cloud-init status --wait >/dev/null 2>&1 || true; \
       echo "[PRESET] cloud-init clean"; \
       sudo cloud-init clean || true; \
       sudo rm -rf /var/lib/cloud/instances/* /var/lib/cloud/instance 2>/dev/null || true; \
       sudo truncate -s 0 /var/log/cloud-init.log /var/log/cloud-init-output.log 2>/dev/null || true; \
       sync' 2>/dev/null || true
    sleep 2
    # Create AMI without reboot
    CUSTOM_AMI_ID=$(aws ec2 create-image --instance-id "$BLD_ID" --name "$CUSTOM_AMI_NAME" --no-reboot --region "$AWS_REGION" --query 'ImageId' --output text)
    log_stage "Preset/CreateImage: $CUSTOM_AMI_ID"
    aws ec2 wait image-available --image-ids "$CUSTOM_AMI_ID" --region "$AWS_REGION"
    update_env_kv CUSTOM_AMI_ID "$CUSTOM_AMI_ID"
    AMI_ID="$CUSTOM_AMI_ID"
    # Cleanup builder instance
    aws ec2 terminate-instances --instance-ids "$BLD_ID" --region "$AWS_REGION" >/dev/null 2>&1 || true
    log_stage "Preset/Available: $CUSTOM_AMI_ID"
}

wait_for_ready() {
	log_info "Waiting remote setup (~2-15 min)..."
	for i in $(seq 1 180); do
		# Cloud-init user-data flag
		ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SCRIPT_DIR/${KEY_NAME}.pem" ubuntu@"$PUBLIC_IP" "test -f /tmp/terminal-ready" 2>/dev/null && { log_info "Remote setup complete (flag)."; return 0; }
		# NoVNC reachable check
		if curl -fsS --max-time 2 "http://$PUBLIC_IP:$NO_VNC_PORT/" >/dev/null 2>&1; then
			log_info "Remote setup complete (novnc reachable)."
			return 0
		fi
		printf "."; sleep 5
	done
	echo; log_error "Remote setup timeout"; debug_remote || true; return 1
}

debug_remote() {
    echo "\n==== DEBUG: Remote diagnostics (start) ===="
    local SSH_BASE=(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SCRIPT_DIR/${KEY_NAME}.pem" ubuntu@"$PUBLIC_IP")
    "${SSH_BASE[@]}" 'set -e; echo "[REMOTE] whoami=$(whoami)"; echo "[REMOTE] uname=$(uname -a)"; echo "[REMOTE] date=$(date -Is)" || true'
    echo "-- tail: /var/log/terminal-setup.log --"
    "${SSH_BASE[@]}" 'sudo tail -n 200 /var/log/terminal-setup.log 2>/dev/null || echo "<no terminal-setup.log>"'
    echo "-- tail: /var/log/cloud-init-output.log --"
    "${SSH_BASE[@]}" 'sudo tail -n 200 /var/log/cloud-init-output.log 2>/dev/null || echo "<no cloud-init-output.log>"'
    echo "-- processes: vnc/websockify --"
    "${SSH_BASE[@]}" 'ps -ef | egrep -i "(vnc|websockify|novnc|Xtightvnc)" | grep -v egrep || echo "<none>"'
    echo "-- sockets: 5901/6080 --"
    "${SSH_BASE[@]}" 'ss -tulpn 2>/dev/null | egrep "(5901|6080)" || (command -v netstat >/dev/null && netstat -tulpn | egrep "(5901|6080)" || true)'
    echo "-- xstartup --"
    "${SSH_BASE[@]}" 'ls -l ~/.vnc/xstartup 2>/dev/null; echo "-----"; sed -n "1,120p" ~/.vnc/xstartup 2>/dev/null || echo "<no xstartup>"'
    echo "-- curl local novnc --"
    "${SSH_BASE[@]}" "bash -lc 'curl -fsS --max-time 2 http://127.0.0.1:${NO_VNC_PORT} >/dev/null && echo OK || echo FAIL'"
    echo "==== DEBUG: Remote diagnostics (end) ===="
}

print_instructions2() {
    local pem="$SCRIPT_DIR/${KEY_NAME}.pem"
    if [ ! -f "$pem" ] && [ -f "$STATE_FILE" ]; then
        local state_key
        state_key=$(awk -F= '$1=="KEY_NAME"{print $2}' "$STATE_FILE" 2>/dev/null || true)
        [ -n "$state_key" ] && pem="$SCRIPT_DIR/${state_key}.pem"
    fi
    printf "\n======================================================\nTemporary EC2 Terminal Ready\n======================================================\nInstance ID : %s\nPublic IP   : %s\n\nSSH\n  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\\n+      -i '%s' ubuntu@%s\n\nNoVNC\n  URL      : http://%s:%s/vnc.html\n  Password : %s\n\nPress Ctrl+C to terminate and delete this terminal.\n======================================================\n\n" "$INSTANCE_ID" "$PUBLIC_IP" "$pem" "$PUBLIC_IP" "$PUBLIC_IP" "$NO_VNC_PORT" "$VNC_PASSWORD"
}

print_instructions() { printf "\n======================================================\nTemporary EC2 Terminal Ready\n======================================================\nInstance ID : %s\nPublic IP   : %s\n\nSSH\n  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\n      -i '%s/%s.pem' ubuntu@%s\n\nNoVNC\n  URL      : http://%s:%s/vnc.html\n  Password : %s\n\nPress Ctrl+C to terminate and delete this terminal.\n======================================================\n\n" "$INSTANCE_ID" "$PUBLIC_IP" "$SCRIPT_DIR" "$KEY_NAME" "$PUBLIC_IP" "$PUBLIC_IP" "$NO_VNC_PORT" "$VNC_PASSWORD"; }

check_existing_state() {
	[ -f "$STATE_FILE" ] || return 1
	. "$STATE_FILE"
	[ -n "${INSTANCE_ID:-}" ] || return 1
	local state
	state=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "${REGION:-$AWS_REGION}" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo not-found)
	[[ "$state" =~ ^(not-found|terminated|shutting-down)$ ]] && return 1
	echo
	echo "기존 임시 터미널: $INSTANCE_ID (state=$state, ip=${PUBLIC_IP:-n/a})"
	read -p "삭제하고 새로 생성할까요? (y/N): " yn
	if [[ "$yn" =~ ^[Yy]$ ]]; then
		SG_ID="${SECURITY_GROUP_ID:-}"
		AWS_REGION="${REGION:-$AWS_REGION}"
		cleanup
		return 1
	fi
	AWS_REGION="${REGION:-$AWS_REGION}"
	SG_ID="${SECURITY_GROUP_ID:-$SG_ID}"
	[ -f "$SCRIPT_DIR/${KEY_NAME}.pem" ] || {
		log_error "로컬 키 파일 없음: $SCRIPT_DIR/${KEY_NAME}.pem"
		read -p "인스턴스를 삭제하시겠습니까? (y/N): " a
		[[ "$a" =~ ^[Yy]$ ]] && {
			cleanup
			exit 0
		} || exit 1
	}
	[ "$state" = "stopped" ] && {
		aws ec2 start-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" >/dev/null
		aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$AWS_REGION"
		PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
	}
	if [ "$USE_ENC_VOL" -eq 1 ]; then
		derive_volume_from_key || true
		attach_and_mount_volume || true
	fi
	print_instructions2
	while true; do sleep 60; done
}

cleanup() {
    # Prevent double-execution from INT handler + EXIT trap
    if [ "${CLEANUP_CALLED:-0}" = "1" ]; then return 0; fi
    CLEANUP_CALLED=1
    log_warn "Cleanup started..."
	if [ -n "${VOLUME_ID:-}" ] && [ -n "${PUBLIC_IP:-}" ] && [ -f "$SCRIPT_DIR/${KEY_NAME}.pem" ]; then
		ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SCRIPT_DIR/${KEY_NAME}.pem" ubuntu@"$PUBLIC_IP" \
			"sudo umount -f /mnt/local >/dev/null 2>&1 || true; sudo cryptsetup luksClose cryptlocal >/dev/null 2>&1 || true" 2>/dev/null || true
		aws ec2 detach-volume --volume-id "$VOLUME_ID" --region "$AWS_REGION" >/dev/null 2>&1 || true
		aws ec2 wait volume-available --volume-ids "$VOLUME_ID" --region "$AWS_REGION" 2>/dev/null || true
	fi
	if [ -n "${INSTANCE_ID:-}" ]; then
		aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" >/dev/null 2>&1 || true
		aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID" --region "$AWS_REGION" 2>/dev/null || true
	fi
	[ -n "${SG_ID:-}" ] && sleep 3 && aws ec2 delete-security-group --group-id "$SG_ID" --region "$AWS_REGION" >/dev/null 2>&1 || true
	# Preserve key pair and PEM; user deletes manually if desired
	[ -f "$STATE_FILE" ] && rm -f "$STATE_FILE" || true
	log_info "Cleanup finished. SSH key preserved: ${KEY_NAME:-<unknown>}"
	log_info "To delete key + matching encrypted volume later, run ./aws-terminal-delete-pem.sh"
}

handle_signal() {
  echo
  log_warn "Signal received. Destroying the temporary terminal..."
  # Disable EXIT trap to avoid double cleanup
  trap - EXIT
  cleanup
  exit 0
}

main() {
    trap handle_signal INT TERM
    trap cleanup EXIT
    : >"$STATE_FILE"
    log_stage "0-Init: Check dependencies"
    check_dependencies
    log_stage "1-Config: Load .env and prompt options"
    load_or_init_env
    prompt_encrypted_volume
    ensure_enc_volume_config
    echo "REGION=$AWS_REGION" >>"$STATE_FILE"
    VNC_PASSWORD=$(generate_vnc_password)
    echo "VNC_PASSWORD=$VNC_PASSWORD" >>"$STATE_FILE"
    log_stage "2-KeyPair: Resolve or create SSH key pair"
    create_key_pair
    log_stage "3-SG: Create security group and open ports"
    create_security_group
    log_stage "4-Preset AMI: Ensure preset image (reuse/build)"
    ensure_custom_ami
    if [ -z "$AMI_ID" ]; then get_latest_ubuntu_ami; fi
    log_stage "5-State: Check existing instance reuse/delete"
    if check_existing_state; then return 0; fi
    if [ "$USE_ENC_VOL" -eq 1 ]; then
        log_stage "6-EncVolume: Derive from PEM and locate volume"
        derive_volume_from_key || true
        find_existing_volume || true
    fi
    log_stage "7-Launch: Start instance"
    launch_instance
    if [ "$USE_ENC_VOL" -eq 1 ]; then log_stage "8-Volume: Attach and mount"; attach_and_mount_volume || true; fi
    log_stage "9-Ready: Wait for remote readiness"
    wait_for_ready || true
    log_stage "10-Output: Show connection instructions"
    print_instructions2
    while true; do sleep 60; done
}

if [ "${1:-}" = "--dry-run" ]; then
	echo "Dry-run summary:"
	echo "  Region: $AWS_REGION"
	echo "  Instance type: $INSTANCE_TYPE"
	echo "  Geometry: $DISPLAY_GEOMETRY"
	echo "  NoVNC port: $NO_VNC_PORT"
	echo "No resources will be created in dry-run."
	exit 0
fi

main "$@"
