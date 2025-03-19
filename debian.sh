#!/bin/bash
clear
    echo -e "   \e[1;32m_______________________________$NC"
    echo -e "   \e[1;36m         INPUT DOMAIN $NC"
    echo -e "   \e[1;32m_______________________________$NC"
    echo -e ""
    # Tambahkan domain yang ingin digunakan di bawah ini
    read -p "   input your domain :   " host1
    echo $host1 > /root/domain
    echo ""
clear
### Color
apt upgrade -y
apt update -y
apt install tmux -y
apt install lolcat -y
apt install curls
apt install wondershaper -y
apt install fail2ban -y
sudo apt install socat
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
domain=$(cat /root/domain)
TIME=$(date '+%d %b %Y')
ipsaya=$(wget -qO- ipinfo.io/ip)
TIMES="10"
CHATID="6285234805"
KEY="6838495061:AAGq5FPwqVNVs0YtvOjcKpFW4CAIs7fCbpM"
URL="https://api.telegram.org/bot$KEY/sendMessage"
# ===================
MYIP=$(curl -sS ipv4.icanhazip.com)
REPO="http://autsc.my.id/oqjshisuqksudueuwiow/"
izin="https://data-ip.autsc.my.id/penak"
clear
  # // Exporint IP AddressInformation
export IP=$( curl -sS icanhazip.com )


# Mengecek apakah file sudah ada
if [ -f "/root/.key" ]; then
    echo "kode auth sudah terpasang"
else
    random_string=$(tr -dc 'a-z0-9' </dev/urandom | head -c 10)
    
    echo "$random_string" > "/root/.key"
fi

clear

# Checking Os Architecture
if [[ $(uname -m) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# Checking System
OS_ID=$(grep -w ID /etc/os-release | head -n1 | sed 's/ID=//g' | tr -d '"')
OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/PRETTY_NAME=//g' | tr -d '"')

if [[ $OS_ID == "ubuntu" || $OS_ID == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$OS_NAME${NC} )"
else
    echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$OS_NAME${NC} )"
    exit 1
fi

# IP Address Validating
MYIP=$(curl -sS ipv4.icanhazip.com)
if [[ -z $MYIP ]]; then
    echo -e "${EROR} IP Address ( ${RED}Not Detected${NC} )"
    exit 1
else
    echo -e "${OK} IP Address ( ${green}$MYIP${NC} )"
fi

# Validate Successfull
if [[ "${EUID}" -ne 0 ]]; then
    echo "You need to run this script as root"
    exit 1
fi

if [[ "$(systemd-detect-virt)" == "openvz" ]]; then
    echo "OpenVZ is not supported"
    exit 1
fi

echo -e "\e[32mloading...\e[0m"
clear
# Version sc
clear
#########################
# USERNAME
rm -f /usr/bin/user
username=$(curl $izin | grep $MYIP | awk '{print $2}')
echo "$username" >/usr/bin/user
expx=$(curl $izin | grep $MYIP | awk '{print $3}')
echo "$expx" >/usr/bin/e
# DETAIL ORDER
username=$(cat /usr/bin/user)
oid=$(cat /usr/bin/ver)
exp=$(cat /usr/bin/e)
clear
# CERTIFICATE STATUS
d1=$(date -d "$valid" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
# VPS Information
DATE=$(date +'%Y-%m-%d')
datediff() {
    d1=$(date -d "$1" +%s)
    d2=$(date -d "$2" +%s)
    echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""

# Status ExpiRED Active | Geo Project
Info="(${green}Active${NC})"
Error="(${RED}ExpiRED${NC})"
today=`date -d "0 days" +"%Y-%m-%d"`
Exp1=$(curl $izin | grep $MYIP | awk '{print $4}')
if [[ $today < $Exp1 ]]; then
sts="${Info}"
else
sts="${Error}"
fi
echo -e "\e[32mloading...\e[0m"
clear

####
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
### Status
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
	echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW}   $1 ${FONT}"
	echo -e "${green} =============================== ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
		echo -e "${green} =============================== ${FONT}"
        echo -e "${Green}  $1 berhasil dipasang"
		echo -e "${green} =============================== ${FONT}"
        sleep 2
    fi
}

### Cek root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi

}

# Buat direktori xray
print_install "get file"
    mkdir -p /etc/xray
    curl -s ifconfig.me > /etc/xray/ipvps
    touch /etc/xray/domain
    echo $domain > /etc/xray/domain
    mkdir -p /var/log/xray
    chown www-data.www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    mkdir -p /var/lib/kyt >/dev/null 2>&1
    # // Ram Information
    while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
        mem_used="$((mem_used-=${b/kB}))"
    ;;
    esac
    done < /proc/meminfo
    Ram_Usage="$((mem_used / 1024))"
    Ram_Total="$((mem_total / 1024))"
    export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
    export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
    export Kernel=$( uname -r )
    export Arch=$( uname -m )
    export IP=$( curl -s https://ipinfo.io/ip/ )

function meki() {
    # Set timezone
    timedatectl set-timezone Asia/Jakarta

    echo "Installing iptables-persistent and netfilter-persistent..."

    # Perbarui paket
    sudo apt update -y

    # Cek apakah iptables-persistent sudah tersedia
    if apt-cache show iptables-persistent >/dev/null 2>&1; then
        # Instal iptables-persistent tanpa interaksi pengguna
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        sudo apt install iptables-persistent netfilter-persistent -y

        # Verifikasi instalasi
        if dpkg -l | grep iptables-persistent >/dev/null; then
            echo "iptables-persistent installed successfully!"
        else
            echo "Failed to install iptables-persistent."
            exit 1
        fi
    else
        echo "iptables-persistent is not available in the package repository for this OS."
        exit 1
    fi
}


# Change Environment System
function first_setup() {
    # Set timezone
    timedatectl set-timezone Asia/Jakarta

    # Konfigurasi iptables-persistent untuk auto-save
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    print_success "get file sukses"

    # Ambil informasi OS
    OS=$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
    PRETTY_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')

    echo "Setup Dependencies for $PRETTY_NAME"

    # Perbarui paket dan install HAProxy
    if [[ "$OS" == "ubuntu" ]]; then
        # Untuk Ubuntu
        sudo apt update -y
        sudo apt install --no-install-recommends software-properties-common -y

        # Gunakan versi HAProxy default di Ubuntu (sudah lebih baru di versi ini)
        sudo apt install haproxy -y

    elif [[ "$OS" == "debian" ]]; then
        # Untuk Debian
        sudo apt update -y

        # Tambahkan repositori resmi HAProxy jika perlu
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor | sudo tee /usr/share/keyrings/haproxy.debian.net.gpg >/dev/null
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bullseye-backports-2.6 main" | sudo tee /etc/apt/sources.list.d/haproxy.list

        # Update paket dan install versi HAProxy terbaru
        sudo apt update -y
        sudo apt install haproxy -y

    else
        echo -e "Your OS is not supported ($PRETTY_NAME)"
        exit 1
    fi

    # Verifikasi instalasi
    if haproxy -v >/dev/null 2>&1; then
        echo "HAProxy installed successfully: $(haproxy -v | head -n1)"
    else
        echo "Failed to install HAProxy!"
        exit 1
    fi
}


# GEO PROJECT
clear
function nginx_install() {
    # // Checking System
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        print_install "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        # // sudo add-apt-repository ppa:nginx/stable -y 
        sudo apt-get install nginx -y 
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        print_success "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        apt -y install nginx 
    else
        echo -e " Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
        # // exit 1
    fi
}

clear
function base_package() {

    print_install "install paket"

    # Update dan instal paket dasar
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    sudo apt install socat
    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet python3 python3-pip ntpdate sudo \
        speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
        libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev \
        sed dirmngr libxml-parser-perl build-essential gcc g++ libc6 util-linux msmtp-mta ca-certificates bsd-mailx \
        iptables iptables-persistent netfilter-persistent net-tools wget curl ruby unzip p7zip-full jq gnupg dnsutils \
        openvpn easy-rsa screen socat xz-utils apt-transport-https

    # Konfigurasi iptables-persistent otomatis
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Sistem sinkronisasi waktu
    systemctl enable chronyd
    systemctl restart chronyd
    systemctl enable chrony
    systemctl restart chrony
    chronyc sourcestats -v
    chronyc tracking -v
    ntpdate pool.ntp.org

    # Hapus paket yang tidak diperlukan
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get remove --purge -y exim4 ufw firewalld

    # Periksa versi OS
    os_name=$(lsb_release -is)
    os_version=$(lsb_release -rs | cut -d. -f1)

    if [[ "$os_name" == "Debian" && "$os_version" == "12" ]]; then
        print_install "install paket"

        # Instalasi modul Python menggunakan apt
        apt install python3-requests -y 
        apt install python3-flask -y
    else
        print_install "install paket"

        # Instalasi modul Python menggunakan pip
        pip3 install --upgrade pip
        pip3 install requests flask
    fi

    print_success "berhasil diinstal"
}

clear
restart_system() {
    Name=$(curl -sS $izin | grep $MYIP | awk '{print $2}')
    Name2=$(curl -sS $izin | grep $MYIP | awk '{print $5, $6, $7, $8 $9}')
    isp=$(cat /etc/xray/isp)
    city=$(cat /etc/xray/city)
    RAM=$(free -m | awk 'NR==2 {print $2}')
    MODEL2=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')
    EXPSC=$(wget -qO- $izin | grep $ipsaya | awk '{print $3}')
    d1=$(date -d "$EXPSC" +%s)
    d2=$(date -d "$today" +%s)
    EXP=$(( (d1 - d2) / 86400 ))

    TIMEZONE=$(printf '%(%H:%M:%S)T')
    TEXT="
<code>────────────────────</code>
<b> 🍁 NOTIFICATIONS INSTALL 🍁 </b>
<code>────────────────────</code>
<code>ID     : </code><code>$Name2</code>
<code>ORDER  : </code><code>$Name</code>
<code>IP     : </code><code>$ipsaya</code>
<code>DOMAIN : </code><code>$domain</code>
<code>ISP    : </code><code>$isp</code>
<code>CITY   : </code><code>$city</code>
<code>RAM    : </code><code>$RAM</code>
<code>OS     : </code><code>$MODEL2</code>
<code>DATE   : </code><code>$TIME $TIMEZONE</code>
<code>EXP    : </code><code>$EXP DAY</code>
<code>────────────────────</code>"
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}
clear
# Pasang SSL
function pasang_ssl() {
clear
print_install "Memasang SSL Pada Domain"
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    systemctl stop $STOPWEBSERVER
    systemctl stop nginx
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate"
}

function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess/akun/
    mkdir -p /etc/vless/akun/
    mkdir -p /etc/trojan/akun/
    mkdir -p /etc/shadowsocks/akun
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/files/vmess/ip
    mkdir -p /etc/kyt/files/vless/ip
    mkdir -p /etc/kyt/files/trojan/ip
    mkdir -p /etc/kyt/files/ssh/ip
    mkdir -p /etc/files/vmess
    mkdir -p /etc/files/vless
    mkdir -p /etc/files/trojan
    mkdir -p /etc/files/ssh
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    }
#Instal Xray
function install_xray() {
clear
    print_install "Core Xray Latest Version"
    # install xray
    #echo -e "[ ${green}INFO$NC ] Downloading & Installing xray core"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    # / / Ambil Xray Core Version Terbaru
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.16
 
    # // Ambil Config Server
    wget --no-check-certificate -q -O /etc/xray/config.json "${REPO}cfg/config.json" >/dev/null 2>&1
    #wget --no-check-certificate -q -O /usr/local/bin/xray "${REPO}xray/xray.linux.64bit" >/dev/null 2>&1
    wget --no-check-certificate -q -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    #chmod +x /usr/local/bin/xray
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Core Xray Latest Version"
    
    # // Settings UP Nginix Server
    clear
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Memasang Konfigurasi Packet"
    wget --no-check-certificate -q -O /etc/haproxy/haproxy.cfg "${REPO}cfg/haproxy.cfg" >/dev/null 2>&1
    wget --no-check-certificate -q -O /etc/nginx/conf.d/xray.conf "${REPO}cfg/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    wget --no-check-certificate -q -O /etc/nginx/nginx.conf "${REPO}cfg/nginx.conf" >/dev/null 2>&1
    
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # > Set Permission
    chmod +x /etc/systemd/system/runn.service

    # > Create Service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
filesNPROC=10000
filesNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
print_success "Konfigurasi Packet"
}

function ssh(){
clear
print_install "Memasang Password SSH"
    wget --no-check-certificate -q -O /etc/pam.d/common-password "${REPO}files/password"
chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# // nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# // Ubah izin akses
chmod +x /etc/rc.local

# // enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# // disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# // update
# // set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# // set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}

function udp_mini(){
clear
print_install "Memasang Service limit Quota"
wget --no-check-certificate -q "${REPO}files/limit.sh" && chmod +x limit.sh && ./limit.sh 

#SERVICE VMESS
# // Installing UDP Mini
mkdir -p /usr/local/kyt/
wget --no-check-certificate -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget --no-check-certificate -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
wget --no-check-certificate -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
wget --no-check-certificate -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
print_success "files Quota Service"
}

function ssh_slow(){
clear
# // Installing UDP Mini
print_install "Memasang modul SlowDNS Server"
    wget --no-check-certificate -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
 print_success "SlowDNS"
}

clear
function ins_SSHD(){
clear
print_install "Memasang SSHD"
wget --no-check-certificate -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD"
}

clear
function ins_dropbear(){
clear
print_install "Menginstall Dropbear"
# Installing Dropbear
wget --no-check-certificate -q ${REPO}files/dropbear.sh && chmod +x dropbear.sh && ./dropbear.sh
print_success "Dropbear"
}

clear
function ins_vnstat(){
clear
print_install "Menginstall Vnstat"
# setting vnstat
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget --no-check-certificate -q https://autsc.my.id/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
print_success "Vnstat"
}

function ins_openvpn(){
clear
print_install "Menginstall OpenVPN"
#OpenVPN
wget --no-check-certificate -q ${REPO}files/openvpn &&  chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
print_success "OpenVPN"
}

function ins_backup(){
clear
print_install "Memasang Backup Server"
#BackupOption
apt install rclone -y
printf "q\n" | rclone config
wget --no-check-certificate -q -O /root/.config/rclone/rclone.conf "${REPO}cfg/rclone.conf"
#Install Wondershaper
cd /bin
git clone  https://github.com/magnific0/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf wondershaper
echo > /home/files
apt install msmtp-mta ca-certificates bsd-mailx -y
cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77 
logfile ~/.msmtp.log
EOF
chown -R www-data:www-data /etc/msmtprc
wget --no-check-certificate -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
print_success "Backup Server"
}

clear
function ins_swab(){
clear
print_install "Memasang Swap 1 G"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    
        # > Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # > Singkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v
    
    wget --no-check-certificate -q ${REPO}files/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
print_success "Swap 1 G"
}

function ins_Fail2ban(){
clear
# banner
echo "Banner /etc/banner.txt" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear

# Ganti Banner
wget --no-check-certificate -q -O /etc/kyt.txt "${REPO}banner/issue.net"
  # fail2ban
  wget --no-check-certificate -q ${REPO}files/fail2ban && chmod +x fail2ban && ./fail2ban

print_success "Fail2ban"
}

function ins_epro(){
clear
print_install "Menginstall ePro WebSocket Proxy"
    wget --no-check-certificate -q -O /usr/bin/memek "${REPO}files/memek"  >/dev/null 2>&1
    wget --no-check-certificate -q -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget --no-check-certificate -q -O /usr/bin/tun.conf "${REPO}cfg/tun.conf" >/dev/null 2>&1
    wget --no-check-certificate -q -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod +x /usr/bin/ws-epro
    chmod +x /usr/bin/memek
    chmod 644 /usr/bin/tun.conf
systemctl disable ws
systemctl stop ws
systemctl enable ws
systemctl start ws
systemctl restart ws
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geositeindo.dat "https://autsc.my.id/core/geositeindo.dat" >/dev/null 2>&1
wget --no-check-certificate -q -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# remove unnecessary files
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
print_success "ePro WebSocket Proxy"
}

function ins_restart(){
clear
print_install "Restarting  All Packet"
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
systemctl restart haproxy
/etc/init.d/cron restart
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now ws
    systemctl enable --now fail2ban
history -c
echo "unset HISTFILE" >> /etc/profile

cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
print_success "All Packet"
}

#Instal Menu
function menu(){
    clear
    print_install "INSTALL UPDATE"


    wget --no-check-certificate -q ${REPO}Features/menu.zip > /dev/null 2>&1


    mkdir -p /usr/local/sbin/ > /dev/null 2>&1


    unzip -qq menu.zip > /dev/null 2>&1


    mv menu/* /usr/local/sbin/ > /dev/null 2>&1


    chmod +x /usr/local/sbin/* > /dev/null 2>&1


    rm -rf menu* > /dev/null 2>&1
}


# Membaut Default Menu 
function profile(){
clear
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu1
EOF

cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/local/sbin/xp
END

cat >/etc/cron.d/bkpbot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /usr/local/sbin/backup2
END

cat >/etc/cron.d/limitssh <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/15 * * * * root /usr/local/sbin/notifssh
END

cat >/etc/cron.d/limitxray <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/15 * * * * root /usr/local/sbin/notifxray vmip
*/15 * * * * root /usr/local/sbin/notifxray trip
*/15 * * * * root /usr/local/sbin/notifxray vlip
END

cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END

    echo "0 0 * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "0 0 * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart
    cat >/home/daily_reboot <<-END
		5
	END

cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF
  
cat >/etc/systemd/system/badvpn.service << EOF
[Unit]
Description=memek
ProjectAfter=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/./memek
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable badvpn
systemctl restart badvpn

cat >/etc/systemd/system/cpu.service << EOF
[Unit]
Description=memek
ProjectAfter=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/local/sbin/./cpu
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable cpu 
systemctl restart cpu

  #install ws-epro
  
echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local
    
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
print_success "Menu Packet"
}

# Restart layanan after install
function enable_services(){
clear
print_install "Enable Service"
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    print_success "Enable Service"
    clear
}

# Fingsi Install Script
function instal(){
clear
    first_setup
    meki
    nginx_install
    base_package
    make_folder_xray
    password_default
    pasang_ssl
    install_xray
    ssh
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    ins_restart
    menu
    profile
    enable_services
    restart_system
}
instal
echo ""
history -c
rm /root/* >/dev/null 2>&1
#sudo hostnamectl set-hostname $user
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $ipsaya
echo -e "${green} install sukses ${NC}"
sleep 3
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} TO REBOOT") "
reboot

