#!/bin/bash
set -uo pipefail
######################
_SLES_version=$(grep VERSION /etc/SuSE-release | cut -d= -f2 | xargs)
_SLES_patch_level=$(grep PATCHLEVEL /etc/SuSE-release | cut -d= -f2 | xargs)
_SLES11_SP3_recommended_repo="repos-sles11-sp3-x86_64-20170413-1"
_SLES11_SP3_recommended_kernel="3.0.101-0.47.99"
_SLES11_SP4_recommended_repo="repos-sles11-sp4-x86_64-20170714-1"
_SLES11_SP4_recommended_kernel="3.0.101-107"
_SLES12_SP1_recommended_repo="repos-sles12-sp1-x86_64-20170809-1"
_SLES12_SP1_recommended_kernel="3.12.74-60.64.51"
_recommended_kernel="$(echo '_SLES'"$_SLES_version"_SP"$_SLES_patch_level"_recommended_kernel)"
_recommended_repo="$(echo '_SLES'"$_SLES_version"_SP"$_SLES_patch_level"_recommended_repo)"
_recommended_gpfs_version="3.5.0.30"
_recommended_swappiness="60"
######################
#_recommended_kernel=$(curl --silent http://repo:50000/repo/SM/SCO/repo_relationships | grep sles"$_SLES_version"-sp"$_SLES_patch_level"-x86_64-current.rpm | cut -d' ' -f3 | xargs | cut -d. -f1)
#mkdir /tmp/rpm; wget -P /tmp/rpm http://repo:50000/repo/snapshot/sap-repo/repos-sles"$_SLES_version"-sp"$_SLES_patch_level"-x86_64-current.rpm; cd /tmp/rpm;
#rpm2io *rpm | cpio -idvm
#curl
######################
_SIDADM=$(ps -ef | awk '{print $1}' | grep adm | grep -vE ^'sap|daa|dac' | uniq)
_SID=$(echo $_SIDADM | cut -c1-3)
_SID_upper=$(echo $_SID | tr '[:lower:]' '[:upper:]')
_FQDN=$(hostname --fqdn)
_HOSTNAME=$(hostname)
_DC=$(echo $_FQDN | cut -d. -f2)
echo $_FQDN | grep ^hec* >/dev/null && _customer_interface="eth2" || _customer_interface="external"
_primary_customer_ip=$(ip a s $_customer_interface primary | grep inet | awk '{print $2}' | cut -d/ -f1)
_secondary_customer_ip=$(ip a s $_customer_interface primary | grep inet | awk '{print $2}' | cut -d/ -f1)
_customer_domain=$(dig @127.0.0.1 -x $_primary_customer_ip +short | cut -d. -f2- | rev | cut -c2- | rev)
_pdnsd_auto=$(grep -v ^# /etc/sysconfig/pdnsd | awk NF | grep PDNSD_NOAUTOCONF | cut -d= -f2 | sed 's/"//g')
ps -ef | grep hdbnameserver | grep -v grep | grep hdbnameserver >/dev/null && _DB="y" || _DB="n"
######################

kernel_repo_check(){
        _current_kernel=$(uname -r | sed -r 's/-xen|-default//')
        _current_repo="$(rpm -qa | grep repo)"
        [ "$_current_repo" == "${!_recommended_repo}" ] && printf "SLES"$_SLES_version" SP"$_SLES_patch_level" Repo date\t\t\t[ OK ]\n" || printf "SLES"$_SLES_version" SP"$_SLES_patch_level" Repo date\t\t\t[ NOK ] - update $_current_repo to ${!_recommended_repo}\n"
        [ "$_current_kernel" == "${!_recommended_kernel}" ] && printf "SLES"$_SLES_version" SP"$_SLES_patch_level" Kernel version\t\t[ OK ]\n" || printf "SLES"$_SLES_version" SP"$_SLES_patch_level" Kernel version\t\t[ NOK ] - update $_current_kernel to ${!_recommended_kernel}\n"
}

hana_backup_check(){
        if [ $_DB == 'y' ]; then
                /bin/mountpoint -q /hana_backup/$_SID_upper/log && printf "Backup Log filesystem\t\t\t[ OK ]\n" || printf "Backup Log filesystem\t\t\t[ NOK ] - not in standard\n"
                /bin/mountpoint -q /hana_backup/$_SID_upper/data && printf "Backup Data filesystem\t\t\t[ OK ]\n" || printf "Backup Data filesystem\t\t\t[ NOK ] - not in standard\n"
        else
                printf "Backup Data/Log filesystem\t\t[ N/A ] - Not a DB server\n"
        fi
}

dns_check(){
        _primary_DNS_IP=$(dig @127.0.0.1 vh"$_CID"dns1."$_customer_domain" +short)
        _secondary_DNS_IP=$(dig @127.0.0.1 vh"$_CID"dns2."$_customer_domain" +short)
        grep -v ^# /etc/resolv.conf | grep nameserver | awk NF | head -1 | awk '/nameserver/ {print $2}' | grep 127.0.0.1 >/dev/null && printf "Localhost entry\t\t\t\t[ OK ]\n" || printf "Localhost entry\t\t\t\t[ NOK ] - it should be the first one of the file\n"
        grep -v ^# /etc/resolv.conf | grep nameserver | awk NF | head -3 | tail -2 | awk '/nameserver/ {print $2}' | grep "$_primary_DNS_IP" >/dev/null && printf "Dedicated DNS1\t\t\t\t[ OK ]\n" || printf "Dedicated DNS1\t\t\t\t[ NOK ]\n"
        grep -v ^# /etc/resolv.conf | grep nameserver | awk NF | head -3 | tail -2 | awk '/nameserver/ {print $2}' | grep "$_secondary_DNS_IP" >/dev/null && printf "Dedicated DNS2\t\t\t\t[ OK ]\n" || printf "Dedicated DNS2\t\t\t\t[ NOK ]\n"
        [[ -z "$_pdnsd_auto" || "$_pdnsd_auto" == "no" ]] && printf "PDNSD not autogen\t\t\t[ OK ]\n" || printf "PDNSD not autogen\t\t\t[ NOK ] - Value should be either no or blank\n"
        grep -v ^# /etc/pdnsd.conf | awk NF | tr -d '\040\011' | grep ^ip | grep "$_primary_DNS_IP" >/dev/null && printf "PDNSD Conf Dedicated DNS1\t\t[ OK ]\n" || printf "PDNSD Conf Dedicated DNS1\t\t[ NOK ]\n"
        grep -v ^# /etc/pdnsd.conf | awk NF | tr -d '\040\011' | grep ^ip | grep "$_primary_DNS_IP" >/dev/null && printf "PDNSD Conf Dedicated DNS2\t\t[ OK ]\n" || printf "PDNSD Conf Dedicated DNS2\t\t[ NOK ]\n"
}

virtualip_check(){
        _vh_host_fail='0'
        _virtual_lives='2'
        _virtualip_conf_file="/etc/sysconfig/network/virtualip"
        _tmp_file="/tmp/vh.tmp"
        _vh_db="$(echo 'vh'"$_CID""$_SID"'db.'"$_customer_domain")"; echo $_vh_db > $_tmp_file
        _vh_ci="$(echo 'vh'"$_CID""$_SID"'ci.'"$_customer_domain")"; echo $_vh_ci >> $_tmp_file
        _vh_cs="$(echo 'vh'"$_CID""$_SID"'cs.'"$_customer_domain")"; echo $_vh_cs >> $_tmp_file
        while read _vh_host
        do
                _virtual_ip=$(dig @127.0.0.1 "${_vh_host}" +short | xargs)
                if [ ! -z $_virtual_ip ];then
                        ping -c1 $_virtual_ip >/dev/null; [ $? -eq 0 ] && printf "Virtual IP ping\t\t\t\t[ OK ] - $_vh_host\n" || let "_vh_host_fail++"
                        ip a s | grep $_virtual_ip >/dev/null;
                        if [ $? -eq 0 ]; then
                                printf "Virtual IP exists\t\t\t[ OK ] - $_vh_host\n"
                                grep ""$_customer_interface":"$_vh_host"" "$_virtualip_conf_file">/dev/null && printf "Virtual IP conf file\t\t\t[ OK ] - $_vh_host\n" || printf "Virtual IP conf file\t\t\t[ NOK ] - $_vh_host\n"
                                _virtual_lives=1
                        fi
                fi
        done<$_tmp_file
        if [ "$_virtual_lives" -eq '1' ]; then
                chkconfig --list | grep virtualip | grep "3:on" >/dev/null
                [ $? -eq 0 ] && printf "Virtual IP on boot\t\t\t[ OK ]\n" || printf "Virtual IP on boot\t\t\t[ NOK ] - Configure with chkconfig\n"
        fi

        [ "$_vh_host_fail" -eq '3' ] && printf "Virtual IP check\t\t\t[ NOK ] - There is no Virtual IP for this system, check with TLO if there should be any\n"
}

crontab_check(){
        if [ $_DB == 'y' ]; then
                su -l $_SIDADM -c "crontab -l" | grep backup>/dev/null && printf "Cron Backup Catalog\t\t\t[ OK ]\n" || printf "Cron Backup Catalog\t\t\t[ NOK ] - Please add Cronjob for backup catalog\n"
        else
                printf "Cron Backup Catalog\t\t\t[ N/A ] - Not a DB server\n"
        fi
}

memory_check(){
        #######Swappiness
        _current_swappiness="$(sysctl vm.swappiness | cut -d= -f2 | xargs)"
        [ "$_current_swappiness" == "$_recommended_swappiness" ] && printf "Swappiness\t\t\t\t[ OK ]\n" || printf "Swappiness\t\t\t\t[ NOK ] - Change to $_recommended_swappiness\n"
        #######/tmp on RAM
        grep tmpfs /etc/fstab | grep -E 'none.*/tmp.*tmpfs' >/dev/null
        [ $? -eq 0 ] && printf "Separate tmpfs on fstab\t\t\t[ OK ]\n" || printf "Separate tmpfs on fstab\t\t\t[ NOK ]\n"
        _tmpfs_lines=$(df 2>/dev/null | grep tmp | grep -E 'none.*/tmp|tmpfs.*/dev/shm' | wc -l)
        [ "$_tmpfs_lines" -eq 2 ] && printf "Separate tmpfs active\t\t\t[ OK ]\n" || printf "Separate tmpfs active\t\t\t[ NOK ]\n"
}

tic_check(){
        /usr/sbin/tic_info > /dev/null 2>&1
        if [ $? -eq 0 ]; then
                _tic_comment=$(/usr/sbin/tic_info | grep Comment | cut -d: -f2 | xargs)
                _tic_status=$(/usr/sbin/tic_info | grep Status | grep Live>/dev/null)
                [[ $? -eq 0 ]] && printf "TIC status\t\t\t\t[ OK ]\n" || printf "TIC status\t\t\t\t[ NOK ] - Change to Live if ready\n"
                echo $_tic_comment | cut -d- -f1 | xargs | grep -o -E '\[[[:alnum:]]{3}\]' >/dev/null; _CID_check=$?
                echo $_tic_comment | cut -d- -f2 | xargs | grep -o -E '[[:alnum:]]{3}' >/dev/null; _SID_check=$?
                echo $_tic_comment | cut -d- -f3 | xargs | grep -iE 'ABAP|JAVA|HANA|DB|AI|CS' >/dev/null; _TYPE_check=$?
                echo $_tic_comment | cut -d- -f4 | xargs | grep -E '.*' >/dev/null; _SELNAME_check=$?
                echo $_tic_comment | cut -d- -f5- | xargs | grep -iE 'PRD|SBX|DEV|QA' >/dev/null; _TIER_check=$?
                [[ $_CID_check -eq 0 && $_SID_check -eq 0 && $_TYPE_check -eq 0 && $_SELNAME_check -eq 0 && $_TIER_check -eq 0 ]] && { printf "TIC naming convention\t\t\t[ OK ]\n";_tic_configured="0"; } || { printf "TIC naming convention\t\t\t[ NOK ]\n";_tic_configured="1"; }
        else
                printf "TIC communication issue\t\t\t[ NOK ]\n"
                _tic_configured="2"
        fi
}

ha_check(){
        _PROD="$(/usr/sbin/tic_info "Virtual Machine" "$_HOSTNAME" | grep PRIORITY | cut -d\' -f2 | xargs)"
        echo $_HOSTNAME | grep ^hec > /dev/null 2>&1
        if [ "$?" -ne '0' ]; then
                printf "HA group\t\t\t\t[ OK ] - Physical servers dont require HA group\n"
        elif [ "$_PROD" == "prod" ]; then
                _HA_GROUP="$(/usr/sbin/tic_info "Virtual Machine" "$_HOSTNAME" | grep HA_GROUP | cut -d\' -f2 | xargs)"
                [ -z "$_HA_GROUP" ] && printf "HA group\t\t\t\t[ NOK ] - No HA group configured for this PRD server\n" || printf "HA group\t\t\t\t[ OK ] - Part of HA group => $_HA_GROUP\n"
        #elif [ "$_tic_configured" -eq 0 ]; then
        #        echo $_tic_comment | cut -d- -f5- | grep -iE 'PRD' > /dev/null
        #        if [ $? -eq '0' ]; then
        #                _HA_GROUP="$(/usr/sbin/tic_info "Virtual Machine" "$_HOSTNAME" | grep HA_GROUP | cut -d\' -f2 | xargs)"
        #                [ -z "$_HA_GROUP" ] && printf "HA group\t\t\t\t[ NOK ] - No HA group configured for this PRD server\n" || printf "HA group\t\t\t\t[ OK ] - Part of HA group => $_HA_GROUP\n"
        #        elif [ $? -eq '1' ]; then
        #                printf "HA group\t\t\t\t[ OK ] - Not a PRD server, no need of HA group\n"
        #        fi
        #elif [ "$_tic_configured" -eq 2 ];then
        #        printf "HA group\t\t\t\t[ NOK ] - Unable to determine if it's PRD - TIC configuration issue\n"
        else
                #printf "HA group\t\t\t\t[ NOK ] - Unable to determine if it's PRD - TIC SCO naming convention not set, check manually\n"
                printf "HA group\t\t\t\t[ OK ] - Not a PRD server, no need of HA group\n"
        fi
}

network_optimization(){
        if [ $_DB == 'y' ]; then
                _sysctl_file="/etc/sysctl.conf"
                _net_core_somaxconn_v="4096"
                _net_ipv4_tcp_max_syn_backlog_v="8192"
                _net_ipv4_ip_local_port_range_v="1024 64999"
                _net_ipv4_tcp_tw_reuse_v="1"
                _net_ipv4_tcp_tw_recycle_v="1"
                _net_ipv4_tcp_syn_retries_v="8"
                grep -v ^# $_sysctl_file | grep net.core.somaxconn | cut -d= -f2- | xargs | grep "$_net_core_somaxconn_v" >/dev/null; _net_core_somaxconn_e="$?"
                grep -v ^# $_sysctl_file | grep net.ipv4.tcp_max_syn_backlog | cut -d= -f2- | xargs | grep "$_net_ipv4_tcp_max_syn_backlog_v" >/dev/null; _net_ipv4_tcp_max_syn_backlog_e="$?"
                grep -v ^# $_sysctl_file | grep net.ipv4.ip_local_port_range | cut -d= -f2- | xargs | grep "$_net_ipv4_ip_local_port_range_v" >/dev/null; _net_ipv4_ip_local_port_range_e="$?"
                grep -v ^# $_sysctl_file | grep net.ipv4.tcp_tw_reuse | cut -d= -f2- | xargs | grep "$_net_ipv4_tcp_tw_reuse_v" >/dev/null; _net_ipv4_tcp_tw_reuse_e="$?"
                grep -v ^# $_sysctl_file | grep net.ipv4.tcp_tw_recycle | cut -d= -f2- | xargs | grep "$_net_ipv4_tcp_tw_recycle_v" >/dev/null; _net_ipv4_tcp_tw_recycle_e="$?"
                grep -v ^# $_sysctl_file | grep net.ipv4.tcp_syn_retries | cut -d= -f2- | xargs | grep "$_net_ipv4_tcp_syn_retries_v" >/dev/null; _net_ipv4_tcp_syn_retries_e="$?"
                [[ $_net_core_somaxconn_e -eq 0 && $_net_ipv4_tcp_max_syn_backlog_e -eq 0 && $_net_ipv4_ip_local_port_range_e -eq 0 && $_net_ipv4_tcp_tw_reuse_e -eq 0 &&       $_net_ipv4_tcp_tw_recycle_e -eq 0 && $_net_ipv4_tcp_syn_retries_e -eq 0 ]] && printf "OS Network optimization (persistent)\t[ OK ] - SAP Note 2382421\n" || printf "OS Network optimization (persistent)\t[ NOK ] - SAP Note 2382421\n"
        
                sysctl -a | grep net.core.somaxconn | cut -d= -f2- | xargs | grep "$_net_core_somaxconn_v" >/dev/null; _net_core_somaxconn_e2="$?"
                sysctl -a | grep net.ipv4.tcp_max_syn_backlog | cut -d= -f2- | xargs | grep "$_net_ipv4_tcp_max_syn_backlog_v" >/dev/null; _net_ipv4_tcp_max_syn_backlog_e2="$?"
                sysctl -a | grep net.ipv4.ip_local_port_range | cut -d= -f2- | xargs | grep "$_net_ipv4_ip_local_port_range_v" >/dev/null; _net_ipv4_ip_local_port_range_e2="$?"
                sysctl -a | grep net.ipv4.tcp_tw_reuse | cut -d= -f2- | xargs | grep "$_net_ipv4_tcp_tw_reuse_v" >/dev/null; _net_ipv4_tcp_tw_reuse_e2="$?"
                sysctl -a | grep net.ipv4.tcp_tw_recycle | cut -d= -f2- | xargs | grep "$_net_ipv4_tcp_tw_recycle_v" >/dev/null; _net_ipv4_tcp_tw_recycle_e2="$?"
                sysctl -a | grep net.ipv4.tcp_syn_retries | cut -d= -f2- | xargs | grep "$_net_ipv4_tcp_syn_retries_v" >/dev/null; _net_ipv4_tcp_syn_retries_e2="$?"
                [[ $_net_core_somaxconn_e2 -eq 0 && $_net_ipv4_tcp_max_syn_backlog_e2 -eq 0 && $_net_ipv4_ip_local_port_range_e2 -eq 0 && $_net_ipv4_tcp_tw_reuse_e2 -eq 0 &&   $_net_ipv4_tcp_tw_recycle_e2 -eq 0 && $_net_ipv4_tcp_syn_retries_e2 -eq 0 ]] && printf "OS network optimization (running)\t[ OK ] - SAP Note 2382421\n" || printf "OS network optimization (running)\t\t[ NOK ] - SAP Note 2382421\n"
        else
                printf "OS network optimization S-Note 2382421\t[ N/A ] - Not a DB server\n"
        fi
}

gpfs_locality(){
        _USERSTORE_N=$(su - "$_SIDADM" -c "hdbuserstore list | grep 'KEY.BKPMON' | wc -l")
        [ "$_USERSTORE_N" -eq '2' ] && _USERSTORE=$(su - "$_SIDADM" -c "hdbuserstore list | grep 'KEY.BKPMON'" | awk '{print $2}' | grep BKPMON.) || _USERSTORE=$(su - "$_SIDADM" -c "hdbuserstore list | grep 'KEY.BKPMON'" | awk '{print $2}' | grep BKPMON)
        _DATA_FULL="/tmp/gpfs_data_distribution_full.tmp"
        _DATA="/tmp/gpfs_data_distribution.tmp"
        _LOCALITY_ALL="/tmp/gpfs_data_distribution_all.tmp"
        _LOCALITY_FULL="/tmp/gpfs_data_distribution_full.tmp"
        _TOPOLOGY="/tmp/landscapeHostConfiguration.tmp"
        _QUERY="/tmp/sql_query.tmp"
        _DIR="/hana/shared/tools"
        _REP="/hana/shared/tools/replicainfo"
        [ -d "$_DIR" ] || mkdir -p "$_DIR"
        [ -f "$_REP" ] || wget -q -P "$_DIR" http://repo:50000/repo/CloudFrameSW/gpfs/replicainfo; chmod +x "$_DIR/replicainfo"

        echo "select * from M_VOLUME_FILES where FILE_TYPE='DATA'" > "$_QUERY"
        su - "$_SIDADM" -c "hdbsql -U "$_USERSTORE" -I "$_QUERY"" > $_DATA_FULL
        _PORT="$(cat "$_DATA_FULL" | grep -vi port | cut -d, -f2 | sort -nr | uniq -c | sort -nr | head -1 | awk '{print $2}')"
        cat "$_DATA_FULL" | grep "$_PORT" | cut -d, -f5 > $_DATA
        su - "$_SIDADM" -c "cdpy; python landscapeHostConfiguration.py" > $_TOPOLOGY
        _STANDBY="$(grep -i standby $_TOPOLOGY | wc -l)"

        if [ "$_STANDBY" -eq '2' ]; then
                printf "DB Topology\t\t\t\t[ NOK ] - WARNING: Master DB role is running on the standby, it's recommended to failback\n"
        else
                printf "DB Topology\t\t\t\t[ OK ] - Master is on its corresponding DB node\n"
        fi

        printf "GPFS locality check is running, it could take a few mins, check progress in:\n\t"$_LOCALITY_ALL"\n\t"$_LOCALITY_FULL"\n"

        echo "" > "$_LOCALITY_ALL"
        echo "" > "$_LOCALITY_FULL"
        for _CF in $(mmlscluster | awk '{print $2}' | grep CF); do
                _CF_m="$(echo $_CF | rev | cut -c2- | rev)"
                _VH_HOST="$(dig +short -x "$(ssh -q -tt $_CF ip a s external primary | grep inet | awk '{print $2}' | cut -d/ -f1)" | cut -d. -f1)"
                _VOLUME_ID="$(grep -iE "$_VH_HOST|$_CF|$_CF_m"  $_TOPOLOGY | awk '{print $10}')"
                if [ "$_VOLUME_ID" -ne '0' ]; then
                        _VOLUME="$(grep -E mnt0+"$_VOLUME_ID"/ $_DATA | sed 's/"//g')"
                        printf "$_VOLUME should be completely local in "$_CF"\n" >> "$_LOCALITY_FULL"; /hana/shared/tools/replicainfo replicapctpernode "$_VOLUME" >> "$_LOCALITY_FULL"; printf -- "--------------------\n" >> "$_LOCALITY_FULL"
                        _LOCALITY="$(/hana/shared/tools/replicainfo replicapctpernode "$_VOLUME" | grep $_CF | awk '{print $4}' | sed 's/%//g' | cut -d. -f1)"
        
                        if [ "$_LOCALITY" -lt '80' ]; then
                                printf "$_CF has $_LOCALITY%% of locality \t\t[ NOK ] - $_VOLUME\n" >> "$_LOCALITY_ALL"
                        elif [ "$_LOCALITY" -ge '80' ]; then
                                printf "$_CF has $_LOCALITY%% of locality \t\t[ OK ] - $_VOLUME\n" >> "$_LOCALITY_ALL"
                        fi
                else
                        printf "$_CF --> Configured as Standby\n" >> "$_LOCALITY_ALL"
                fi
        done
        
        if [ -f "$_LOCALITY_ALL" ] && grep "NOK" "$_LOCALITY_ALL" >/dev/null; then
                printf "GPFS Locality\t\t\t\t[ NOK ] - Locality below 80%%, more details: /tmp/qa-check.sh [CID] [locality_summary|locality_detailed]\n"
        else
                printf "GPFS Locality\t\t\t\t[ OK ] - Locality above 80%%, more details: /tmp/qa-check.sh [CID] [locality_summary|locality_detailed]\n"
        fi
}

gpfs_locality_summary(){
        _LOCALITY_ALL="/tmp/gpfs_data_distribution_all.tmp"
        [ -f "$_LOCALITY_ALL" ] && cat "$_LOCALITY_ALL" || printf "Please execute first: ./qa-check.sh [CID] [gpfs]\n"
}

gpfs_locality_detailed(){
        _LOCALITY_FULL="/tmp/gpfs_data_distribution_full.tmp"
        [ -f "$_LOCALITY_FULL" ] && cat "$_LOCALITY_FULL" || printf "Please execute first: ./qa-check.sh [CID] [gpfs]\n"
}

gpfs_check(){
        set +o pipefail
        _gpfs=$(df -Th 2>/dev/null | grep gpfs >/dev/null)
        if [ $? -eq '0' ];then
                set -o pipefail
                _restripeonDiskfailure_v=$(/usr/lpp/mmfs/bin/mmlsconfig restripeonDiskfailure | awk '{print $2}' | xargs);
                _running_gpfs_version=$(/usr/lpp/mmfs/bin/mmfsadm dump version | grep Build | xargs | awk '{print $3}' | xargs)
                _old_gpfs_packages=$(rpm -qa | grep gpfs | grep -v joschy | grep -v gpfs.gskit | grep -v "$_running_gpfs_version" | wc -l)
                _current_gpfs_packages=$(rpm -qa | grep gpfs | grep -v joschy | grep -E "gpfs.gskit|$_running_gpfs_version" | wc -l)
                [[ "$_restripeonDiskfailure_v" == "no" ]] && printf "GPFS restripeonDiskfailure disabled\t[ OK ]\n" || printf "GPFS restripeonDiskfailure disabled\t[ NOK ]\n"
                [[ "$_running_gpfs_version" == "$_recommended_gpfs_version" ]] && printf "GPFS version\t\t\t\t[ OK ]\n" || printf "GPFS version \t\t\t\t[ NOK ] - Recommended to upgrade to "$_recommended_gpfs_version"\n"
                [[ "$_old_gpfs_packages" -eq 0 ]] && printf "GPFS old version packages removed\t[ OK ]\n" || printf "GPFS old version packages removed\t[ NOK ]\n"
                [[ "$_current_gpfs_packages" -eq 6 ]] && printf "GPFS installed packages\t\t\t[ OK ]\n" || printf "GPFS installed packages\t\t\t[ NOK ]\n"
                gpfs_locality;
        else
                printf "GPFS checks\t\t\t\t[ N/A ] - Not a multi-scale GPFS server\n"
        fi
}

exit_msg(){
        printf "qa-check.sh: Missing arguments.\nPlease specify Customer ID (CID)\nUsage:\n\tqa-check.sh [CID] [function]\n"
        printf "\tAvailable functions:\n\t\tkernel\n\t\tfs\n\t\tdns\n\t\tvirtualip\n\t\thana\n\t\toptimization\n\t\tmisc\n\t\t[ Dont specify to use all ]\n\n"
        exit 1
}

main(){
        _CID_lenght=$(echo $_CID | wc -c ); [ $_CID_lenght -eq '4' ] || exit_msg
        echo $_CID | grep "[[:alnum:]]\{3\}" >/dev/null; [ $? -eq 0 ] || exit_msg
        set +o pipefail
        df 2>/dev/null | grep -i $_CID >/dev/null; [ $? -eq 0 ] || exit_msg
        set -o pipefail
        _function="$2"
        case "$_function" in
                kernel)         kernel_repo_check
                                ;;
                fs)             hana_backup_check
                                ;;
                dns)            dns_check
                                ;;
                virtualip)      virtualip_check
                                ;;
                hana)           crontab_check
                                ;;
                optimization)   network_optimization
                                ;;
                gpfs)           gpfs_check
                                ;;
                locality_summary)  gpfs_locality_summary
                                ;;
                locality_detailed) gpfs_locality_detailed
                                ;;
                misc)           memory_check
                                tic_check
                                ha_check
                                ;;
                all)
                                kernel_repo_check
                                network_optimization
                                hana_backup_check
                                dns_check
                                virtualip_check
                                crontab_check
                                gpfs_check
                                memory_check
                                tic_check
                                ha_check
                                ;;
        esac
}

_CID=${1:-"XXXX"}
_function=${2:-"all"}
main $_CID $_function


wget -q -P /tmp http://repo:50000/repo/SM/SCO/qa-check.sh 2>/dev/null; chmod +x /tmp/qa-check.sh; sh /tmp/qa-check.sh ald misc | grep HA

wget -P /tmp http://repo:50000/repo/SM/SCO/qa-check.sh 2>/dev/null; chmod +x /tmp/qa-check.sh; sh /tmp/qa-check.sh nbh gpfs
tic_info | grep Comment
sh /tmp/qa-check.sh dow kernel;
sh /tmp/qa-check.sh dow fs;
sh /tmp/qa-check.sh dow dns;
sh /tmp/qa-check.sh dow virtualip;
sh /tmp/qa-check.sh dow hana;
sh /tmp/qa-check.sh dow optimization;
sh /tmp/qa-check.sh dow gpfs;
sh /tmp/qa-check.sh dow misc;
rm /tmp/qa-check.sh;
######################
##
######################

###################us01c37n01

virtualip list | grep -A5 State | grep vh && printf "Virtualip\t\t[ OK ]\n" || printf "Virtualip\t\t[ NOK ]\n"
#cat /etc/resolv.conf

#cat /etc/sysconfig/pdnsd
#df -h
#echo "please check backup catalog manually..."

#echo "please check HA group manually..."
#tic_info


Ticket 1100663152 created successfully


reservation

1690
2190




https://www.blackmoreops.com/2014/10/28/delete-clean-cache-to-free-up-memory-on-your-slow-linux-server-vps/
https://serverfault.com/questions/597115/why-drop-caches-in-linux
http://blog.scoutapp.com/articles/2009/07/31/understanding-load-averages

http://www.traveler.es/viajes/mundo-traveler/articulos/18-hashtags-para-viajeros/5542
https://www.lovelystreets.com/blog/hashtags-que-todo-instagramer-viajero-debe-conocer/

https://in.accenture.com/skypeforbusiness/upgrade-to-skype-for-business-client-office-2016/


1100725019 
JEJEJ
LLEGO UNO ahorita
1100701077


R4P	APP:hec01v011819
APP:hec01v011820
DB:hec01v011817	ABAP	742 PL 300	745 PL 413 or the latest as of Apr	6-May
RWP	APP:hec01v014961
APP:hec01v014956
DB:de01c04n13	ABAP	742 PL 200	745 PL 413 or the latest as of Apr	6-May




hec03v013628
hec03v013629
hec03v013630
hec03v013631
hec03v013632
hec03v013633
hec03v013634
hec03v013635
hec03v013636
hec03v013637
hec03v013639
hec03v013640
hec03v013641
hec03v013642
hec03v013643
hec03v013644
hec03v013645
hec03v013646
hec03v013647
hec03v013648
hec03v013652



###display Areas
echo -e "\t\t ${RED} Post Installation/Post Patching Checks For Physical Server"
echo -e "\t\t   =========================================="
echo -e "\t\t$(tput setaf 4)SERVER:$(tput setaf 2)`hostname`"
echo -e "$(tput setaf 4)Tic Status Is                                         :"$(tput setaf $t0)$TIC2""
echo -e "$(tput setaf 4)Kernel version                                        :"$(tput setaf $t1)$k1""
echo -e "$(tput setaf 4)QPI Connection Checks                                 :"$(tput setaf $QPI1)$QPI2  $(tput setaf 4)$QPI3""
echo -e "$(tput setaf 4)Default Gateway                                       :"$(tput setaf 2)$GW $(tput setaf 4 )//Verify Gateway from TIC Tool""
echo -e "$(tput setaf 4)Fusion IO Version                                     :"$(tput setaf $t2)$f1         $(tput setaf 4)$STM1""
echo -e "$(tput setaf 4)IO Memory Version                                     :"$(tput setaf $t3)$I1         $(tput setaf 4)$STM1""
echo -e "$(tput setaf 4)Mcafee version updated                                :"$(tput setaf $t4)$M1""
echo -e "$(tput setaf 4)Separate tmpfs                                        :"$(tput setaf $t5)$T1""
echo -e "$(tput setaf 4)Separate Rootfs                                       :"$(tput setaf $t6)$R1""
echo -e "$(tput setaf 4)Check Instance Number                                 :"$(tput setaf $t7)$IN""
echo -e "$(tput setaf 4)Kernel Lock Enabled                                   :"$(tput setaf $t8)$KL1""
echo -e "$(tput setaf 4)Check BMC Agent is Running                            :"$(tput setaf $t9)$BMC""
echo -e "$(tput setaf 4)Check Old Kernel RPM Removed                          :"$(tput setaf $t11)$KRL_RPM    $(tput setaf 4)$STM2""
echo -e "$(tput setaf 4)PAM Security Check                                    :"$(tput setaf $t12)$PAM""
echo -e "$(tput setaf 4)Splunk service status                                 :"$(tput setaf $t14)$SPK1""
echo -e "$(tput setaf 4)CFM Version                                           :"$(tput setaf $t13)$hec_std""
echo -e "$(tput setaf 4)Backup Data FS Mount                                  :"$(tput setaf $t15)$bck_data1""
echo -e "$(tput setaf 4)Backup Log  FS Mount                                  :"$(tput setaf $t16)$bck_log1""
echo -e "$(tput setaf 4)Backup Data FS Layout is in standard(No Overmount)    :"$(tput setaf $c02)$nest_data""
echo -e "$(tput setaf 4)Backup Log  FS Layout is in Standard(No Overmount)    :"$(tput setaf $c03)$nest_log""

wget -P /tmp http://repo:50000/repo/SM/SCO/qa-check.sh 2>/dev/null; chmod +x /tmp/qa-check.sh; sh /tmp/qa-check.sh dow; rm /tmp/qa-check.sh
wget -P /tmp http://repo:50000/repo/SM/SCO/qa-check.sh 2>/dev/null; chmod +x /tmp/qa-check.sh; sh /tmp/qa-check.sh bry; rm /tmp/qa-check.sh
wget http://repo:50000/repo/SM/SCO/qa-check.sh 2>/dev/null; chmod +x /hana/shared/scripts/qa-check.sh; sh /hana/shared/scripts/qa-check.sh dow; rm /tmp/qa-check.sh



17759788

012180027907512511

wget http://repo:50000/repo/SM/SCO/qa-check.sh 2>/dev/null; chmod +x /hana/shared/scripts/qa-check.sh; mmdsh -f1 /hana/shared/scripts/qa-check.sh nee optimization 2>/dev/null; rm /hana/shared/scripts/qa-check.sh;