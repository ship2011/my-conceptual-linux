#!/bin/bash

function kernel_parameter {

      FILE_SYS="/etc/sysctl.d/01-custom-SYS.conf"
      [[ -f $FILE_SYS ]]|| touch $FILE_SYS
      parmater_0=("fs.suid_dumpable"
"net.ipv4.ip_forward" 
"net.ipv4.conf.all.send_redirects" 
"net.ipv4.conf.default.send_redirects" 
"net.ipv4.conf.all.accept_source_route" 
"net.ipv4.conf.default.accept_source_route"
"net.ipv4.conf.all.accept_redirects" 
)
      for i in "${parmater_0[@]}"
         do 
          value0=$(sysctl -n $i)
          if [ "$value0" -eq "0" ]
             then 
               echo "$i paramter present"
             else 
                echo "$i=0" >> $FILE_SYS
                sysctl -p $FILE_SYS > /dev/null
             fi
         done
      parmater_1=("net.ipv4.icmp_echo_ignore_broadcasts"
"net.ipv4.icmp_ignore_bogus_error_responses"
"net.ipv4.conf.all.rp_filter"
"net.ipv4.tcp_syncookies")
      for l in "${parmater_1[@]}"
          do
           value1=$(sysctl -n $l)
          if [ "$value1" -eq "1" ]
             then
               echo "$l paramter present"
             else
               echo "$l=1" >> $FILE_SYS
               sysctl -p $FILE_SYS
           fi
         done
      value2=$(sysctl -n kernel.randomize_va_space)
      if [ "$value2" -eq "2" ]
        then
          echo "kernel.randomize_va_space paramter persent"
        else
          echo "$value2=2" >> $FILE_SYS
          sysctl -p $FILE_SYS
      fi
      (grep '^* hard core 0' /etc/security/limits.conf &&  grep '^* soft core 0' /etc/security/limits.conf) > /dev/null
      if [ "$?" -ne "0" ]
      then
       sed -i '/End of file/i * hard core 0\n* soft core 0'  /etc/security/limits.conf
      fi
}

function sshd_update {
    cp /etc/ssh/sshd_config /tmp/sshd_config.bk-$(date +%d-%m-%y)
    sshd_file="/etc/ssh/sshd_config"
    egrep "^Protocol" $sshd_file > /dev/null
    if [ "$?" -eq "0" ]
    then 
      sed -i 's/^Protocol.*/Protocol 2/' $sshd_file
    else
      sed -i '/Port\s22/i Protocol 2' $sshd_file
    fi
    egrep "^LogLevel" $sshd_file > /dev/null
    if [ "$?" -eq "0" ]
    then
      sed -i 's/^LogLevel.*/LogLevel INFO/' $sshd_file
    else
      sed -i '/LogLevel\s/i LogLevel INFO' $sshd_file
    fi
    function ssh_repeat {
      egrep "^$1" $sshd_file > /dev/null
      if [ "$?" -eq "0" ]
      then
        sed -i "s/^$1.*/$1 $2/" $sshd_file
      else
        sed -i "/$3/i $1 $2" $sshd_file
      fi
    }
    ssh_repeat "X11Forwarding" "no" "AllowTcpForwarding\s"
    ssh_repeat "MaxAuthTries" "4" "MaxAuthTries\s"
    ssh_repeat "IgnoreRhosts" "yes" "IgnoreRhosts\s"
    ssh_repeat "HostbasedAuthentication" "no" "HostbasedAuthentication\s"
    ssh_repeat "PermitRootLogin" "no" "LoginGraceTime\s"
    ssh_repeat "PermitEmptyPasswords" "no" "PermitEmptyPasswords\s"
    ssh_repeat "PermitUserEnvironment" "no" "PermitUserEnvironment\s"
    ssh_repeat "ClientAliveInterval" "300" "Compression\s"
    ssh_repeat "ClientAliveCountMax" "3" "ClientAliveCountMax\s"
    ssh_repeat "Ciphers" "aes128-ctr,aes192-ctr,aes256-ctr" "RekeyLimit\s"
    ssh_repeat "AllowGroups" "users ag-linux-admins ag-sapbasis-admins" "Match User"
    ssh_repeat "Banner" "\/etc\/issue.net" "Banner"
    chown root:root $sshd_file
    chmod 644 $sshd_file
    systemctl reload sshd
}

function pass_parm {
      pam-config --add --cracklib-retry=3 --cracklib-minlen=15 --cracklib-lcredit=13 --cracklib-ucredit=1 --cracklib-dcredit=15 --cracklib-ocredit=1 --cracklib-difok=5
      pam-config -a --pwhistory --pwhistory-remember=24
      LOGIN_FILE="/etc/login.defs"
      sed -i 's/^UMASK.*/UMASK 0077/' $LOGIN_FILE
      sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' $LOGIN_FILE
      sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' $LOGIN_FILE
      sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' $LOGIN_FILE
      [[ -f /etc/default/useradd ]] && sed -i 's/^INACTIVE.*/INACTIVE=7/' /etc/default/useradd
}

function msg_parm {
    echo "type any message which you want in motd file" > /etc/motd
    
    echo "type any message which you want on issue.net file" > /etc/issue.net
  
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
chown root:root /etc/issue
chmod 640 /etc/issue
chown root:shadow /etc/shadow
chmod 400 /etc/shadow
chown root:root /etc/group
chmod 644 /etc/group
chown root:root /etc/passwd
}

function parm_crontab {
        
        systemctl restart cron.service
        if [ "$?" -ne "0" ]
        then 
           echo "Unable to restart crond troubleshooting needed"
        fi
        [[ -f /etc/cron.allow ]] || touch /etc/cron.allow
        [[ -f /etc/cron.deny ]] || touch /etc/cron.deny
	parm=(/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d /etc/cron.deny /etc/cron.allow)
	for i in ${parm[@]}
         do 
           [[ -f $i ]] && chown -R root:root $i && chmod 640 $i
           [[ -d $i ]] && chown -R root:root $i && chmod 700 $i
       
          done
          
}

function parm_rsyslog {
           rpm -qa|grep rsyslog > /dev/null
           if [ "$?" -ne "0" ]
            then
             zypper -n in rsyslog > /dev/null
            fi
           systemctl restart rsyslog.service
           if [ "$?" -ne "0" ]
           then 
             echo "Unable to start rsyslog service, Need to check"
           fi
          [[ -f /etc/rsyslog.conf ]] && chown root:root /etc/rsyslog.conf && chmod 600 /etc/rsyslog.conf 


}

function audit_rules {
    systemctl enable auditd.service
    audit_sys="/etc/audit/rules.d/audit.rules"
    audit_repeat(){
    grep "$1" $audit_sys > /dev/null
    if [ "$?" -ne "0" ]
    then 
     echo "$2" >> $audit_sys 
    fi
      }

    audit_repeat "adjtimex" "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules"
    audit_repeat "settimeofday" "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules"
    audit_repeat "clock_settime" "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules"
    audit_repeat "/etc/localtime" "-w /etc/localtime -p wa -k audit_time_rules" 
    audit_repeat "/etc/group" "-w /etc/group -p wa -k identity"
    audit_repeat "/etc/passwd" "-w /etc/passwd -p wa -k identity"
    audit_repeat "/etc/gshadow" "-w /etc/gshadow -p wa -k identity"
    audit_repeat "/etc/shadow" "-w /etc/shadow -p wa -k identity"
    audit_repeat "/etc/security/opasswd" "-w /etc/security/opasswd -p wa -k identity"
    audit_repeat "sethostname" "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale"
    audit_repeat "setdomainname" "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications"
    audit_repeat "/etc/issue" "-w /etc/issue -p wa -k system-locale"
    audit_repeat "/etc/issue.net" "-w /etc/issue.net -p wa -k system-locale"
    audit_repeat "/etc/hosts" "-w /etc/hosts -p wa -k system-locale"
    audit_repeat "/etc/sysconfig/network" "-w /etc/sysconfig/network -p wa -k system-locale"
    audit_repeat "/etc/selinux" "-w /etc/selinux/ -p wa -k MAC-policy"
    audit_repeat "/var/log/faillog" "-w /var/log/faillog -p wa"
    audit_repeat "/var/log/lastlog" "-w /var/log/lastlog -p wa -k logins"
    audit_repeat "/var/log/tallylog" "-w /var/log/tallylog -p wa"
    audit_repeat "/var/run/utmp" "-w /var/run/utmp -p wa -k session"
    audit_repeat "/var/run/wtmp" "-w /var/run/wtmp -p wa -k session"
    audit_repeat "/var/run/btmp" "-w /var/run/btmp -p wa -k session"
    audit_repeat "chmod" "-a always,exit -S chmod -S fchmod -S chown -S fchown -S lchown -S fchownat -S fchmodat"
    audit_repeat "setxattr" "-a always,exit -S setxattr"
    audit_repeat "lsetxattr" "-a always,exit -S lsetxattr"
    audit_repeat "fsetxattr" "-a always,exit -S fsetxattr"
    audit_repeat "removexattr" "-a always,exit -S removexattr"
    audit_repeat "lremovexattr" "-a always,exit -S lremovexattr"
    audit_repeat "fremovexattr" "-a always,exit -S fremovexattr"
    audit_repeat "truncate" "-a always,exit -S creat -S open -S truncate -S openat -S ftruncate"
    audit_repeat "4294967295" "-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged"
    audit_repeat "unlink" "-a always,exit -S unlink -S unlinkat -S rename -S renameat -S link -S symlink"
    audit_repeat "/etc/sudoers" "-w /etc/sudoers -p wa -k scope"
    audit_repeat "/var/log/sudo.log" "-w /var/log/sudo.log -p wa -k actions"
    audit_repeat "-e 2" "-e 2"
    systemctl restart rsyslog.service
    systemctl restart auditd.service
    grep GRUB_CMDLINE_LINUX_DEFAULT /etc/default/grub|grep -o " audit=1\"$" > /dev/null
    if [ "$?" -ne "0" ]
    then
     sed -i '/GRUB_CMDLINE_LINUX_DEFAULT/ s/"$/ audit=1"/' /etc/default/grub
     cp /boot/grub2/grub.cfg /tmp/grub.cfg_$(date "+%d-%m-%y")
     grub2-mkconfig -o /boot/grub2/grub.cfg 2> /dev/null
     echo "Reboot the OS"
    fi
    
}
val="$2"
function os_filesystem {
      SIZE="$(expr $(($(awk '/MemTotal:/ {print $2}' /proc/meminfo) / 1000)) / 1000 / 2)G"
      mkdir /opt/bk
      rsync -Paxr /home /opt/bk/
      rsync -Paxr /var /opt/bk/
      rsync -Paxr /tmp /opt/bk/
 
      if [[ ! $val =~ (sda|sdb) ]]
      then
       PART=$(lsblk /dev/$val|wc -l)
       DISK=$(lsblk /dev/$val|awk 'NR == 2 {print $6}')
       echo "$DISK $val $PART"
       if [ "$PART" -le "2" ] && [ "$DISK" == "disk" ]
        then
         echo "$val $DISK start woring"
         VOL=infravol
         vgs |grep -o $VOL
         if [ "$?" -ne "0" ]
         then
          pvcreate /dev/$val
          vgcreate $VOL /dev/$val 
          lvcreate -L 5G -n tmp $VOL 
          lvcreate -L 10G -n var $VOL
          lvcreate -L 10G -n varlog $VOL
          lvcreate -L 10G -n varlogaudit $VOL
          lvcreate -L 5G -n home $VOL
          LVNAME=($VOL-tmp $VOL-var $VOL-varlog $VOL-varlogaudit $VOL-home)
          for i in ${LVNAME[@]}
          do
           mkfs.xfs /dev/mapper/$i
          done
          sed -i "/vfat/a /dev/mapper/${LVNAME[0]} /tmp  xfs    defaults,nodev,nosuid,noexec    0 0" /etc/fstab
          mount /tmp
          chmod -R 1777 /tmp
          sed -i "/${LVNAME[0]}/a /dev/mapper/${LVNAME[1]} /var  xfs    defaults    0 0" /etc/fstab
          mount /var
          mkdir -p /var/log
          mkdir -p /var/tmp
          sed -i "/${LVNAME[1]}/a /tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0" /etc/fstab
          sed -i "/${LVNAME[1]}/a /dev/mapper/${LVNAME[2]} /var/log  xfs    defaults    0 0" /etc/fstab
          mount /var/log
          mkdir -p /var/log/audit
          sed -i "/${LVNAME[2]}/a /dev/mapper/${LVNAME[3]} /var/log/audit  xfs    defaults    0 0" /etc/fstab
          mount /var/log/audit
          sed -i "/vfat/a /dev/mapper/${LVNAME[4]} /home  xfs    defaults,nodev    0 0" /etc/fstab
          mount /home
          sed -i "/${LVNAME[4]}/a shm /dev/shm  tmpfs   defaults,nodev,nosuid,noexec,size=$SIZE 0 0" /etc/fstab
         fi
        fi
      fi

     rsync -Paxr /opt/bk/home/ /home
     rsync -Paxr /opt/bk/var/ /var
     rsync -Paxr /opt/bk/tmp/ /tmp
}


if [ ! -z "$val" ] && [ "$1" == "-ospart" ]
then
echo $val
######For creating infra file system this fucntion will be used#####
os_filesystem $val
fi
############For updating rsyslog parameter this function will be used#######
parm_rsyslog
###########For updating audit rules this function will be used########
audit_rules
############For updating kernel parameters this function will be used#########
kernel_parameter
#############For updating parameters in SSHD file this function will be used######
sshd_update
##############For updating password related paramaters this function will be used#####3
pass_parm
############For updating banner related messages this function will be used########
msg_parm
############For updating crontab related parameter this function will be used#########
parm_crontab
