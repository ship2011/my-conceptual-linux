#!/bin/bash
#this script is for joining Redhat 9/8 server to AD

ad_pack(){
        pack=(sssd realmd oddjob oddjob-mkhomedir adcli samba-common samba-common-tools krb5-workstation openldap-clients)
        for i in "${pack[@]}"
           do
             echo "installing $i"
             yum -y install $i > /dev/null
             if [ "$?" -ne "0" ]
                then
                   echo "Something worng, please try to install package $i manaully"
                   exit 127
             fi
         done

}

ad_join(){
        echo "you need to enter your AD user"
        realm join --user=aduser ADSERVER.EXAMPLE.COM
        sed -i 's/use_fully_qualified_name.*/use_fully_qualified_name = False/' /etc/sssd/sssd.conf
        sed -i 's/fallback_homedir.*/fallback_homedir = \/home\/%u/' /etc/sssd/sssd.conf
        systemctl daemon-reload
        systemctl restart sssd
        systemctl enable sssd
        
}

update_group(){
        grep -i admingroup /etc/sudoers.d/sudo-admin  > /dev/null
        if [ "$?" -ne "0" ]
           then
            echo -e "%admingroup ALL=(ALL) : ALL\n%anothergroup ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/sudo-admin
          fi
  }

ad_pack
ad_join
update_group
