#!/usr/bin/bash
#This script I have written to take backup of Azure based of NFS file system and keep their copy in Azure standard storage 
#As of now Azure doesn't support Azure NFS file system backup so this script will be mount NFS file system in read only in /mnt 
#And then it will mount Azure based Standard file share as CIFS in mnt and then sync NFS to CIFS and create archive of previous day
#Also delete archive copy which is older than 15 days. 

mount_nfs() {
    [[ -d "/mnt/bk/nfsfilesystem1" ]] || /usr/bin/mkdir -p /mnt/bk/nfsfilesystem1
       /usr/bin/mount -o ro file1.file.core.windows.net:/file1 /mnt/bk/nfsfilesystem1
    [[ -d "/mnt/bk/nfsfilesystem2" ]] || /usr/bin/mkdir -p /mnt/bk/nfsfilesystem2
       /usr/bin/mount -o ro file2.file.core.windows.net:/file2 /mnt/bk/nfsfilesystem2
    [[ -d "/mnt/bk/nfsfilesystem3" ]] || /usr/bin/mkdir -p /mnt/bk/nfsfilesystem3
      /usr/bin/mount -o ro file3.file.core.windows.net:/file3 /mnt/bk/nfsfilesystem3
}
mount_bknfs() {
    [[ -d "/mnt/bk/nfsfilesystem1-bak" ]] || /usr/bin/mkdir -p /mnt/bk/nfsfilesystem1-bk
    /usr/bin/mount -t cifs //file1cifs.file.core.windows.net/file1cifs  /mnt/bk/nfsfilesystem1-bk -o credentials=/etc/cfislogin.cred,dir_mode=0777,file_mode=0777
    [[ -d "/mnt/bk/nfsfilesystem2-bak" ]] || /usr/bin/mkdir -p /mnt/bk/nfsfilesystem2-bk
    /usr/bin/mount -t cifs //file2cifs.file.core.windows.net/file2cifs  /mnt/bk/nfsfilesystem2-bk -o credentials=/etc/cfislogin.cred,dir_mode=0777,file_mode=0777
    [[ -d "/mnt/bk/nfsfilesystem3-bak" ]] || /usr/bin/mkdir -p /mnt/bk/nfsfilesystem3-bk
    /usr/bin/mount -t cifs //file3cifs.file.core.windows.net/file3cifs  /mnt/bk/nfsfilesystem3-bk -o credentials=/etc/cfislogin.cred,dir_mode=0777,file_mode=0777

}

archive_bak() {
        lst=("/mnt/bk/nfsfilesystem1-bk" "/mnt/bk/nfsfilesystem2-bk" "/mnt/bk/nfsfilesystem3-bk")
        for ar in ${lst[@]}
        do
          [[ -d "$ar/archive" ]] || /usr/bin/mkdir $ar/archive
          [[ -d "$ar/current-bk" ]] || echo "$(date +%Y-%m-%d-%T): $ar/current-bk dones not present >> /var/log/backupscript.log
           /usr/bin/tar -zcf $ar/archive/backup$(date +%Y-%m-%d-%H-%M).tar.gz -C $ar current-bk
        done

}

sync_vol_bknfs() {
        declare -A sync_vol
        sync_vol["/mnt/bk/nfsfilesystem1"]=/mnt/bk/nfsfilesystem1-bk
        sync_vol["/mnt/bk/nfsfilesystem2"]=/mnt/bk/nfsfilesystem2-bk
        sync_vol["/mnt/bk/nfsfilesystem3"]=/mnt/bk/nfsfilesystem3-bk
        for i in ${!sync_vol[@]}
           do
             [[ -d "${sync_vol[$i]}/current-bk" ]] || /usr/bin/mkdir ${sync_vol[$i]}/current-bk
             echo "$i--${sync_vol[$i]}"
             ls -ld ${sync_vol[$i]}/current-bak
             /usr/bin/rsync -azv --delete  $i/ ${sync_vol[$i]}/current-bak/
           done

}
clean_oldbk() {
    fd=("/mnt/bk/nfsfilesystem1-bk" "/mnt/bk/nfsfilesystem2-bk" "/mnt/bk/nfsfilesystem3-bk")
    for f in ${fd[@]}
     do
        /usr/bin/find $f/archive/ -type f -mtime +15 -delete
     done


}

umount_nfs() {
       /usr/bin/umount /mnt/bk/nfsfilesystem1
       /usr/bin/umount /mnt/bk/nfsfilesystem2
       /usr/bin/umount /mnt/bk/nfsfilesystem3
       /usr/bin/umount /mnt/bk/nfsfilesystem1-bk
       /usr/bin/umount /mnt/bk/nfsfilesystem2-bk
       /usr/bin/umount /mnt/bk/nfsfilesystem3-bk
 }

mount_nfs && mount_bknfs
if [[ "$?" -eq "0" ]]
   then
     archive_bak
     sync_vol_bknfs
     echo "$(date +%Y-%m-%d-%T) tar and sync action completed successfully" >> /var/log/backupscript.log
   else
     echo "$(date +%Y-%m-%d-%T) tar and sync action didn't complete successfully" >> /var/log/backupscript.log
   fi
clean_oldbk
umount_nfs

