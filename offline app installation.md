

# Offline Package Installation Guide

This guide will walk you through the steps of installing a package offline on a Linux machine.

## On the Online Machine

### Set the `PKG` variable to the name of the package you want to install on the offline machine.
```
[root@localhost ~]# PKG=powershell
```

### Run the following command to download the package to the `/tmp/$PKG` directory: ==note: change `releasever=7` to the centos version you want to install the package on==
```
[root@localhost ~]# yum install --downloadonly --installroot=/tmp/$PKG-installroot --releasever=7 --downloaddir=/tmp/$PKG $PKG
```

### Run the following command to create a repository for the package:

```
[root@localhost ~]# createrepo --database /tmp/$PKG
```

### Remove the temporary installation directory:
```
[root@localhost ~]# rm -rf /tmp/$PKG-installroot
```

### Move the directory to the offline machine on the `/tmp/` directory; you can use `rsync` to copy the package files to the offline machine:
```
[root@localhost ~]# rsync -arv /tmp/$PKG/ [IP of the machine]:/tmp/$PKG
```


## On the Offline Machine

### Set the  `PKG`  variable to the name of the package you want to install:
```
[root@localhost ~]# PKG=powershell
```

###  Setup the repo: ==note: change CentOS-7 to your version of centos==

```
[root@localhost ~]# echo "[offline-$PKG]
name=CentOS-\$releasever - $PKG
baseurl=file:///tmp/$PKG/
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7" >  /etc/yum.repos.d/offline-$PKG.repo
```

### Install the package:
```
[root@localhost ~]# yum --disablerepo=* --enablerepo=offline-$PKG install --nogpgcheck $PKG
```

Once the package has been installed, you can remove the `/tmp/$PKG` directory.

## Notes

-   This method works for CentOS 7. For other versions of centos, change the `--releasever` and `CentOS-7` spot.
-   This method works for upwards compatibility; you can install `centos7` packages on `centos8` online machine and transfer them to the `centos7` machine but not the other way around
