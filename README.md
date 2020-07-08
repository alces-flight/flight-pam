# Flight PAM

PAM module using the Alces Flight Platform for authentication.

## Overview

Flight PAM is a PAM module which uses the Alces Flight Platform for
authentication, allowing a user to use their Alces Flight Platform password to
authenticate their Linux account.

## Installation

### From source

Flight PAM works with libcurl v 7.29.0.

The following will install from source using `git`:

```
git clone https://github.com/alces-flight/flight-pam.git
cd flight-pam
make
sudo make install
```

### Installing from the Alces Flight RPM repository:

 * Enable the Alces Flight RPM repository:

    ```
    yum install https://alces-flight.s3-eu-west-1.amazonaws.com/repos/alces-flight/x86_64/alces-flight-release-1-1.noarch.rpm
    ```

 * Rebuild your `yum` cache:

    ```
    yum makecache
    ```
    
 * Install the `flight-pam` RPM:

    ```
    [root@myhost ~]# yum install flight-pam
    ```

 * Link the files into place.

    ```
    [root@myhost ~]# ln -s /opt/flight/etc/pam.d/flight /etc/pam.d/flight
    ```


## Configuration

The PAM configuration files located in `/etc/pam.d/` need to be edited to
enable Flight PAM.  The exact files and configuration vary from distro to
distro.  Some examples are shown below.

### Use Flight PAM for SSH access on Centos 7

If `flight-pam` has been installed from source create the file
`/etc/pam.d/flight` containing the following:

```
#%PAM-1.0
auth sufficient pam-flight.so url=https://accounts.alces-flight.com/sign-in
```

If `flight-pam` was installed from the RPM using the instructions above you
will already have created a suitable symlink at `/etc/pam.d/flight`.

Edit the file `/etc/pam.d/sshd` and add the line

```
auth include flight
```

Edit the file `/etc/ssh/sshd_config` and ensure that `PasswordAuthentication`,
`ChallengeResponseAuthentication` and `UsePAM` are all set to `yes`.

Finally, restart `sshd`, `sudo systemctl restart sshd`.


## Prior work

This module is based on code taken from https://github.com/beatgammit/pam-http
and https://github.com/1nfiniteloop/pam-http both licensed under the MIT
license.
