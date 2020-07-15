# Flight PAM

A set of PAM modules using the Alces Flight Platform for authentication.

## Overview

Flight PAM is a set of PAM modules which uses the Alces Flight Platform for
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
    yum install https://alces-flight.s3-eu-west-1.amazonaws.com/repos/pub/centos/7/alces-flight-release-latest.noarch.rpm
    ```

 * Rebuild your `yum` cache:

    ```
    yum makecache
    ```
    
 * Install the `flight-pam` RPM:

    ```
    [root@myhost ~]# yum install flight-pam
    ```


## Configuration

The PAM configuration files located in `/etc/pam.d/` need to be edited to
enable Flight PAM.  The exact files and configuration vary from distro to
distro.  Some examples are shown below.

### Use Flight PAM for all password authentication on Centos 7

Edit the files `/etc/pam.d/password-auth` and `/etc/pam.d/system-auth` and add
the following line to the desired location.  We recommend adding it directly
above the `pam_unix.so` line.

```
auth        include       /opt/flight/etc/pam.d/flight
```

If `flight-pam` has been installed from source, you will have to adjust the
path to the location you have installed it to.

To ensure that SSH uses `flight-pam`, you will need to edit the file
`/etc/ssh/sshd_config` and ensure that `PasswordAuthentication`,
`ChallengeResponseAuthentication` and `UsePAM` are all set to `yes`.

Finally, restart `sshd`, `sudo systemctl restart sshd`.

### Restricting access to certain users

By default, Flight PAM supports authentication for all users with a `uid`
greater than `1000`.  This can be configured by setting the `minuid` parameter
in the file `/opt/flight/etc/plugin/pam.d/flight`, e.g.,

```
auth sufficient /opt/flight/usr/lib/security/pam_flight.so url=<URL> minuid=<minimum permitted UID>
```

If you wish to restrict the users Flight PAM permits to only those specified
in the user map file, you can set the `permit_non_mapped_users` argument to
`false` in the file `/opt/flight/etc/plugin/pam.d/flight`, e.g.,

```
auth sufficient /opt/flight/usr/lib/security/pam_flight.so url=<URL> permit_non_mapped_users=false
```


### Username mapping

It's possible that a user's UNIX username will not match their Flight
username.  Flight PAM supports mapping UNIX usernames to Flight usernames in
the file `/opt/flight/etc/security/flight_user_map.conf`.  The file is
commented explaining its format.  Briefly, to add a mapping from the UNIX
username "bob" to the Flight username "kate", add the following line:

```
bob: kate
```

## Prior work

This module is based on code taken from https://github.com/beatgammit/pam-http
and https://github.com/1nfiniteloop/pam-http both licensed under the MIT
license.
