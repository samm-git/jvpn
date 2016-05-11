jvpn
====
Connect to Juniper Junos Pulse / Pulse Secure VPN on the command line without Java

## Features
 * Works *without Java* on both x86 and x86_64 hosts
 * Emulates web browser to get authentication data
 * Automatically starts juniper client and passes data to it using TCP socket
    connection.
 * Able to download Linux client from the VPN server without browser or
    Java.
 * Supports launching Host Checker to perform checks on a client host.
 * Option to protect resolv.conf by setting +i attribute for the connection time
 * Ability to run scripts on connect/disconnect events
 * Integration with external password/token providers, including "stoken" RSA
    softkey.
 * Ability to kick existing sessions (for example, you forgot to log out of the
    VPN on another system and/or your server is set up with connection count limits)

## Requirements
 * Perl with LWP modules (for https)
 * openssl binary
 * unzip (for client unpacking)

### Extra requirements for ncui mode (optional):
 (note the i686 requirements if your OS is 64-bit)
 * gcc
 * glibc-devel.i686
 * zlib.i686
 * libgcc.i686

## Usage
To configure jvpn.pl, edit jvpn.ini.

The first run of jvpn.pl (under sudo) will download and install the client automatically.

If you want to run it without sudo - set the suid bit on the "ncsvc" binary (chmod u+s ncsvc).

If you have multiple configurations - use the --conf switch to define ini file.

### How the script works
 1. Connects to the VPN web portal with provided user name and password (and PIN/token).
 2. Gets DSID value
 3. Gets md5 fingerprint of the SSL certificate
 4. If VPN client is not installed script downloads and unpacks it.
 5. Starts ncsvc and connects to it (using TCP 127.0.0.1:4242
    socket in ncsvc mode or using "ncui" wrapper in ncui mode).
 6. Script emulates (aka "fakes") native GUI and passes configuration data to daemon.
 7. Script can optionally protect resolv.conf from dhcpd or Network Manager by
    setting +i flag on it (disabled by default).
 8. On Ctrl+C script sending "Disconnect" command to the daemon and logs out
    by, again, emulating browser interaction.

### Difference between `mode=ncui` and `mode=ncsvc`
In "ncsvc" (default) mode jvpn establishes a TCP socket connection to nvsvc daemon and tries to establish connection using it protocol.

In "ncui" mode jvpn tries to use the main() function in libncui.so which later calls ncsvc. Basically, if default mode does not work for you, try ncui mode.

Please note that to use ncui mode you must have gcc and other stuff (noted above) installed.

### Scripting support
It is possible to run user-defined scripts on conncect/disconnect events. To
use this functionality you will need to define the script to run in the jvpn.ini
using the `script=<scriptname>` line. That script needs to be executable, of course.

List of pre-defined variables and sample route table modification can be found
in scripts/sample-script.sh.

### Different ways to provide password
By default jvpn asks for your password on startup. It is also possible to define
password in configuration file or to use external program to provide it (and
token).

To store password directly in jvpn.ini, use `password=plaintext:mypassword`.

If you write a helper script, it should simply print your password to stdout. If it is called a second time (some VPN servers request additional tokens) jvpn will define an "OLDPIN" variable containing first token code. See scripts/stoken.sh for example of "stoken" integration.

If you need to use an external token (either a key fob or a mobile phone app,
for example), set your password with the `password=xxx` parameter as above, and also set `token=1` in jvpn.ini.  You will be prompted to type in the token before the script attempts to connect.

### Hostchecker support
As of version 0.7.0 it is possible to run hostchecker using the `hostchecker=1` setting
in jvpn.ini. Hostchecker is used to perform checks on endpoint computers that
connect to the VPN device to make sure the endpoints meet certain security
requirements. If hostchecker support is enabled jvpn tries to run tncc.jar using
Java (emulating web browser applet behavior).

JRE needs to be installed to support this feature.

Generally, It is recommended to enable this only if you are unable to connect without it.

### Bugs and debugging
This script was written (and modified) without any official Juniper/Pulse documentation or support, only using wireshark/tcpdump, Firefox (to look at web forms) and a debugger. It is very likely that it has a bugs or will not work correctly for you.

If you need some support - enable debug and send me as much information as you can.

Script debug is written to stdout and daemon log is written to the
~/.juniper_networks/network_connect/ncsvc.log file.

## License
The author has placed this work in the Public Domain, thereby relinquishing
all copyrights. Everyone is free to use, modify, republish, sell or give away
this work without prior consent from anybody.

This software is provided on an "as is" basis, without warranty of any
kind. Use at your own risk! Under no circumstances shall the author(s) or
contributor(s) be liable for damages resulting directly or indirectly from
the use or non-use of this software.

## Authors
Original Author: Alex Samorukov <samm@os2.kiev.ua>

2015-2016 revisions author: Jeff Vier <jeff@jeffvier.com>
