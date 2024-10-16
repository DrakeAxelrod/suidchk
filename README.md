# suidchk

## Overview

This Rust program is a CLI tool designed to scan a system for SUID binaries that could potentially be exploited for privilege escalation. It provides detailed information about the binaries found and their associated exploitation techniques. The tool is particularly useful for penetration testers, system administrators, and security professionals who need to assess the security risks posed by SUID binaries.

## Features

- **SUID Binary Detection**: Recursively Scans the system to identify SUID binaries, which could be used for privilege escalation.
- **Exploitation Techniques**: For each identified binary, when possible the tool provides potential command-line examples that can be used to escalate privileges.
- **Color-Coded Output**: Uses colorized output to enhance readability.
- **Fast Scanning**: Efficiently walks through directories to identify binaries, leveraging the `jwalk` crate for performance optimization.
- **Timestamped Execution**: Includes timestamping to track the execution time for scans.
- **No Network**: Does not require network access

## Usage

1.  Clone the repository:

    ```sh
    git clone https://github.com/your-repo/suidchk.git
    ```

2.  Build the program:

    ```sh
    just build
    ```

3.  Run the program with the target directory:

    ```sh
    ./suidchk
    ```

A statically compiled binary has been placed in this project to enable fetching quickly without having to deal with any of the build steps.

## Example Output

Upon running the tool, the following output structure will appear:

```plaintxt
  ___ _   _(_) __| | ___| |__ | | __
 / __| | | | |/ _` |/ __| '_ \| |/ /
 \__ \ |_| | | (_| | (__| | | |   <
 |___/\__,_|_|\__,_|\___|_| |_|_|\_\
          [Created by Drake Axelrod]

[INFO] Started on 2024-10-16 16:08:17.951982663 +02:00
[FOUND] /usr/libexec/polkit-agent-helper-1
[FOUND] /usr/share/code/chrome-sandbox
[FOUND] /usr/bin/kismet_cap_hak5_wifi_coconut
[FOUND] /usr/bin/su
[FOUND] /usr/bin/kismet_cap_ti_cc_2540
[FOUND] /usr/bin/mount
[FOUND] /usr/bin/kismet_cap_nrf_mousejack
[FOUND] /usr/bin/rlogin
[FOUND] /usr/bin/sg
[FOUND] /usr/bin/kismet_cap_nrf_52840
[FOUND] /usr/bin/vmware-user
[FOUND] /usr/bin/kismet_cap_rz_killerbee
[FOUND] /usr/bin/gpasswd
[FOUND] /usr/bin/vmware-user-suid-wrapper
[FOUND] /usr/bin/newgrp
[FOUND] /usr/bin/umount
[FOUND] /usr/bin/chfn
[FOUND] /usr/bin/rsh
[FOUND] /usr/bin/fusermount
[FOUND] /usr/bin/kismet_cap_ubertooth_one
[FOUND] /usr/bin/kismet_cap_nxp_kw41z
[FOUND] /usr/bin/pkexec
[VULNERABLE] /usr/bin/gawk

LFILE=file_to_read
./gawk '//' "$LFILE"

[FOUND] /usr/bin/kismet_cap_nrf_51822
[FOUND] /usr/bin/kismet_cap_ti_cc_2531
[FOUND] /usr/bin/fusermount3
[VULNERABLE] /usr/bin/awk

LFILE=file_to_read
./awk '//' "$LFILE"

[FOUND] /usr/bin/kismet_cap_linux_wifi
[FOUND] /usr/bin/rsh-redone-rlogin
[FOUND] /usr/bin/passwd
[VULNERABLE] /usr/bin/nawk

LFILE=file_to_read
./nawk '//' "$LFILE"

[FOUND] /usr/bin/rsh-redone-rsh
[FOUND] /usr/bin/sudoedit
[FOUND] /usr/bin/chsh
[FOUND] /usr/bin/sudo
[FOUND] /usr/bin/ntfs-3g
[FOUND] /usr/bin/kismet_cap_linux_bluetooth
[FOUND] /usr/lib/dbus-1.0/dbus-daemon-launch-helper
[FOUND] /usr/lib/openssh/ssh-keysign
[FOUND] /usr/lib/chromium/chrome-sandbox
[FOUND] /usr/lib/polkit-1/polkit-agent-helper-1
[FOUND] /usr/lib/xorg/Xorg.wrap
[FOUND] /usr/lib/policykit-1/polkit-agent-helper-1
[FOUND] /usr/lib/obsidian/chrome-sandbox
[FOUND] /usr/sbin/mount.cifs
[FOUND] /usr/sbin/mount.ntfs-3g
[FOUND] /usr/sbin/pppd
[FOUND] /usr/sbin/mount.nfs
[FOUND] /usr/sbin/mount.ntfs
[FOUND] /usr/sbin/mount.smb3
[FOUND] /usr/sbin/umount.nfs
[FOUND] /usr/sbin/mount.nfs4
[FOUND] /usr/sbin/umount.nfs4
[FOUND] /opt/Pomatez/chrome-sandbox
[FOUND] /opt/microsoft/msedge/msedge-sandbox
[FOUND] /etc/alternatives/rlogin
[FOUND] /etc/alternatives/rsh
[VULNERABLE] /etc/alternatives/awk

LFILE=file_to_read
./awk '//' "$LFILE"

[VULNERABLE] /etc/alternatives/nawk

LFILE=file_to_read
./nawk '//' "$LFILE"

[INFO] Ended on 2024-10-16 16:09:38.884797912 +02:00
[INFO] Total execution time 79.38
```

## Exploitation Details

Each vulnerable binary is matched against known exploitation techniques from [GTFObins](https://gtfobins.github.io/) stored in a `HashMap`. For example:

- **Binary**: `bash`
    - **Exploit Command**: `./bash -p`

This information can help assess the risk posed by each SUID binary and how it might be leveraged in a security compromise.

## Dependencies

- **colored**: For colorful terminal output.
- **jwalk**: For fast, parallel directory walking.
- **chrono**: For handling timestamps and logging.

Install dependencies by running:

```sh
cargo install colored jwalk chrono
```

## Contributions

Feel free to contribute by submitting pull requests or reporting issues. Any additional SUID binary exploit techniques can also be suggested!

## License

This project is licensed under the MIT License.

## Special Thanks

- [GTFObins](https://gtfobins.github.io/)