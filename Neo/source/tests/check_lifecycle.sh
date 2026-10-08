#!/bin/sh
# The package's shell scripts against fakes: S99hrneo (raw-off, ipset-clean,
# start) and prerm. Each script runs in its own busybox sh, from a copy in a
# scratch root where /opt, /var/run and /proc/locks point, so rc.func, hrneo,
# pidof, sleep, lsmod, iptables, ip6tables and rmmod are fakes that log what
# they are asked. Every scenario checks the whole log, so order and absence
# count too.
set -u
SRC=$(cd "$(dirname "$0")/.." && pwd)
T="$SRC/build/lifecycle"
FAILS=0
NAME=

rm -rf "$T"
mkdir -p "$T/opt/etc/init.d" "$T/opt/bin" "$T/run"
export FAKE_LOG="$T/log" FAKE_ST="$T/state" FAKE_LOCKS="$T/locks"
S99="$T/opt/etc/init.d/S99hrneo"
PRERM="$T/prerm"

copy() {    # <source> <copy>: the script with its system paths in the scratch root
    [ -f "$1" ] || { : > "$2"; return; }
    sed -e "s#/opt/#$T/opt/#g" -e "s#/var/run/#$T/run/#g" -e "s#/proc/locks#$FAKE_LOCKS#g" "$1" > "$2"
    chmod 0755 "$2"
}
copy "$SRC/ipk/rootfs/opt/etc/init.d/S99hrneo" "$S99"
copy "$SRC/ipk/control/prerm" "$PRERM"

# rc.func is sourced by the init script: it logs its action and, for stop,
# makes the process go (ok), take 3 more polls (slow) or stay (stuck).
cat > "$T/opt/etc/init.d/rc.func" <<'EOF'
echo "rc.func $1 caller=${2:-} ARGS=$ARGS" >> "$FAKE_LOG"
case "$1" in
    stop)
        case "$(cat "$FAKE_ST/stop_mode")" in
            ok) echo 0 > "$FAKE_ST/alive" ;;
            slow) echo 3 > "$FAKE_ST/alive" ;;
        esac
        ;;
    start) echo 99 > "$FAKE_ST/alive" ;;
esac
EOF
# pidof: alive holds how many more polls see the process; 99 means for good.
cat > "$T/opt/bin/pidof" <<'EOF'
#!/bin/sh
n=$(cat "$FAKE_ST/alive")
[ "$n" -gt 0 ] || exit 1
[ "$n" = 99 ] || echo $((n - 1)) > "$FAKE_ST/alive"
echo 4242
EOF
cat > "$T/opt/bin/hrneo" <<'EOF'
#!/bin/sh
echo "hrneo $*" >> "$FAKE_LOG"
exit "$(cat "$FAKE_ST/hrneo_rc")"
EOF
for ipt in iptables ip6tables; do
    cat > "$T/opt/bin/$ipt" <<EOF
#!/bin/sh
echo "$ipt \$*" >> "\$FAKE_LOG"
cat "\$FAKE_ST/$ipt.out"
exit "\$(cat "\$FAKE_ST/$ipt.rc")"
EOF
done
cat > "$T/opt/bin/lsmod" <<'EOF'
#!/bin/sh
cat "$FAKE_ST/lsmod"
EOF
for cmd in sleep rmmod; do
    printf '#!/bin/sh\necho "%s $*" >> "$FAKE_LOG"\n' "$cmd" > "$T/opt/bin/$cmd"
done
chmod 0755 "$T"/opt/bin/*

EMPTY_RAW='-P PREROUTING ACCEPT
-P OUTPUT ACCEPT'
SLEEPS='sleep 1
sleep 1
sleep 1
sleep 1
sleep 1
sleep 1
sleep 1
sleep 1
sleep 1
sleep 1'

# A fresh state: hrneo running and stopping when asked, its lock free,
# hrneo --raw-off working, both raw modules loaded with empty tables.
scenario() {
    NAME=$1
    rm -rf "$FAKE_ST"
    mkdir -p "$FAKE_ST"
    : > "$FAKE_LOG"
    : > "$FAKE_LOCKS"
    rm -f "$T/run/hrneo.lock"
    echo 99 > "$FAKE_ST/alive"
    echo ok > "$FAKE_ST/stop_mode"
    echo 0 > "$FAKE_ST/hrneo_rc"
    for ipt in iptables ip6tables; do
        printf '%s\n' "$EMPTY_RAW" > "$FAKE_ST/$ipt.out"
        echo 0 > "$FAKE_ST/$ipt.rc"
    done
    printf 'iptable_raw 2158 0 - Live 0x0\nip6table_raw 2168 0 - Live 0x0\n' > "$FAKE_ST/lsmod"
}

fail() {
    echo "check_lifecycle: $NAME: $*" >&2
    FAILS=$((FAILS + 1))
}

# run <rc> <script> <args...>: runs it in its own sh, checks the exit code.
run() {
    want=$1
    shift
    sh "$@" > "$T/out" 2>&1
    got=$?
    [ "$got" = "$want" ] || fail "exit $got, want $want; output: $(cat "$T/out")"
}

log_is() {
    [ "$(cat "$FAKE_LOG")" = "$1" ] || fail "log:
$(cat "$FAKE_LOG")
want:
$1"
}

out_has() {
    grep -qF "$1" "$T/out" || fail "output lacks '$1': $(cat "$T/out")"
}

for f in "$S99" "$PRERM"; do
    [ -s "$f" ] && sh -n "$f" || { NAME=syntax; fail "$f missing or not sh"; }
done

# --- S99hrneo ---------------------------------------------------------------

scenario start
run 0 "$S99" start
log_is "rc.func start caller= ARGS="

scenario restart-keeps-sets
run 0 "$S99" restart
log_is "rc.func restart caller= ARGS="

scenario raw-off
run 0 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
hrneo --raw-off"
out_has "RawGuard=true puts the raw guard back"

scenario raw-off-already-stopped
echo 0 > "$FAKE_ST/alive"
run 0 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
hrneo --raw-off"

scenario raw-off-slow-stop
echo slow > "$FAKE_ST/stop_mode"
run 0 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
sleep 1
sleep 1
sleep 1
hrneo --raw-off"

scenario raw-off-stop-timeout
echo stuck > "$FAKE_ST/stop_mode"
run 1 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
$SLEEPS"
out_has "hrneo did not stop within 10 s"

scenario raw-off-lock-held
# No hrneo process, yet the lock is taken (/proc/locks names its inode).
: > "$T/run/hrneo.lock"
set -- $(ls -i "$T/run/hrneo.lock")
echo "1: FLOCK  ADVISORY  WRITE 4242 00:4f:$1 0 EOF" > "$FAKE_LOCKS"
echo "2: FLOCK  ADVISORY  WRITE 4243 00:4f:1$1 0 EOF" >> "$FAKE_LOCKS"
run 1 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
$SLEEPS"

scenario raw-off-other-lock
# A lock on another file does not count.
: > "$T/run/hrneo.lock"
set -- $(ls -i "$T/run/hrneo.lock")
echo "2: FLOCK  ADVISORY  WRITE 4243 00:4f:1$1 0 EOF" > "$FAKE_LOCKS"
echo "3: FLOCK  ADVISORY  WRITE 4244 00:4f:${1}7 0 EOF" >> "$FAKE_LOCKS"
run 0 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
hrneo --raw-off"

scenario raw-off-fails
echo 1 > "$FAKE_ST/hrneo_rc"
run 1 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
hrneo --raw-off"

scenario raw-off-started-meanwhile
echo 2 > "$FAKE_ST/hrneo_rc"
run 2 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
hrneo --raw-off"

scenario raw-off-status-unsaved
# Exit 3: the rules are gone, the status file was not saved; hrneo said so.
echo 3 > "$FAKE_ST/hrneo_rc"
run 3 "$S99" raw-off
log_is "rc.func stop caller= ARGS=
hrneo --raw-off"
out_has "RawGuard=true puts the raw guard back"

scenario ipset-clean
run 0 "$S99" ipset-clean awg
log_is "rc.func stop caller=awg ARGS=
rc.func start caller=awg ARGS=--KeepIpsetOnRestart false --clearIPSet true"

scenario ipset-clean-slow-stop
echo slow > "$FAKE_ST/stop_mode"
run 0 "$S99" ipset-clean
log_is "rc.func stop caller= ARGS=
sleep 1
sleep 1
sleep 1
rc.func start caller= ARGS=--KeepIpsetOnRestart false --clearIPSet true"

scenario ipset-clean-stop-timeout
echo stuck > "$FAKE_ST/stop_mode"
run 1 "$S99" ipset-clean
log_is "rc.func stop caller= ARGS=
$SLEEPS"
out_has "hrneo did not stop within 10 s"

# --- prerm ------------------------------------------------------------------

scenario prerm-upgrade
run 0 "$PRERM" upgrade 1:3.21.0-1le3
log_is ""

scenario prerm-other-actions
run 0 "$PRERM" failed-upgrade 1:3.21.0-1le3
run 0 "$PRERM"
log_is ""

scenario prerm-remove
run 0 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
hrneo --raw-off
iptables -w -t raw -S
rmmod iptable_raw
ip6tables -w -t raw -S
rmmod ip6table_raw"

scenario prerm-remove-v6-not-loaded
printf 'iptable_raw 2158 0 - Live 0x0\nxt_CT 3000 0 - Live 0x0\n' > "$FAKE_ST/lsmod"
run 0 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
hrneo --raw-off
iptables -w -t raw -S
rmmod iptable_raw"

scenario prerm-remove-foreign-rules
printf '%s\n-A PREROUTING -p udp -m udp --dport 9 -j CT --notrack\n' "$EMPTY_RAW" > "$FAKE_ST/iptables.out"
printf '%s\n-A OUTPUT -o lo -j CT --notrack\n' "$EMPTY_RAW" > "$FAKE_ST/ip6tables.out"
run 0 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
hrneo --raw-off
iptables -w -t raw -S
ip6tables -w -t raw -S"

scenario prerm-remove-foreign-chain-or-policy
printf '%s\n-N FOREIGN\n' "$EMPTY_RAW" > "$FAKE_ST/iptables.out"
printf -- '-P PREROUTING DROP\n-P OUTPUT ACCEPT\n' > "$FAKE_ST/ip6tables.out"
run 0 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
hrneo --raw-off
iptables -w -t raw -S
ip6tables -w -t raw -S"

scenario prerm-remove-dump-fails
echo 1 > "$FAKE_ST/iptables.rc"
: > "$FAKE_ST/ip6tables.out"
run 0 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
hrneo --raw-off
iptables -w -t raw -S
ip6tables -w -t raw -S"
out_has "iptables -t raw -S failed, iptable_raw stays loaded"

scenario prerm-remove-stop-timeout
echo stuck > "$FAKE_ST/stop_mode"
run 1 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
$SLEEPS"
out_has "package kept"

scenario prerm-remove-raw-off-fails
echo 1 > "$FAKE_ST/hrneo_rc"
run 1 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
hrneo --raw-off"
out_has "package kept"

scenario prerm-remove-status-unsaved
# The rules are gone; the status file means nothing once the package goes.
echo 3 > "$FAKE_ST/hrneo_rc"
run 0 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
hrneo --raw-off
iptables -w -t raw -S
rmmod iptable_raw
ip6tables -w -t raw -S
rmmod ip6table_raw"
out_has "warning: raw guard removed, but its status file was not saved"

scenario prerm-remove-again
echo 0 > "$FAKE_ST/alive"
: > "$FAKE_ST/lsmod"
run 0 "$PRERM" remove
log_is "rc.func stop caller= ARGS=
hrneo --raw-off"

rm -rf "$T"
[ "$FAILS" = 0 ] || { echo "check_lifecycle: $FAILS failures" >&2; exit 1; }
echo "check_lifecycle: OK"
