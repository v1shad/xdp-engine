#!/usr/bin/env bash
# verify_phase6.sh - automated acceptance tests for Phase 6 (red team).
# Safe: only touches the lab (namespace "attacker", veth-host, fake logs).
set -u
cd "$(dirname "$0")"
DB="${ENGINE_DB:-../engine.db}"
PASS=0; FAIL=0; SKIP=0
ok()   { echo "[PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "[SKIP] $1"; SKIP=$((SKIP+1)); }
q()    { sqlite3 ../engine.db "$1" 2>/dev/null; }
listed() { ../engine-cli list 2>/dev/null; }

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 2; }

echo "=== T0: preconditions ==="
ip netns list | grep -q attacker && ok "namespace attacker exists" || bad "namespace attacker missing"
ip link show veth-host >/dev/null 2>&1 && ok "veth-host exists" || bad "veth-host missing"
[ -x ./attack_scenarios.sh ] && ok "attack_scenarios.sh executable" || bad "attack_scenarios.sh not executable"
[ -x ./fuzz_logs.sh ] && ok "fuzz_logs.sh executable" || bad "fuzz_logs.sh not executable"
[ -x ./reset_demo.sh ] && ok "reset_demo.sh executable" || bad "reset_demo.sh not executable"

echo "=== T1: reset_demo.sh works twice in a row ==="
for n in 1 2; do
  out=$(./reset_demo.sh < /dev/null 2>&1); rc=$?
  if [ $rc -eq 0 ] && echo "$out" | grep -q "READY"; then ok "reset run $n printed READY, exit 0"
  else bad "reset run $n failed (rc=$rc)"; echo "$out"; fi
done
../engine-cli stats >/dev/null 2>&1 && ok "engine-cli answers after reset" || bad "engine-cli not answering after reset"
[ "$(q 'select count(*) from events;')" = "0" ] && ok "fresh DB is empty after reset" || bad "DB not empty after reset"

echo "=== T2: --list has no side effects ==="
before=$(q 'select count(*) from events;')
./attack_scenarios.sh --list >/dev/null 2>&1; rc=$?
after=$(q 'select count(*) from events;')
[ $rc -eq 0 ] && ok "--list exits 0" || bad "--list exit code $rc"
[ "$before" = "$after" ] && ok "--list created no events" || bad "--list changed event count"

echo "=== T3: full attack run ==="
./attack_scenarios.sh --pause 2 >/tmp/p6_attack.txt 2>&1; rc=$?
[ $rc -eq 0 ] && ok "attack_scenarios.sh exit 0" || bad "attack_scenarios.sh exit code $rc"
sleep 8
L=$(listed)
echo "$L" | grep -q "10.10.0.2" && ok "stage1: 10.10.0.2 blocked" || bad "stage1: 10.10.0.2 NOT blocked"
echo "$L" | grep -q "10.10.0.3" && ok "stage2: 10.10.0.3 blocked" || bad "stage2: 10.10.0.3 NOT blocked"
echo "$L" | grep -q "10.10.0.4" && bad "stage3: 10.10.0.4 was blocked (limiter must not ban)" || ok "stage3: 10.10.0.4 not blocked"
echo "$L" | grep -q "10.10.0.5" && bad "stage4: 10.10.0.5 was blocked" || ok "stage4: 10.10.0.5 not blocked"
[ "$(q "select count(*) from events where src_ip='10.10.0.2' and type='port_scan';")" -ge 1 ] 2>/dev/null && ok "stage1: port_scan event for .2" || bad "stage1: no port_scan event for .2"
[ "$(q "select count(*) from alerts where rule='SCAN_THEN_BRUTE' and severity='critical' and src_ip='10.10.0.2';")" -ge 1 ] 2>/dev/null && ok "stage1: SCAN_THEN_BRUTE critical alert" || bad "stage1: SCAN_THEN_BRUTE alert missing"
[ "$(q "select count(*) from alerts where rule='SSH_BRUTE_FORCE' and src_ip='10.10.0.3';")" -ge 1 ] 2>/dev/null && ok "stage2: SSH_BRUTE_FORCE alert for .3" || bad "stage2: SSH_BRUTE_FORCE alert missing"
rl=$(q "select count(*) from events where src_ip='10.10.0.4' and type='rate_limit_exceeded';")
{ [ "${rl:-0}" -ge 1 ] && [ "${rl:-0}" -le 500 ]; } && ok "stage3: rate_limit events sampled ($rl rows)" || bad "stage3: rate_limit rows = ${rl:-none} (want 1..500)"
h=$(q "select group_concat(type) from (select distinct type from events where src_ip='10.10.0.5' and type like 'http_%' order by type);")
[ "$h" = "http_scanner,http_sqli,http_traversal" ] && ok "stage4: exactly three http_* types" || bad "stage4: http types = '${h:-none}'"
[ "$(q "select count(*) from events where src_ip='10.10.0.5' and type like 'http_%';")" = "3" ] && ok "stage4: exactly 3 http rows" || bad "stage4: http row count is not 3"

echo "=== T4: stage 3 source recovers (limiter, not a ban) ==="
sleep 5
ip netns exec attacker ping -c 2 -W 2 -I 10.10.0.4 10.10.0.1 >/dev/null 2>&1 && ok "10.10.0.4 can ping again" || bad "10.10.0.4 still cut off"

echo "=== T5: single stage isolation ==="
./reset_demo.sh < /dev/null >/dev/null 2>&1
./attack_scenarios.sh --stage 2 --pause 1 >/dev/null 2>&1
sleep 6
L=$(listed)
echo "$L" | grep -q "10.10.0.3" && ok "--stage 2 blocked .3" || bad "--stage 2 did not block .3"
echo "$L" | grep -q "10.10.0.2" && bad "--stage 2 also touched .2" || ok "--stage 2 left .2 alone"

echo "=== T6: Ctrl-C cleanup leaves no hping3 behind ==="
./reset_demo.sh < /dev/null >/dev/null 2>&1
./attack_scenarios.sh --stage 3 >/dev/null 2>&1 &
APID=$!
sleep 2; kill -INT "$APID" 2>/dev/null; wait "$APID" 2>/dev/null
sleep 2
pgrep -x hping3 >/dev/null && { bad "hping3 still running after Ctrl-C"; pkill -x hping3; } || ok "no stray hping3 after Ctrl-C"

echo "=== T7: static safety checks ==="
grep -q "10.10.0.1" attack_scenarios.sh && ok "target 10.10.0.1 hardcoded" || bad "target not hardcoded"
grep -nE 'hping3[^#]*\$\{?[1-9]' attack_scenarios.sh | grep -v "\-a" >/dev/null && bad "hping3 target may come from an argument" || ok "no argument-controlled hping3 target"
grep -nE '/var/log' fuzz_logs.sh attack_scenarios.sh | grep -v '^\s*#' >/dev/null && bad "script references /var/log" || ok "scripts never touch /var/log"
grep -q "set -u" attack_scenarios.sh && grep -q "set -u" fuzz_logs.sh && grep -q "set -u" reset_demo.sh && ok "all scripts use set -u" || bad "a script is missing set -u"
grep -nE 'system\(|popen\(' *.cpp *.h 2>/dev/null | grep -q . && bad "system()/popen() found in engine code" || ok "no system()/popen() in engine code"

echo "=== T8: fuzz run ==="
./reset_demo.sh < /dev/null >/dev/null 2>&1
fz=$(./fuzz_logs.sh 2>&1); echo "$fz" | tail -15
np=$(echo "$fz" | grep -c '\[PASS\]'); nf=$(echo "$fz" | grep -c '\[FAIL\]')
[ "$nf" -eq 0 ] && ok "fuzz: zero FAIL lines" || bad "fuzz: $nf FAIL lines"
[ "$np" -ge 8 ] && ok "fuzz: $np PASS lines (>= 8 expected)" || bad "fuzz: only $np PASS lines"
sleep 5
hx=$(q "select hex(user) from events where src_ip='10.20.0.2' limit 1;")
[ "$hx" = "EFBFBDEFBFBDEFBFBD" ] && ok "UTF-8 regression: invalid bytes sanitized" || bad "UTF-8 regression: hex was '${hx:-none}'"
pgrep -x engine >/dev/null && ok "engine alive after fuzzing" || bad "engine dead after fuzzing"
[ "$(sqlite3 ../engine.db 'PRAGMA integrity_check;')" = "ok" ] && ok "SQLite integrity ok" || bad "SQLite integrity check failed"
[ ! -e /tmp/pwned ] && ok "/tmp/pwned does not exist" || bad "/tmp/pwned exists - command injection!"

echo "=== T9: dashboard (optional) ==="
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:5000/api/summary 2>/dev/null)
if [ "$code" = "200" ]; then ok "dashboard /api/summary returns 200 after hostile input"
else skip "dashboard not running on 127.0.0.1:5000 (code ${code:-none})"; fi

echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
