#!/bin/bash
# Benchmark script to compare No Filtering vs iptables vs XDP (Averaged over 3 runs)
# Warning: Do not run this on a production system. 

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./bench.sh)"
  exit 1
fi

if ! command -v iptables &> /dev/null; then
    echo "iptables not found. Please install it with: sudo dnf install -y iptables"
    exit 1
fi

DURATION=20
RESULTS_FILE="bench_results.txt"
> "$RESULTS_FILE"

cleanup() {
    echo -e "\nCleaning up lab state..."
    pkill -f "hping3.*--flood" 2>/dev/null
    pkill -f "./engine" 2>/dev/null
    iptables -t raw -D PREROUTING -s 10.10.0.2 -j DROP 2>/dev/null
    iptables -D INPUT -s 10.10.0.2 -j DROP 2>/dev/null
}
trap cleanup EXIT INT TERM

get_iptables_raw_drops() {
    local pkts=$(iptables -t raw -nvx -L PREROUTING 2>/dev/null | awk '/10\.10\.0\.2.*DROP/ {print $1}')
    echo "${pkts:-0}"
}

get_iptables_filter_drops() {
    local pkts=$(iptables -nvx -L INPUT 2>/dev/null | awk '/10\.10\.0\.2.*DROP/ {print $1}')
    echo "${pkts:-0}"
}

run_scenario() {
    local name=$1
    echo "=== Starting Scenario: $name ==="
    
    local sum_pps=0
    local sum_busy=0
    local sum_soft=0
    local sum_core=0
    local sum_drops=0
    
    for i in {1..3}; do
        echo "  Run $i/3 (Please wait ~$DURATION seconds)..."
        
        local drops_start=0
        if [ "$name" == "IPTABLES_RAW" ]; then
            iptables -t raw -A PREROUTING -s 10.10.0.2 -j DROP
            drops_start=$(get_iptables_raw_drops)
        elif [ "$name" == "IPTABLES_FILTER" ]; then
            iptables -A INPUT -s 10.10.0.2 -j DROP
            drops_start=$(get_iptables_filter_drops)
        elif [ "$name" == "XDP" ]; then
            > /tmp/xdp_out.txt
            touch /tmp/fake_auth.log
            (echo "block 10.10.0.2 manual"; sleep $DURATION; sleep 2; echo "stats"; sleep 1; echo "quit") | ./engine veth-host xdp_prog.bpf.o /tmp/fake_auth.log > /tmp/xdp_out.txt 2>&1 &
            ENGINE_PID=$!
            sleep 2
            
            # Check attach mode while it's running (only need to do it once)
            if [ -z "$XDP_MODE" ]; then
                XDP_MODE=$(ip -details link show veth-host | grep -o "xdp[^ ]*" | head -n1)
                [ -z "$XDP_MODE" ] && XDP_MODE="xdp"
            fi
        fi
        
        ip netns exec attacker hping3 -S -p 22 --flood 10.10.0.1 >/dev/null 2>&1 &
        local HPING_PID=$!
        sleep 2
        
        local rx_start=$(cat /sys/class/net/veth-host/statistics/rx_packets)
        local cpu_stats_start=$(grep "^cpu" /proc/stat)
        
        sleep $DURATION
        
        local cpu_stats_end=$(grep "^cpu" /proc/stat)
        local rx_end=$(cat /sys/class/net/veth-host/statistics/rx_packets)
        
        kill -9 $HPING_PID 2>/dev/null
        wait $HPING_PID 2>/dev/null
        
        local drops_end=0
        if [ "$name" == "IPTABLES_RAW" ]; then
            drops_end=$(get_iptables_raw_drops)
            iptables -t raw -D PREROUTING -s 10.10.0.2 -j DROP
        elif [ "$name" == "IPTABLES_FILTER" ]; then
            drops_end=$(get_iptables_filter_drops)
            iptables -D INPUT -s 10.10.0.2 -j DROP
        elif [ "$name" == "XDP" ]; then
            wait $ENGINE_PID 2>/dev/null || true
            pkill -f "./engine" 2>/dev/null
            drops_end=$(grep "packets dropped=" /tmp/xdp_out.txt | tail -n 1 | sed -n 's/.*packets dropped=\([0-9]*\).*/\1/p')
            [ -z "$drops_end" ] && drops_end=0
        fi
        
        local pps=$(( (rx_end - rx_start) / DURATION ))
        sum_pps=$((sum_pps + pps))
        
        local drops_d=$((drops_end - drops_start))
        local dps=$(( drops_d / DURATION ))
        sum_drops=$((sum_drops + dps))
        
        local sys_busy=0
        local sys_soft=0
        local max_core=0
        
        while IFS= read -r line_s && IFS= read -r line_e <&3; do
            read c_name user_s nice_s sys_s idle_s iowait_s irq_s soft_s steal_s rest <<< "$line_s"
            read c_name_e user_e nice_e sys_e idle_e iowait_e irq_e soft_e steal_e rest <<< "$line_e"
            
            local total_d=$(( (user_e-user_s) + (nice_e-nice_s) + (sys_e-sys_s) + (idle_e-idle_s) + (iowait_e-iowait_s) + (irq_e-irq_s) + (soft_e-soft_s) + (steal_e-steal_s) ))
            if [ $total_d -gt 0 ]; then
                local busy_d=$(( total_d - (idle_e-idle_s) - (iowait_e-iowait_s) ))
                local busy_pct=$(( busy_d * 100 / total_d ))
                local soft_pct=$(( (soft_e-soft_s) * 100 / total_d ))
                
                if [ "$c_name" == "cpu" ]; then
                    sys_busy=$busy_pct
                    sys_soft=$soft_pct
                else
                    if [ $busy_pct -gt $max_core ]; then
                        max_core=$busy_pct
                    fi
                fi
            fi
        done <<< "$cpu_stats_start" 3<<< "$cpu_stats_end"
        
        sum_busy=$((sum_busy + sys_busy))
        sum_soft=$((sum_soft + sys_soft))
        sum_core=$((sum_core + max_core))
        
        sleep 2
    done
    
    export "${name}_PPS"="$((sum_pps / 3))"
    export "${name}_BUSY"="$((sum_busy / 3))"
    export "${name}_SOFT"="$((sum_soft / 3))"
    export "${name}_CORE"="$((sum_core / 3))"
    export "${name}_DROPS"="$((sum_drops / 3))"
}

run_scenario "BASELINE"
run_scenario "IPTABLES_FILTER"
run_scenario "IPTABLES_RAW"
run_scenario "XDP"

echo "" | tee -a "$RESULTS_FILE"
echo "=================================================================================" | tee -a "$RESULTS_FILE"
echo "                           BENCHMARK RESULTS (AVERAGE OF 3 RUNS)                 " | tee -a "$RESULTS_FILE"
echo "=================================================================================" | tee -a "$RESULTS_FILE"
printf "%-18s | %-12s | %-12s | %-9s | %-9s | %-9s\n" "SCENARIO" "RX PKTS/SEC" "DROP PKTS/SEC" "SYS CPU %" "SYS SOFT%" "MAX CORE%" | tee -a "$RESULTS_FILE"
echo "---------------------------------------------------------------------------------" | tee -a "$RESULTS_FILE"
printf "%-18s | %-12s | %-12s | %-9s | %-9s | %-9s\n" "1. BASELINE" "${BASELINE_PPS}" "${BASELINE_DROPS}" "${BASELINE_BUSY}" "${BASELINE_SOFT}" "${BASELINE_CORE}" | tee -a "$RESULTS_FILE"
printf "%-18s | %-12s | %-12s | %-9s | %-9s | %-9s\n" "2. IPTABLES_FILTER" "${IPTABLES_FILTER_PPS}" "${IPTABLES_FILTER_DROPS}" "${IPTABLES_FILTER_BUSY}" "${IPTABLES_FILTER_SOFT}" "${IPTABLES_FILTER_CORE}" | tee -a "$RESULTS_FILE"
printf "%-18s | %-12s | %-12s | %-9s | %-9s | %-9s\n" "3. IPTABLES_RAW" "${IPTABLES_RAW_PPS}" "${IPTABLES_RAW_DROPS}" "${IPTABLES_RAW_BUSY}" "${IPTABLES_RAW_SOFT}" "${IPTABLES_RAW_CORE}" | tee -a "$RESULTS_FILE"
printf "%-18s | %-12s | %-12s | %-9s | %-9s | %-9s\n" "4. XDP ($XDP_MODE)" "${XDP_PPS}" "${XDP_DROPS}" "${XDP_BUSY}" "${XDP_SOFT}" "${XDP_CORE}" | tee -a "$RESULTS_FILE"
echo "=================================================================================" | tee -a "$RESULTS_FILE"
echo "* Veth is virtual; results on real NICs were not measured." | tee -a "$RESULTS_FILE"
echo "Results saved to $RESULTS_FILE"
echo ""
