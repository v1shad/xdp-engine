#!/bin/bash
# Benchmark script to compare No Filtering vs iptables vs XDP
# Warning: Do not run this on a production system. 

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./bench.sh)"
  exit 1
fi

# Check for iptables. If missing, tell the user what to install.
if ! command -v iptables &> /dev/null; then
    echo "iptables not found. Please install it with: sudo dnf install -y iptables"
    exit 1
fi

DURATION=20
RESULTS_FILE="bench_results.txt"
> "$RESULTS_FILE" # Clear the results file

# Define a cleanup trap to guarantee system stability even if Ctrl-C is pressed
cleanup() {
    echo -e "\nCleaning up lab state..."
    # Kill the flood if it's still running
    pkill -f "hping3.*--flood" 2>/dev/null
    # Kill the XDP engine if it's running
    pkill -f "./engine" 2>/dev/null
    # Remove the iptables rule (errors suppressed if it doesn't exist)
    iptables -t raw -D PREROUTING -s 10.10.0.2 -j DROP 2>/dev/null
}
trap cleanup EXIT INT TERM

# Function to run a 20-second test and gather stats
run_test() {
    local scenario_name=$1
    echo "Starting $scenario_name scenario (Please wait $DURATION seconds)..."
    
    # Start the SYN flood from the attacker namespace in the background
    ip netns exec attacker hping3 -S -p 22 --flood 10.10.0.1 >/dev/null 2>&1 &
    local HPING_PID=$!

    # Wait for the flood to stabilize
    sleep 2

    # Record the starting RX packet count on the host interface
    local rx_start=$(cat /sys/class/net/veth-host/statistics/rx_packets)
    
    # Record the starting global CPU statistics from /proc/stat
    read cpu user_s nice_s sys_s idle_s iowait_s irq_s soft_s steal_s rest < /proc/stat
    
    # Wait for the duration of the benchmark
    sleep $DURATION
    
    # Record the ending global CPU statistics
    read cpu user_e nice_e sys_e idle_e iowait_e irq_e soft_e steal_e rest < /proc/stat
    
    # Record the ending RX packet count
    local rx_end=$(cat /sys/class/net/veth-host/statistics/rx_packets)
    
    # Stop the hping3 flood
    kill -9 $HPING_PID 2>/dev/null
    wait $HPING_PID 2>/dev/null
    
    # Calculate Packets Per Second (PPS)
    local rx_delta=$((rx_end - rx_start))
    local pps=$((rx_delta / DURATION))
    
    # Calculate CPU percentages based on the delta of ticks
    local user_d=$((user_e - user_s))
    local sys_d=$((sys_e - sys_s))
    local idle_d=$((idle_e - idle_s))
    local soft_d=$((soft_e - soft_s))
    local total_d=$((user_d + sys_d + idle_d + soft_d + (nice_e-nice_s) + (iowait_e-iowait_s) + (irq_e-irq_s) + (steal_e-steal_s)))
    
    local softirq_pct=0
    local busy_pct=0
    if [ $total_d -gt 0 ]; then
        softirq_pct=$(( soft_d * 100 / total_d ))
        local busy_d=$((total_d - idle_d - (iowait_e-iowait_s)))
        busy_pct=$(( busy_d * 100 / total_d ))
    fi
    
    # Export metrics globally for the final table
    export "${scenario_name}_PPS"="$pps"
    export "${scenario_name}_SOFT"="$softirq_pct"
    export "${scenario_name}_BUSY"="$busy_pct"
    
    echo "$scenario_name completed."
}

# --- 1. BASELINE (No filtering) ---
run_test "BASELINE"
sleep 3

# --- 2. IPTABLES (Drop in raw PREROUTING table) ---
echo "Applying iptables block rule..."
iptables -t raw -A PREROUTING -s 10.10.0.2 -j DROP
run_test "IPTABLES"
iptables -t raw -D PREROUTING -s 10.10.0.2 -j DROP
sleep 3

# --- 3. XDP (Kernel-level drop) ---
echo "Starting XDP engine..."
touch /tmp/fake_auth.log
# Pipe the block command to the engine so it blocks the IP automatically, then sleeps to keep the engine alive
(echo "block 10.10.0.2 manual"; sleep 40; echo "quit") | ./engine veth-host xdp_prog.bpf.o /tmp/fake_auth.log > /dev/null 2>&1 &
ENGINE_PID=$!
sleep 2 # Let the engine load and attach the XDP program

run_test "XDP"

# Stop the engine gracefully
pkill -f "./engine" 2>/dev/null
wait $ENGINE_PID 2>/dev/null

# --- Print Results ---
echo "" | tee -a "$RESULTS_FILE"
echo "===========================================================" | tee -a "$RESULTS_FILE"
echo "                BENCHMARK RESULTS SUMMARY                  " | tee -a "$RESULTS_FILE"
echo "===========================================================" | tee -a "$RESULTS_FILE"
printf "%-15s | %-12s | %-10s | %-10s\n" "SCENARIO" "PACKETS/SEC" "CPU BUSY %" "SOFTIRQ %" | tee -a "$RESULTS_FILE"
echo "-----------------------------------------------------------" | tee -a "$RESULTS_FILE"
printf "%-15s | %-12s | %-10s | %-10s\n" "1. BASELINE" "${BASELINE_PPS}" "${BASELINE_BUSY}" "${BASELINE_SOFT}" | tee -a "$RESULTS_FILE"
printf "%-15s | %-12s | %-10s | %-10s\n" "2. IPTABLES" "${IPTABLES_PPS}" "${IPTABLES_BUSY}" "${IPTABLES_SOFT}" | tee -a "$RESULTS_FILE"
printf "%-15s | %-12s | %-10s | %-10s\n" "3. XDP" "${XDP_PPS}" "${XDP_BUSY}" "${XDP_SOFT}" | tee -a "$RESULTS_FILE"
echo "===========================================================" | tee -a "$RESULTS_FILE"
echo "* Note: veth interfaces use generic (software) XDP." | tee -a "$RESULTS_FILE"
echo "  Performance on real hardware with Native XDP driver" | tee -a "$RESULTS_FILE"
echo "  offload will be orders of magnitude higher." | tee -a "$RESULTS_FILE"
echo "Results saved to $RESULTS_FILE"
echo ""
