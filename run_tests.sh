#!/bin/bash

# PPFE automated test script (using Network Namespace to realistically simulate network environment)
# Solved the problem of 127.0.0.1 bypassing tc configuration

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration parameters
ENTRY_SIZE=8
PORT=8080
SERVER_IP="10.0.0.1"  # IP in network namespace
CLIENT_IP="10.0.0.2"
RESULTS_DIR="./test_results"

# CPU core affinity configuration (using taskset to improve performance)
SERVER_CPU_CORE=0  # Server bound to CPU core 0
CLIENT_CPU_CORE=1  # Client bound to CPU core 1

# Set library path
export LD_LIBRARY_PATH=/root/troy-nova/build/src:$LD_LIBRARY_PATH

# Database size parameters (Log2DBSize)
DB_SIZES=(10 12 14 16 18 20 22)

# Network environment configuration
# Format: "Network Name|Latency|Bandwidth"
NETWORK_CONFIGS=(
    "Net1_3gbit|800us|3gbit"
    "Net2_1gbit|800us|1gbit"
    "Net3_200mbit|40ms|200mbit"
    "Net4_100mbit|80ms|100mbit"
)

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script requires root privileges to configure the network environment${NC}"
        echo "Please use: sudo ./run_tests.sh"
        exit 1
    fi
}

# Check number of CPU cores
check_cpu_cores() {
    local num_cores=$(nproc)
    echo -e "${BLUE}Checking CPU core count...${NC}"
    echo -e "  System CPU cores: ${num_cores}"
    echo -e "  Server will use core: ${SERVER_CPU_CORE}"
    echo -e "  Client will use core: ${CLIENT_CPU_CORE}"
    
    if [ $num_cores -lt 2 ]; then
        echo -e "${YELLOW}Warning: System only has ${num_cores} CPU cores, at least 2 are recommended for best performance${NC}"
        echo -e "${YELLOW}Server and client will share the same CPU core${NC}"
    else
        echo -e "${GREEN}✓ Sufficient CPU cores, independent cores will be assigned to server and client${NC}"
    fi
    echo ""
}

# Create network namespace and virtual pair
setup_namespaces() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}Setup Network Namespace Environment${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    cleanup_namespaces 2>/dev/null
    
    echo -e "${BLUE}Creating network namespaces...${NC}"
    ip netns add server_ns
    ip netns add client_ns
    
    echo -e "${BLUE}Creating virtual ethernet pair veth0 <-> veth1...${NC}"
    ip link add veth0 type veth peer name veth1
    
    ip link set veth0 netns server_ns
    ip link set veth1 netns client_ns
    
    echo -e "${BLUE}Configuring IP addresses...${NC}"
    ip netns exec server_ns ip addr add ${SERVER_IP}/24 dev veth0
    ip netns exec client_ns ip addr add ${CLIENT_IP}/24 dev veth1
    
    ip netns exec server_ns ip link set lo up
    ip netns exec client_ns ip link set lo up
    
    ip netns exec server_ns ip link set veth0 up
    ip netns exec client_ns ip link set veth1 up
    
    echo -e "${GREEN}✓ Network Namespace environment setup complete${NC}"
    echo -e "  Server: server_ns (${SERVER_IP})"
    echo -e "  Client: client_ns (${CLIENT_IP})"
    echo ""
}

cleanup_namespaces() {
    echo -e "${BLUE}Cleaning up Network Namespace...${NC}"
    ip netns del server_ns 2>/dev/null
    ip netns del client_ns 2>/dev/null
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

setup_network_in_client() {
    local delay=$1
    local rate=$2
    
    echo -e "${BLUE}Configuring network limits in client: delay=${delay}, rate=${rate}${NC}"
    ip netns exec client_ns tc qdisc del dev veth1 root 2>/dev/null
    ip netns exec client_ns tc qdisc add dev veth1 root netem delay ${delay} rate ${rate}
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Network limits configured successfully${NC}"
        echo -e "${CYAN}Current network configuration:${NC}"
        ip netns exec client_ns tc qdisc show dev veth1
        return 0
    else
        echo -e "${RED}✗ Failed to configure network limits${NC}"
        return 1
    fi
}

clear_network_in_client() {
    echo -e "${BLUE}Clearing client network limits...${NC}"
    ip netns exec client_ns tc qdisc del dev veth1 root 2>/dev/null
    echo -e "${GREEN}✓ Network limits cleared${NC}"
}

test_connectivity() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}Test Network Connectivity${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    echo -e "${BLUE}Client pinging server...${NC}"
    ip netns exec client_ns ping -c 3 ${SERVER_IP}
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Network connectivity normal${NC}"
        return 0
    else
        echo -e "${RED}✗ Network connectivity test failed${NC}"
        return 1
    fi
}

verify_network_limits() {
    local delay=$1
    local rate=$2
    
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}Verify Network Limits${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    echo -e "${BLUE}Expected: delay=${delay}, rate=${rate}${NC}"
    local ping_output=$(ip netns exec client_ns ping -c 5 ${SERVER_IP} | grep "avg")
    echo -e "${CYAN}Ping results: ${ping_output}${NC}"
    
    local avg_rtt=$(echo $ping_output | awk -F'/' '{print $5}')
    echo -e "${YELLOW}Average RTT: ${avg_rtt} ms (Configured delay: ${delay})${NC}"
    echo ""
}

start_server() {
    local log2dbsize=$1
    local entrysize=$2
    local port=$3
    local logfile=$4
    
    echo -e "${BLUE}Starting server in server_ns...${NC}"
    ip netns exec server_ns taskset -c ${SERVER_CPU_CORE} bash -c "export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}; ./build/s3pir_server $log2dbsize $entrysize $port" > "$logfile" 2>&1 &
    SERVER_PID=$!
    
    echo -e "${YELLOW}Waiting for server to be ready...${NC}"
    local timeout=30
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if ! ps -p $SERVER_PID > /dev/null; then
            echo -e "${RED}✗ Server process exited${NC}"
            cat "$logfile"
            return 1
        fi
        # Adjust the grep string below to match your server's actual "Ready" output
        if grep -qi "Waiting for client connection" "$logfile" 2>/dev/null; then
            echo -e "${GREEN}✓ Server ready (PID: $SERVER_PID)${NC}"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    
    echo -e "${RED}✗ Timeout waiting for server${NC}"
    return 1
}

stop_server() {
    if [ ! -z "$SERVER_PID" ]; then
        echo -e "${BLUE}Stopping server (PID: $SERVER_PID)...${NC}"
        kill $SERVER_PID 2>/dev/null
        wait $SERVER_PID 2>/dev/null
        SERVER_PID=""
    fi
}

run_client() {
    local server_ip=$1
    local port=$2
    local output_file=$3
    local logfile=$4
    
    echo -e "${BLUE}Running client in client_ns...${NC}"
    ip netns exec client_ns taskset -c ${CLIENT_CPU_CORE} bash -c "export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}; ./build/s3pir_client $server_ip $port $output_file" > "$logfile" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Client finished successfully${NC}"
        return 0
    else
        echo -e "${RED}✗ Client failed. Check log: $logfile${NC}"
        return 1
    fi
}

run_all_tests() {
    local success_count=0
    local total_count=0
    
    for dbsize in "${DB_SIZES[@]}"; do
        for net_config in "${NETWORK_CONFIGS[@]}"; do
            IFS='|' read -r network_name delay rate <<< "$net_config"
            total_count=$((total_count + 1))
            
            local test_name="${network_name}_log2db${dbsize}"
            local output_file="${RESULTS_DIR}/${test_name}.csv"
            local srv_log="${RESULTS_DIR}/${test_name}_server.log"
            local cli_log="${RESULTS_DIR}/${test_name}_client.log"

            setup_network_in_client "$delay" "$rate"
            if start_server "$dbsize" "$ENTRY_SIZE" "$PORT" "$srv_log"; then
                run_client "$SERVER_IP" "$PORT" "$output_file" "$cli_log"
                [ $? -eq 0 ] && success_count=$((success_count + 1))
                stop_server
            fi
            clear_network_in_client
        done
    done
    echo -e "\n${CYAN}Final Stats: Success ${success_count}/${total_count}${NC}"
}

check_prerequisites() {
    mkdir -p "$RESULTS_DIR"
    if [ ! -f "./build/s3pir_server" ] || [ ! -f "./build/s3pir_client" ]; then
        echo -e "${RED}Error: Binaries not found in ./build/. Please compile first.${NC}"
        exit 1
    fi
}

main() {
    check_root
    check_cpu_cores
    check_prerequisites
    
    local cmd=${1:-test}
    case $cmd in
        setup)   setup_namespaces ;;
        cleanup) cleanup_namespaces ;;
        test)
            setup_namespaces
            test_connectivity && run_all_tests
            cleanup_namespaces
            ;;
        *) echo "Usage: sudo $0 {test|setup|cleanup}" ;;
    esac
}

trap cleanup_namespaces EXIT
main "$@"