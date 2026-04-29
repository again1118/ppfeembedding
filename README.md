# PPFE
Preprocessed Private Function Evaluation: Achieving Sublinear
Online Complexity for Lookup Tables

### System Requirements
- **OS**: Linux (tested on Ubuntu/Debian)
- **Compiler**: `g++` with C++20 support
- **Build Tool**: `make`
- **Optional**: `CUDA` (for GPU acceleration via Troy)

### Libraries
- [Troy](https://github.com/v6p/Troy) (included in `encryption/` directory)
- [Crypto++](https://www.cryptopp.com/)
- [libOTe](https://github.com/osu-crypto/libOTe)
- [cryptoTools](https://github.com/osu-crypto/cryptoTools)
- [coproto](https://github.com/osu-crypto/coproto)
- [libsodium](https://doc.libsodium.org/)
- [SimplestOT](https://github.com/mkschreiber/SimplestOT)

## Compilation

The project uses a standard `Makefile`. To build the server and client executables, run:

```bash
make
```

This will generate the following binaries in the `build/` directory:
- `build/s3pir_server`: The standalone server executable.
- `build/s3pir_client`: The standalone client executable.
- `build/s3pir`: Unified test executable.
- `build/s3pir_simlargeserver`: Version simulating a large server database.

To clean the build:
```bash
make clean
```

## Usage

### 1. Manual Execution

#### Start the Server:
```bash
./build/s3pir_server <Log2DBSize> <EntrySize> <Port>
```
Example:
```bash
./build/s3pir_server 16 8 8080
```
- `Log2DBSize`: Log base 2 of the number of entries (e.g., 16 for 65,536 entries).
- `EntrySize`: Size of each database entry in bytes (must be a multiple of 8).
- `Port`: Port to listen on.

#### Run the Client:
```bash
./build/s3pir_client <ServerIP> <Port> <OutputFile>
```
Example:
```bash
./build/s3pir_client 127.0.0.1 8080 results.csv
```
- `ServerIP`: IP address of the PPFE server.
- `Port`: Target port on the server.
- `OutputFile`: Path to save performance statistics in CSV format.

### 2. Automated Testing
The project includes a comprehensive testing script `run_tests.sh` that uses Linux Network Namespaces to simulate realistic network conditions (latency and bandwidth).

**Note**: This script requires `root` privileges.

```bash
sudo ./run_tests.sh
```

Supported commands for `run_tests.sh`:
- `test`: Run all defined network configuration tests (Default).
- `setup`: Only set up the network namespaces.
- `cleanup`: Remove simulated network environments.
- `verify`: Verify network connectivity and limits.

## Project Structure

- `src/`: Core source code.
    - `client_main.cpp`: Client application entry point.
    - `server_main.cpp`: Server application entry point.
    - `client.cpp` / `server.cpp`: Protocol logic for client and server.
    - `network.cpp`: Network communication implementation.
    - `utils.cpp`: Database initialization and PRF utilities.
- `src/include/`: Header files for all components.
- `encryption/`: The Troy homomorphic encryption library.
- `Makefile`: Build configuration.
- `build/`: Target directory for executables.

## Performance Statistics
Upon completion, the client will output detailed performance metrics, including:
- **Offline Time**: Pre-processing and hint generation.
- **Online Time**: Query construction, server computation, and unmasking.
- **Communication Volume**: Total bytes sent/received for both main and OT connections.
- **Amortized Costs**: Predicted cost per query in long-running scenarios.
