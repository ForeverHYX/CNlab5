# CN Lab 5
This project implements a simple client-server system using a custom binary protocol. It includes a multi-threaded C++ server, a C++ terminal client, and a Python-based GUI client.

## Directory Structure

- `server/`: Contains the C++ server source code and Makefile.
- `client/`: Contains the C++ terminal client, Python GUI client, and Makefile.
- `shared/`: Shared protocol definitions and utility functions used by both server and client.
- `tests/`: Python test scripts for functionality and performance verification.
- `.venv/`: Python virtual environment for running the GUI and tests.

## Build Instructions

### Prerequisites
- GCC/G++ compiler with C++17 support.
- Make build tool.
- Python 3 with `tkinter` (for the GUI client).

### Compiling
To build the executables, run `make` in both the `server` and `client` directories:

```bash
# Build the server
cd server
make

# Build the client
cd ../client
make
```

This will generate two executable files:
- `server/lab05_server`
- `client/lab05_client`

## Usage

### 1. Running the Server
Start the server first from the `server` directory. You can optionally specify a port number (default is 2930).

```bash
cd server
./lab05_server [port]
```

### 2. Running the Terminal Client
Run the client from the `client` directory. It will provide an interactive menu for connecting and sending requests.

```bash
cd client
./lab05_client
```
Follow the on-screen prompts to:
- Connect to the server (default `127.0.0.1` and port `2930`).
- Get server time or hostname.
- List active clients.
- Send messages to other connected clients.

### 3. Running the GUI Client
The GUI client is written in Python. It is recommended to use the provided virtual environment.

```bash
# Activate the virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows (cmd):
# .venv\Scripts\activate

# Run the GUI client
python client/client_gui.py
```
The GUI allows you to connect to the server via a graphical interface and perform all the actions available in the terminal client.

## Features
- **Binary Protocol**: Custom header-based communication.
- **Multi-threading**: Server handles multiple clients concurrently.
- **Message Forwarding**: Allows clients to send messages to each other through the server.
- **Real-time Updates**: GUI client displays incoming messages and server responses dynamically.

## Testing
Comprehensive tests are provided in the `tests/` directory.

```bash
# Run smoke tests
python tests/smoke_test.py

# Run full feature tests
python tests/full_feature_test.py

# Run concurrency tests
python tests/concurrency_test.py
```
