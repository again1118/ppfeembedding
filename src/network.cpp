#include "network.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <netinet/tcp.h>
#include <vector>

using namespace std;
using namespace troy;

// NetworkHelper implementation

// Static variable definitions
size_t NetworkHelper::totalBytesSent = 0;
size_t NetworkHelper::totalBytesRecv = 0;
size_t NetworkHelper::phaseBytesSent = 0;
size_t NetworkHelper::phaseBytesRecv = 0;

bool NetworkHelper::sendData(int socket, const void* data, size_t size) {
    size_t totalSent = 0;
    const char* ptr = static_cast<const char*>(data);
    
    while (totalSent < size) {
        ssize_t sent = send(socket, ptr + totalSent, size - totalSent, 0);
        if (sent <= 0) {
            cerr << "Failed to send data" << endl;
            return false;
        }
        totalSent += sent;
    }
    totalBytesSent += size;  // Update stats
    phaseBytesSent += size;  // Update phase stats
    return true;
}

bool NetworkHelper::recvData(int socket, void* data, size_t size) {
    size_t totalRecv = 0;
    char* ptr = static_cast<char*>(data);
    
    while (totalRecv < size) {
        ssize_t received = recv(socket, ptr + totalRecv, size - totalRecv, 0);
        if (received <= 0) {
            cerr << "Failed to receive data" << endl;
            return false;
        }
        totalRecv += received;
    }
    totalBytesRecv += size;  // Update stats
    phaseBytesRecv += size;  // Update phase stats
    return true;
}

bool NetworkHelper::sendBoolArray(int socket, const unsigned char* data, size_t count) {
    // Send array size first
    if (!sendData(socket, &count, sizeof(count))) return false;
    
    // Convert bool array to uint8_t to save bandwidth
    size_t byteCount = (count + 7) / 8;
    vector<uint8_t> bytes(byteCount, 0);
    
    for (size_t i = 0; i < count; i++) {
        if (data[i]) {
            bytes[i / 8] |= (1 << (i % 8));
        }
    }
    
    return sendData(socket, bytes.data(), byteCount);
}

bool NetworkHelper::recvBoolArray(int socket, unsigned char* data, size_t count) {
    // Receive array size and verify
    size_t receivedCount;
    if (!recvData(socket, &receivedCount, sizeof(receivedCount))) return false;
    
    if (receivedCount != count) {
        cerr << "Bool array size mismatch: expected " << count << ", received " << receivedCount << endl;
        return false;
    }
    
    size_t byteCount = (count + 7) / 8;
    vector<uint8_t> bytes(byteCount);
    
    if (!recvData(socket, bytes.data(), byteCount)) return false;
    
    for (size_t i = 0; i < count; i++) {
        data[i] = (bytes[i / 8] >> (i % 8)) & 1;
    }
    
    return true;
}

bool NetworkHelper::sendUint32Array(int socket, const uint32_t* data, size_t count) {
    if (!sendData(socket, &count, sizeof(count))) return false;
    return sendData(socket, data, count * sizeof(uint32_t));
}

bool NetworkHelper::recvUint32Array(int socket, uint32_t* data, size_t count) {
    size_t receivedCount;
    if (!recvData(socket, &receivedCount, sizeof(receivedCount))) return false;
    
    if (receivedCount != count) {
        cerr << "Uint32 array size mismatch" << endl;
        return false;
    }
    
    return recvData(socket, data, count * sizeof(uint32_t));
}

bool NetworkHelper::sendUint64Array(int socket, const uint64_t* data, size_t count) {
    if (!sendData(socket, &count, sizeof(count))) return false;
    return sendData(socket, data, count * sizeof(uint64_t));
}

bool NetworkHelper::recvUint64Array(int socket, uint64_t* data, size_t count) {
    size_t receivedCount;
    if (!recvData(socket, &receivedCount, sizeof(receivedCount))) return false;
    
    if (receivedCount != count) {
        cerr << "Uint64 array size mismatch" << endl;
        return false;
    }
    
    return recvData(socket, data, count * sizeof(uint64_t));
}

bool NetworkHelper::sendCiphertext(int socket, const troy::Ciphertext& ct, const troy::HeContextPointer& context) {
    // Use stringstream to serialize ciphertext
    stringstream ss;
    ct.save(ss, context, troy::utils::compression::CompressionMode::Nil);
    
    // Get serialized data
    string data = ss.str();
    size_t size = data.size();
    
    // Send size
    if (!sendData(socket, &size, sizeof(size))) return false;
    
    // Send data
    return sendData(socket, reinterpret_cast<const unsigned char*>(data.data()), size);
}

bool NetworkHelper::recvCiphertext(int socket, troy::Ciphertext& ct, const troy::HeContextPointer& context) {
    // Receive size
    size_t size;
    if (!recvData(socket, &size, sizeof(size))) return false;
    
    // Receive data
    vector<unsigned char> buffer(size);
    if (!recvData(socket, buffer.data(), size)) return false;
    
    // Use stringstream to deserialize
    stringstream ss;
    ss.write(reinterpret_cast<const char*>(buffer.data()), size);
    ct.load(ss, context);
    
    return true;
}

bool NetworkHelper::sendCiphertextVector(int socket, const std::vector<troy::Ciphertext>& cts, const troy::HeContextPointer& context) {
    // Send vector size
    size_t count = cts.size();
    if (!sendData(socket, &count, sizeof(count))) return false;
    
    // Send Ciphertexts one by one
    for (const auto& ct : cts) {
        if (!sendCiphertext(socket, ct, context)) return false;
    }
    
    return true;
}

bool NetworkHelper::recvCiphertextVector(int socket, std::vector<troy::Ciphertext>& cts, 
                                         size_t count, const troy::HeContextPointer& context) {
    // Receive vector size and verify
    size_t receivedCount;
    if (!recvData(socket, &receivedCount, sizeof(receivedCount))) return false;
    
    if (receivedCount != count) {
        cerr << "Ciphertext vector size mismatch: expected " << count << ", received " << receivedCount << endl;
        return false;
    }
    
    cts.resize(count);
    
    // Receive Ciphertexts one by one
    for (size_t i = 0; i < count; i++) {
        if (!recvCiphertext(socket, cts[i], context)) return false;
    }
    
    return true;
}

bool NetworkHelper::sendSizedBuffer(int socket, const void* data, size_t size) {
    return sendData(socket, data, size);
}

bool NetworkHelper::recvSizedBuffer(int socket, void* data, size_t size) {
    return recvData(socket, data, size);
}

void NetworkHelper::appendBytes(std::vector<uint8_t>& out, const void* data, size_t size) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    out.insert(out.end(), p, p + size);
}

bool NetworkHelper::readBytes(const std::vector<uint8_t>& in, size_t& offset, void* out, size_t size) {
    if (offset + size > in.size()) {
        return false;
    }
    std::memcpy(out, in.data() + offset, size);
    offset += size;
    return true;
}

// Batch send queries (packed sending: reduces send calls, field semantics remain unchanged; incompatible with old versions)
bool NetworkHelper::sendBatchQueries(int socket, const std::vector<BatchQuery>& queries,
                                     uint32_t PartNum, uint32_t /*B*/,
                                     const troy::HeContextPointer& context) {
    const uint32_t batchSize = static_cast<uint32_t>(queries.size());

    // Estimate approximate capacity to reduce reallocations (no precision required)
    std::vector<uint8_t> payload;
    payload.reserve(sizeof(batchSize) + batchSize * (PartNum + PartNum * sizeof(uint32_t) + 256));

    // batchSize
    appendBytes(payload, &batchSize, sizeof(batchSize));

    // Each query: bvec(bit-pack) + Svec(raw u32 array) + ciphertext(size+raw)
    const size_t bvecByteCount = (static_cast<size_t>(PartNum) + 7) / 8;
    std::vector<uint8_t> bvecPacked(bvecByteCount);

    for (const auto& q : queries) {
        // bvec -> packed bits
        std::fill(bvecPacked.begin(), bvecPacked.end(), 0);
        for (uint32_t i = 0; i < PartNum; ++i) {
            if (q.bvec[i]) {
                bvecPacked[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
            }
        }
        appendBytes(payload, bvecPacked.data(), bvecPacked.size());

        // Svec
        appendBytes(payload, q.Svec.data(), static_cast<size_t>(PartNum) * sizeof(uint32_t));

        // ciphertext: serialize -> size + bytes
        std::stringstream ss;
        q.ciphertext.save(ss, context, troy::utils::compression::CompressionMode::Nil);
        std::string ctData = ss.str();
        const size_t ctSize = ctData.size();
        appendBytes(payload, &ctSize, sizeof(ctSize));
        appendBytes(payload, ctData.data(), ctSize);
    }

    // Wrap with an outer length field to facilitate the receiver parsing the entire buffer in one recv call
    const size_t payloadSize = payload.size();
    if (!sendSizedBuffer(socket, &payloadSize, sizeof(payloadSize))) return false;
    return sendSizedBuffer(socket, payload.data(), payload.size());
}

// Batch receive queries (packed receiving: reduces recv calls, field semantics remain unchanged; incompatible with old versions)
bool NetworkHelper::recvBatchQueries(int socket, std::vector<BatchQuery>& queries,
                                     uint32_t& batchSize, uint32_t PartNum,
                                     const troy::HeContextPointer& context) {
    size_t payloadSize = 0;
    if (!recvSizedBuffer(socket, &payloadSize, sizeof(payloadSize))) return false;

    std::vector<uint8_t> payload(payloadSize);
    if (!recvSizedBuffer(socket, payload.data(), payload.size())) return false;

    size_t off = 0;
    if (!readBytes(payload, off, &batchSize, sizeof(batchSize))) return false;

    queries.clear();
    queries.resize(batchSize);

    const size_t bvecByteCount = (static_cast<size_t>(PartNum) + 7) / 8;
    std::vector<uint8_t> bvecPacked(bvecByteCount);

    for (uint32_t qi = 0; qi < batchSize; ++qi) {
        queries[qi].bvec.assign(PartNum, false);
        queries[qi].Svec.resize(PartNum);

        // bvec packed
        if (!readBytes(payload, off, bvecPacked.data(), bvecPacked.size())) return false;
        for (uint32_t i = 0; i < PartNum; ++i) {
            queries[qi].bvec[i] = ((bvecPacked[i / 8] >> (i % 8)) & 1) != 0;
        }

        // Svec
        if (!readBytes(payload, off, queries[qi].Svec.data(), static_cast<size_t>(PartNum) * sizeof(uint32_t))) return false;

        // ciphertext
        size_t ctSize = 0;
        if (!readBytes(payload, off, &ctSize, sizeof(ctSize))) return false;
        if (off + ctSize > payload.size()) return false;

        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(payload.data() + off), ctSize);
        off += ctSize;
        queries[qi].ciphertext.load(ss, context);
    }

    return off == payload.size();
}

// Batch send responses
bool NetworkHelper::sendBatchResponses(int socket, const std::vector<BatchResponse>& responses, uint32_t B) {
    // Send batch response data
    // Variables sent include:
    // For each response, send following data:
    // - Response_b0: uint64_t array - First part of query result (result when b=0)
    // - Response_b1: uint64_t array - Second part of query result (result when b=1)
    // These responses are results calculated by server based on query parameters and encrypted database
    
    // Send each response
    for (const auto& response : responses) {
        // Send Response_b0 - First part of query result
        if (!sendUint64Array(socket, response.Response_b0.data(), B)) return false;
        
        // Send Response_b1 - Second part of query result
        if (!sendUint64Array(socket, response.Response_b1.data(), B)) return false;
    }
    
    return true;
}

// Batch receive responses
bool NetworkHelper::recvBatchResponses(int socket, std::vector<BatchResponse>& responses,
                                       uint32_t batchSize, uint32_t B) {
    // Receive batch response data
    // Variables received include:
    // For each response, receive following data:
    // - Response_b0: uint64_t array - First part of query result (result when b=0)
    // - Response_b1: uint64_t array - Second part of query result (result when b=1)
    // These responses are results calculated by server based on query parameters and encrypted database
    
    responses.resize(batchSize);
    
    // Receive each response
    for (uint32_t i = 0; i < batchSize; i++) {
        responses[i].Response_b0.resize(B);
        responses[i].Response_b1.resize(B);
        
        // Receive Response_b0 - First part of query result
        if (!recvUint64Array(socket, responses[i].Response_b0.data(), B)) return false;
        
        // Receive Response_b1 - Second part of query result
        if (!recvUint64Array(socket, responses[i].Response_b1.data(), B)) return false;
    }
    
    return true;
}

// ServerNetwork implementation

ServerNetwork::ServerNetwork(int port) 
    : serverSocket(-1), port(port), running(false) {
}

ServerNetwork::~ServerNetwork() {
    stop();
}

bool ServerNetwork::start() {
    serverSocket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        cerr << "Failed to create server socket" << endl;
        return false;
    }
    
    // Set socket options to allow address reuse
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Failed to set socket options" << endl;
        return false;
    }
    
    // Enable TCP_NODELAY, disable Nagle algorithm to reduce latency
    int flag = 1;
    if (setsockopt(serverSocket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        cerr << "Failed to set TCP_NODELAY" << endl;
    }
    
    // Increase socket send/recv buffers (set to 2MB)
    int bufferSize = 2 * 1024 * 1024;
    setsockopt(serverSocket, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(serverSocket, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Failed to bind port" << endl;
        close(serverSocket);
        return false;
    }
    
    if (listen(serverSocket, 5) < 0) {
        cerr << "Failed to listen" << endl;
        close(serverSocket);
        return false;
    }
    
    running = true;
    cout << "Server started successfully, listening on port: " << port << endl;
    return true;
}

int ServerNetwork::acceptClient() {
    if (!running) return -1;
    
    sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    
    int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    if (clientSocket < 0) {
        cerr << "Failed to accept client connection" << endl;
        return -1;
    }
    
    // Set TCP_NODELAY for client connection
    int flag = 1;
    setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    // Increase buffer for client connection
    int bufferSize = 2 * 1024 * 1024;
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    
    cout << "Client connected: " << inet_ntoa(clientAddr.sin_addr) << endl;
    return clientSocket;
}

void ServerNetwork::closeClient(int clientSocket) {
    if (clientSocket >= 0) {
        close(clientSocket);
    }
}

void ServerNetwork::stop() {
    if (running) {
        running = false;
        if (serverSocket >= 0) {
            close(serverSocket);
            serverSocket = -1;
        }
        cout << "Server stopped" << endl;
    }
}

// ClientNetwork implementation

ClientNetwork::ClientNetwork(const std::string& serverIP, int port)
    : clientSocket(-1), serverIP(serverIP), port(port), connected(false) {
}

ClientNetwork::~ClientNetwork() {
    disconnect();
}

bool ClientNetwork::connect() {
    clientSocket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        cerr << "Failed to create client socket" << endl;
        return false;
    }
    
    // Enable TCP_NODELAY to reduce latency
    int flag = 1;
    if (setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        cerr << "Failed to set TCP_NODELAY" << endl;
    }
    
    // Increase socket buffer (set to 2MB)
    int bufferSize = 2 * 1024 * 1024;
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
        cerr << "Invalid server IP address" << endl;
        close(clientSocket);
        return false;
    }
    
    if (::connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Failed to connect to server" << endl;
        close(clientSocket);
        return false;
    }
    
    connected = true;
    cout << "Connected to server: " << serverIP << ":" << port << endl;
    return true;
}

void ClientNetwork::disconnect() {
    if (connected) {
        connected = false;
        if (clientSocket >= 0) {
            close(clientSocket);
            clientSocket = -1;
        }
        cout << "Disconnected from server" << endl;
    }
}

// Send public key
bool NetworkHelper::sendPublicKey(int socket, const troy::PublicKey& publicKey, const troy::HeContextPointer& context) {
    try {
        // Serialize public key
        stringstream ss;
        publicKey.save(ss, context, troy::utils::compression::CompressionMode::Nil);
        string serialized = ss.str();
        
        // Send serialized data length
        size_t dataSize = serialized.size();
        if (!sendData(socket, &dataSize, sizeof(dataSize))) {
            return false;
        }
        
        // Send serialized data
        if (!sendData(socket, serialized.data(), dataSize)) {
            return false;
        }
        
        return true;
    } catch (const exception& e) {
        cerr << "Failed to send public key: " << e.what() << endl;
        return false;
    }
}

// Receive public key
bool NetworkHelper::recvPublicKey(int socket, troy::PublicKey& publicKey, const troy::HeContextPointer& context) {
    try {
        // Receive serialized data length
        size_t dataSize;
        if (!recvData(socket, &dataSize, sizeof(dataSize))) {
            return false;
        }
        
        // Receive serialized data
        vector<char> buffer(dataSize);
        if (!recvData(socket, buffer.data(), dataSize)) {
            return false;
        }
        
        // Deserialize public key
        stringstream ss(string(buffer.begin(), buffer.end()));
        publicKey.load(ss, context);
        
        return true;
    } catch (const exception& e) {
        cerr << "Failed to receive public key: " << e.what() << endl;
        return false;
    }
}

