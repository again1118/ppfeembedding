#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "troy.h"

// Network communication helper class
class NetworkHelper {
public:
    // Communication volume statistics
    static size_t totalBytesSent;
    static size_t totalBytesRecv;
    static size_t phaseBytesSent;  // Phase-based statistics
    static size_t phaseBytesRecv;  // Phase-based statistics
    
    static void resetStats() { totalBytesSent = 0; totalBytesRecv = 0; phaseBytesSent = 0; phaseBytesRecv = 0; }
    static size_t getTotalBytesSent() { return totalBytesSent; }
    static size_t getTotalBytesRecv() { return totalBytesRecv; }
    
    // Phase-based statistics (resettable)
    static void resetPhaseCounters() { phaseBytesSent = 0; phaseBytesRecv = 0; }
    static size_t getPhaseBytesSent() { return phaseBytesSent; }
    static size_t getPhaseBytesRecv() { return phaseBytesRecv; }
    
    // Send raw byte data
    static bool sendData(int socket, const void* data, size_t size);
    
    // Receive raw byte data
    static bool recvData(int socket, void* data, size_t size);
    
    // Send boolean array (using unsigned char to avoid std::vector<bool> specialization issues)
    static bool sendBoolArray(int socket, const unsigned char* data, size_t count);
    
    // Receive boolean array (using unsigned char to avoid std::vector<bool> specialization issues)
    static bool recvBoolArray(int socket, unsigned char* data, size_t count);
    
    // Send uint32 array
    static bool sendUint32Array(int socket, const uint32_t* data, size_t count);
    
    // Receive uint32 array
    static bool recvUint32Array(int socket, uint32_t* data, size_t count);
    
    // Send uint64 array
    static bool sendUint64Array(int socket, const uint64_t* data, size_t count);
    
    // Receive uint64 array
    static bool recvUint64Array(int socket, uint64_t* data, size_t count);
    
    // Send Ciphertext
    static bool sendCiphertext(int socket, const troy::Ciphertext& ct, const troy::HeContextPointer& context);
    
    // Receive Ciphertext
    static bool recvCiphertext(int socket, troy::Ciphertext& ct, const troy::HeContextPointer& context);
    
    // Send Ciphertext vector
    static bool sendCiphertextVector(int socket, const std::vector<troy::Ciphertext>& cts, const troy::HeContextPointer& context);
    
    // Receive Ciphertext vector
    static bool recvCiphertextVector(int socket, std::vector<troy::Ciphertext>& cts, 
                                     size_t count, const troy::HeContextPointer& context);
    
    // Send public key
    static bool sendPublicKey(int socket, const troy::PublicKey& publicKey, const troy::HeContextPointer& context);
    
    // Receive public key
    static bool recvPublicKey(int socket, troy::PublicKey& publicKey, const troy::HeContextPointer& context);
    
    // Batch query structure
    struct BatchQuery {
        std::vector<bool> bvec;
        std::vector<uint32_t> Svec;
        troy::Ciphertext ciphertext;
    };
    
    struct BatchResponse {
        std::vector<uint64_t> Response_b0;
        std::vector<uint64_t> Response_b1;
    };
    
    // Batch send queries (packaged: reduce number of send() calls, field semantics unchanged)
    static bool sendBatchQueries(int socket, const std::vector<BatchQuery>& queries,
                                 uint32_t PartNum, uint32_t B,
                                 const troy::HeContextPointer& context);
    
    // Batch receive queries (packaged: reduce number of recv() calls, field semantics unchanged)
    static bool recvBatchQueries(int socket, std::vector<BatchQuery>& queries,
                                 uint32_t& batchSize, uint32_t PartNum,
                                 const troy::HeContextPointer& context);

    // Batch send responses
    static bool sendBatchResponses(int socket, const std::vector<BatchResponse>& responses, uint32_t B);

    // Batch receive responses
    static bool recvBatchResponses(int socket, std::vector<BatchResponse>& responses,
                                   uint32_t batchSize, uint32_t B);

private:
    // Send/receive "known length" buffer (attempt to complete in one call, still ensuring reliable transfer)
    static bool sendSizedBuffer(int socket, const void* data, size_t size);
    static bool recvSizedBuffer(int socket, void* data, size_t size);

    static void appendBytes(std::vector<uint8_t>& out, const void* data, size_t size);
    static bool readBytes(const std::vector<uint8_t>& in, size_t& offset, void* out, size_t size);
};

// Server-side network management
class ServerNetwork {
public:
    ServerNetwork(int port);
    ~ServerNetwork();
    
    bool start();
    int acceptClient();
    void closeClient(int clientSocket);
    void stop();
    
private:
    int serverSocket;
    int port;
    bool running;
};

// Client-side network management
class ClientNetwork {
public:
    ClientNetwork(const std::string& serverIP, int port);
    ~ClientNetwork();
    
    bool connect();
    int getSocket() const { return clientSocket; }
    void disconnect();
    
private:
    int clientSocket;
    std::string serverIP;
    int port;
    bool connected;
};

