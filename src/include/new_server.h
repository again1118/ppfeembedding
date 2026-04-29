<<<<<<< HEAD
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "utils.h"
#include "troy.h"

using namespace std;
using namespace CryptoPP;
using namespace troy;

// Forward declaration
class NewClient;

// New server class declaration
class NewServer {
public:
    // Constructor
    NewServer(uint64_t *DB_ptr, uint32_t LogN, uint32_t EntryB, troy::HeContextPointer &context, troy::KeyGenerator &keygen, uint64_t p);
    
    // Destructor
    ~NewServer();
    
    // Database preprocessing
    void preprocessDatabase(troy::BatchEncoder &encoder, troy::Encryptor &encryptor);
    
    // Get database entry
    void getEntry(uint32_t index, uint64_t *result);
    
    // Online query processing
    void onlineQuery(bool *bvec, uint32_t *Svec, uint64_t *b0, uint64_t *b1, Ciphertext &c, troy::BatchEncoder &encoder);
    
    // Execute server steps
    void executeServerSteps();
    
    // Get server statistics info
    void printServerStats();
    
    // Verify database integrity
    bool verifyDatabaseIntegrity();
    
    // Get server status
    string getServerStatus();
    
    // Get encrypted database reference
    const std::vector<troy::Ciphertext>& getEncryptedDB() const;
    
    // Get database entry count
    uint32_t getDatabaseSize() const;
    
    // Get partition information
    void getPartitionInfo(uint32_t& partNum, uint32_t& partSize) const;
    
    // Process batch queries
    void processBatchQueries(const std::vector<std::pair<bool*, uint32_t*>>& queries, 
                           std::vector<std::pair<uint64_t*, uint64_t*>>& responses);
    
    // Performance monitoring
    void startPerformanceMonitoring();
    void stopPerformanceMonitoring();
    void printPerformanceStats();

protected:
    // Decryptor
    troy::Decryptor decryptor;
    
    // Encrypted database
    std::vector<troy::Ciphertext> encryptedDB;
    
    // Plaintext modulus
    uint64_t plainModulus;
    
    // Database related
    uint64_t *DB;
    uint32_t N, B, EntrySize;
    uint32_t PartNum, PartSize, lambda, M;
    uint64_t *tmpEntry;
    
    // Performance monitoring
    std::chrono::high_resolution_clock::time_point startTime;
    std::chrono::high_resolution_clock::time_point endTime;
    uint32_t queryCount;
    uint32_t totalProcessingTime;
};
=======
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "utils.h"
#include "troy.h"

using namespace std;
using namespace CryptoPP;
using namespace troy;

// Forward declaration
class NewClient;

// New server class declaration
class NewServer {
public:
    // Constructor
    NewServer(uint64_t *DB_ptr, uint32_t LogN, uint32_t EntryB, troy::HeContextPointer &context, troy::KeyGenerator &keygen, uint64_t p);
    
    // Destructor
    ~NewServer();
    
    // Database preprocessing
    void preprocessDatabase(troy::BatchEncoder &encoder, troy::Encryptor &encryptor);
    
    // Get database entry
    void getEntry(uint32_t index, uint64_t *result);
    
    // Online query processing
    void onlineQuery(bool *bvec, uint32_t *Svec, uint64_t *b0, uint64_t *b1, Ciphertext &c, troy::BatchEncoder &encoder);
    
    // Execute server steps
    void executeServerSteps();
    
    // Get server statistics info
    void printServerStats();
    
    // Verify database integrity
    bool verifyDatabaseIntegrity();
    
    // Get server status
    string getServerStatus();
    
    // Get encrypted database reference
    const std::vector<troy::Ciphertext>& getEncryptedDB() const;
    
    // Get database entry count
    uint32_t getDatabaseSize() const;
    
    // Get partition information
    void getPartitionInfo(uint32_t& partNum, uint32_t& partSize) const;
    
    // Process batch queries
    void processBatchQueries(const std::vector<std::pair<bool*, uint32_t*>>& queries, 
                           std::vector<std::pair<uint64_t*, uint64_t*>>& responses);
    
    // Performance monitoring
    void startPerformanceMonitoring();
    void stopPerformanceMonitoring();
    void printPerformanceStats();

protected:
    // Decryptor
    troy::Decryptor decryptor;
    
    // Encrypted database
    std::vector<troy::Ciphertext> encryptedDB;
    
    // Plaintext modulus
    uint64_t plainModulus;
    
    // Database related
    uint64_t *DB;
    uint32_t N, B, EntrySize;
    uint32_t PartNum, PartSize, lambda, M;
    uint64_t *tmpEntry;
    
    // Performance monitoring
    std::chrono::high_resolution_clock::time_point startTime;
    std::chrono::high_resolution_clock::time_point endTime;
    uint32_t queryCount;
    uint32_t totalProcessingTime;
};
>>>>>>> f4a701c (Add files via upload)
