<<<<<<< HEAD
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "troy.h"
#include "utils.h"

using namespace std;
using namespace CryptoPP;
using namespace troy;

// Forward declaration
class NewServer;

// New client class declaration
class NewClient {
public:
    // Constructor
    NewClient(uint32_t LogN, uint32_t EntryB, uint64_t p);
    
    // Destructor
    ~NewClient();
    
    // Offline phase
    void Offline(NewServer &server, BatchEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator);
    
    // Online query phase
    void Online(NewServer &server, uint32_t query, uint64_t *result, BatchEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator);
    
    // Get client status
    string getClientStatus() const;
    
    // Get query statistics
    void printQueryStats() const;
    
    // Verify query result
    bool verifyQueryResult(uint32_t query, const uint64_t *result, const uint64_t *expected) const;

private:
    // Get dummy index
    uint16_t NextDummyIdx();
    
    // Find matching hint
    uint64_t find_hint(uint32_t query, uint16_t queryPartNum, uint16_t queryOffset, bool &b_indicator);
    
    // Get secure random number
    uint64_t getSecureRandom64();
    
    // Member variables
    uint64_t plainModulus;
    PRFHintID prf;
    
    uint32_t N, B, PartNum, PartSize, lambda, M;
    uint64_t dummyIdxUsed;
    uint32_t NextHintIndex, BackupUsedAgain;
    
    // Query-related arrays
    bool *bvec;
    uint32_t *Svec;
    uint64_t *Response_b0, *Response_b1, *tmpEntry;
    
    // Hint-related arrays
    uint32_t *HintID, *SelectCutoff;
    uint16_t *ExtraPart, *ExtraOffset;
    uint64_t *Parity;
    uint8_t *IndicatorBit;
    
    // Other auxiliary arrays
    uint32_t *prfSelectVals;
    uint64_t *DBPart;
    uint16_t prfDummyIndices[8];
    
    // Encrypted parity array
    std::vector<troy::Ciphertext> ciParity;
    
    // Query statistics
    mutable uint32_t queryCount;
    mutable uint32_t successfulQueries;
};
=======
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "troy.h"
#include "utils.h"

using namespace std;
using namespace CryptoPP;
using namespace troy;

// Forward declaration
class NewServer;

// New client class declaration
class NewClient {
public:
    // Constructor
    NewClient(uint32_t LogN, uint32_t EntryB, uint64_t p);
    
    // Destructor
    ~NewClient();
    
    // Offline phase
    void Offline(NewServer &server, BatchEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator);
    
    // Online query phase
    void Online(NewServer &server, uint32_t query, uint64_t *result, BatchEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator);
    
    // Get client status
    string getClientStatus() const;
    
    // Get query statistics
    void printQueryStats() const;
    
    // Verify query result
    bool verifyQueryResult(uint32_t query, const uint64_t *result, const uint64_t *expected) const;

private:
    // Get dummy index
    uint16_t NextDummyIdx();
    
    // Find matching hint
    uint64_t find_hint(uint32_t query, uint16_t queryPartNum, uint16_t queryOffset, bool &b_indicator);
    
    // Get secure random number
    uint64_t getSecureRandom64();
    
    // Member variables
    uint64_t plainModulus;
    PRFHintID prf;
    
    uint32_t N, B, PartNum, PartSize, lambda, M;
    uint64_t dummyIdxUsed;
    uint32_t NextHintIndex, BackupUsedAgain;
    
    // Query-related arrays
    bool *bvec;
    uint32_t *Svec;
    uint64_t *Response_b0, *Response_b1, *tmpEntry;
    
    // Hint-related arrays
    uint32_t *HintID, *SelectCutoff;
    uint16_t *ExtraPart, *ExtraOffset;
    uint64_t *Parity;
    uint8_t *IndicatorBit;
    
    // Other auxiliary arrays
    uint32_t *prfSelectVals;
    uint64_t *DBPart;
    uint16_t prfDummyIndices[8];
    
    // Encrypted parity array
    std::vector<troy::Ciphertext> ciParity;
    
    // Query statistics
    mutable uint32_t queryCount;
    mutable uint32_t successfulQueries;
};
>>>>>>> f4a701c (Add files via upload)
