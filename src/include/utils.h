#pragma once
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include <cassert>

#define AES_KEY "1234567812345678"
#define LAMBDA 30

using namespace std;
using namespace CryptoPP;

// PRF across partition ID. 
// A single PRF call generates the values of v for 4 consecutive partition numbers for a single hintID and the values of r for 8 consecutive partition numbers for a single hintID, packed in 128 bits.
class PRFPartitionID{
  public:
  PRFPartitionID(string keyStr){
    assert(keyStr.size() == 16);
    SecByteBlock aesKey(reinterpret_cast<const CryptoPP::byte*>(keyStr.data()), AES::DEFAULT_KEYLENGTH);
    enc_.SetKey(aesKey, aesKey.size());
  }
  void evaluate(uint8_t *out, uint32_t word1, uint32_t word2, uint32_t word3){
    uint32_t prfIn [4] = {word1, (word3 << 16) | word2};
      enc_.ProcessData(out, (uint8_t*) prfIn, 16);
  }

  // Returns an indicator bit given a partition number, hint ID, and cutoff value for the hintID.
  bool PRF4Select(uint32_t hintID, uint32_t partID, uint32_t cutoff) {
    uint32_t ctxt [4];
    evaluate((uint8_t*) ctxt, hintID, partID / 4, 1);		
    return ctxt[partID % 4] < cutoff;	 
  }

  // Returns a partition offset given a partition number and hint ID 
  uint16_t PRF4Idx(uint32_t hintID, uint32_t partID) {
    uint16_t ctxt [8];
    evaluate((uint8_t*) ctxt, hintID, partID / 8, 2);	
    return ctxt[partID % 8];	
  }

  // Generate the partition offsets for the batch of 8 consecutive partitions that includes the given partID
  void PRFBatchIdx(uint16_t* prfIndices, uint32_t hintID, uint32_t partID) {
    evaluate((uint8_t*)prfIndices, hintID, partID / 8, 2);
  }

  // Generate the select values for the batch of 4 consecutive partitions that includes the given partID
  void PRFBatchSelect(uint32_t* prfSelectVals, uint32_t hintID, uint32_t partID) {
    evaluate((uint8_t *)prfSelectVals, hintID, partID / 4, 1);
  }

  private:
  // AES-128
	ECB_Mode< AES >::Encryption enc_;
};


// PRF across hint ID
// A single PRF call generates the values of v for 4 consecutive hintIDs for a single partition number and the values of r for 8 consecutive hintIDs for a single partition number, packed in 128 bits.
class PRFHintID{
  public:
  PRFHintID(string keyStr){
    assert(keyStr.size() == 16);
    SecByteBlock aesKey(reinterpret_cast<const CryptoPP::byte*>(keyStr.data()), AES::DEFAULT_KEYLENGTH);
    enc_.SetKey(aesKey, aesKey.size());
  }
  void evaluate(uint8_t *out, uint32_t word1, uint32_t word2, uint32_t word3){
    uint32_t prfIn [4] = {word1, (word3 << 16) | word2};
      enc_.ProcessData(out, (uint8_t*) prfIn, 16);
  }

  // Returns an indicator bit given a partition number, hint ID, and cutoff value for the hintID.
  bool PRF4Select(uint32_t hintID, uint32_t partID, uint32_t cutoff)
  {
    uint32_t ctxt[4];
    evaluate((uint8_t*) ctxt, hintID / 4, partID, 1);		
    return (ctxt[hintID % 4] < cutoff); 
  }

  // Returns a partition offset given a partition number and hint ID 
  uint16_t PRF4Idx(uint32_t hintID, uint32_t partID)
  {
    uint16_t ctxt [8];
    evaluate((uint8_t*) ctxt, hintID / 8, partID, 2);	
    return ctxt[hintID % 8];	
  }


  private:
  // AES-128
	ECB_Mode< AES >::Encryption enc_;
};


// Reads an entry from a DB into result.
void getEntryFromDB(uint64_t* DB, uint32_t index, uint64_t *result, uint32_t embeddingdim);

// Initializes a database with random values.
void initDatabase(uint64_t** DB, uint64_t kLogDBSize, uint64_t embeddingdim, uint64_t plainModulus);

/* Given an array of PartNum prf values, finds the median value. May return 0 if algorithm does not find a median */
uint32_t FindCutoff(uint32_t *prfVals, uint32_t PartNum);

uint64_t getSecureRandom64();