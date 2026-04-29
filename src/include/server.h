#pragma once
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

// Server class for the one server variant
class OneSVServer
{
public:
  troy::Decryptor decryptor;
  std::vector<troy::Ciphertext> encryptedDB;
  uint64_t plainModulus;
  // LogN: Size of the database given in log10.
  // EntryB: Number of bits in a single entry.
  OneSVServer(uint64_t *DB_ptr, uint32_t LogN, uint32_t EntryB,troy::HeContextPointer &context,troy::KeyGenerator &keygen,uint64_t p);
  void getEntry(uint32_t index, uint64_t *result);
  /* Generate a single query using the online server. */
  void onlineQuery(bool *bvec, uint32_t *Svec, uint64_t *b0, uint64_t *b1, troy::Ciphertext &c,troy::BatchEncoder &encoder,troy::Encryptor &encryptor, troy::Ciphertext &ci_s_share_out);
  void preprocessDatabase(troy::BatchEncoder &encoder, troy::Encryptor &encryptor);

public:
  // Get currently used ciphertext modulus q (first item in coeff_modulus)
  uint64_t getModulusQ() const;
  std::vector<uint64_t> server_share;
protected:
  uint64_t *DB;       // Pointer to database array
  uint32_t N;         // Number of database entries
  uint32_t EmbeddingDim; //词向量维度
  uint32_t B;         // Size of one entry is B * 8 bytes
  uint32_t EntrySize; // Size of an entry in bytes
  
  uint32_t PartNum;   // Number of partitions = sqrt(N)
  uint32_t PartSize;  // Number of entries in one partition
  uint32_t lambda;    // Correctness parameter
  uint32_t M;         // Number of hints
  // uint64_t *tmpEntry; // Preallocated space for operations involving a database entry
                       // Store encrypted database (though encryptedDB vector is used)
  
};
