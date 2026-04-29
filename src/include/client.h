#pragma once
#include <cstdint>
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include"troy.h"
#include "server.h"
#include "utils.h"


typedef unsigned __int128 uint128_t;
// Base client class.
template <class PRF>
class Client{
	public:
		std::vector<troy::Ciphertext> ciParity;
		// LogN: Size of the database given in log10.
		// EntryB: Number of bits in a single entry. 
		Client(uint32_t LogN, uint32_t EmbeddingDim);
		uint64_t plainModulus;
		
		// Public members for distributed mode
		uint32_t *HintID;	// Array of hintIDs for each hint.
		uint64_t *Parity; // Array of parities for each hint.
		uint8_t *IndicatorBit; // Array storing the indicator bit for each hint.
		uint16_t *ExtraPart;	// Array storing the extra partition for each hint
		uint16_t *ExtraOffset; // Array storing the extra offset for each hint
		uint32_t *SelectCutoff; // Array storing the PRF cutoff value for each hint.
		bool *bvec;			// Select bits to send to server.
		uint32_t *Svec; 	// Database indices sent to server.
		uint64_t *Response_b0; // Parity of entries with select bit = 0 received from server.
		uint64_t *Response_b1; // Parity of entries with select bit = 1 received from server.
		PRF prf; // PRF Class

	protected:
		uint16_t NextDummyIdx(); // Get a dummy index
		/*
		Finds a valid hint that includes the queried index. 
		Params:
			query: queried index
			queryPartNum: partition number of our queried index
			queryOffset: in-partition offset of our queried index
			b_indicator: set to the indicator bit of the returned hint
		*/ 
		uint64_t find_hint(uint32_t query, uint16_t queryPartNum, uint16_t queryOffset, bool & b_indicator);

		uint16_t prfDummyIndices [8]; // Dummy index buffer
		uint64_t dummyIdxUsed; // Track the number of dummy indices used so far

		uint32_t N; // Number of database entries
		uint32_t B; // Size of one entry is B * 8 bytes
		uint32_t EmbeddingDim;
		uint32_t PartNum; // Number of partitions = sqrt(N)
		uint32_t PartSize; // Number of entries in one partition
		uint32_t lambda; // Correctness parameter
		uint32_t M; // Number of hints
		uint64_t LastHintID; // Last hint ID used
		uint64_t *tmpEntry; // simulating a fake server
};

// Client class for the one server variant.
class OneSVClient : public Client<PRFHintID>
{
public:
  //  LogN: Size of the database given in log10.
  // EntryB: Number of bits in a single entry. 
	OneSVClient(uint32_t LogN, uint32_t EmbeddingDim,uint64_t p); 

	// Runs the offline phase. Simulates streaming the entire DB one partition at a time.
	void Offline(OneSVServer &server,troy::BatchEncoder &encoder,troy::Encryptor &encryptor,troy::Evaluator &evaluator);

	// Runs the online phase with a single query. 
	void Online(OneSVServer &server, uint32_t query, uint64_t *result,troy::BatchEncoder &encoder, troy::Encryptor &encryptor, troy::Evaluator &evaluator);

	// ==================== Enc(0) pre-generation cache (offline generation, online reuse) ====================
	// Default pre-generation count: can be adjusted based on num_queries or actual load
	void precomputeEncZeros(size_t count, troy::BatchEncoder &encoder, troy::Encryptor &encryptor);
	const troy::Ciphertext& getNextEncZero();

	// Provide access rights for separated client/server mode
	uint16_t NextDummyIdx() { return Client<PRFHintID>::NextDummyIdx(); }
	uint64_t find_hint(uint32_t query, uint16_t queryPartNum, uint16_t queryOffset, bool &b_indicator) {
		return Client<PRFHintID>::find_hint(query, queryPartNum, queryOffset, b_indicator);
	}
	
	// Getters and setters for hint management
	uint32_t getNextHintIndex() const { return NextHintIndex; }
	void setNextHintIndex(uint32_t idx) { NextHintIndex = idx; }
	void incrementNextHintIndex() { NextHintIndex++; }
	uint32_t getM() const { return M; }
	std::vector<uint64_t> client_share;
private:
	uint32_t NextHintIndex;	// Next hint index to use from backup hint
	uint32_t BackupUsedAgain; // Track number of backup hints used

	uint64_t *DBPart;	// Streamed partition
	uint32_t *prfSelectVals; // Buffer for hint select values used to find cutoff.

	// Enc(0) ciphertext cache: offline pre-generated, directly used in online phase, avoiding each encrypt(0) call
	std::vector<troy::Ciphertext> encZeroCache;
	size_t encZeroNext = 0;
	
};



