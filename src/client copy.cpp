#include "client.h"
#include "server.h"
#include <random>
#include <algorithm>
#include <cassert>
#include <omp.h>
using namespace std;
using namespace CryptoPP;
using namespace troy;
// N is supported up to 2^32. Allows us to use uint16_t to store a single offset within partition
template <class PRF>
Client<PRF>::Client(uint32_t LogN, uint32_t EntryB) : prf(AES_KEY)
{
	assert(LogN < 32);
	assert(EntryB >= 8);
	N = 1 << LogN; // Database size
	// B is the size of one entry in uint64s
	B = EntryB / 8; // Size of each entry

	PartNum = 1 << (LogN / 2);			   // Number of partitions
	PartSize = 1 << (LogN / 2 + LogN % 2); // Size of each partition
	lambda = LAMBDA;
	M = lambda * PartSize;

	// Allocate memory for making requests to servers and receiving responses from servers
	bvec = new bool[PartNum];	   // Decides if this partition is a real or dummy query
	Svec = new uint32_t[PartNum];  // Specific query offset for each partition
	Response_b0 = new uint64_t[B]; // Two responses
	Response_b1 = new uint64_t[B];
	tmpEntry = new uint64_t[B]; // Decryption result
	// Allocate storage for hints
	HintID = new uint32_t[M];	   // Unique hint ID
	ExtraPart = new uint16_t[M];   // Extra partition
	ExtraOffset = new uint16_t[M]; // Extra offset

	// Pack the bits together
	IndicatorBit = new uint8_t[(M + 7) / 8]; // Records whether hint is used
	LastHintID = 0;							 // Records last used hintID

	dummyIdxUsed = 0; /* dummyIdxUsed
Indicates how many dummy indices have been used so far.
Each time a new dummy query needs to be generated, an index is taken from prfDummyIndices.
prfDummyIndices
This is an array storing dummy indices (size 8).
These indices are pseudo-random numbers generated via PRF to ensure randomness. */
}

template <class PRF>
uint16_t Client<PRF>::NextDummyIdx()
{
	if (dummyIdxUsed % 8 == 0) // need more dummy indices
		prf.evaluate((uint8_t *)prfDummyIndices, 0, dummyIdxUsed / 8, 0);
	return prfDummyIndices[dummyIdxUsed++ % 8];
}

template <class PRF>
uint64_t Client<PRF>::find_hint(uint32_t query, uint16_t queryPartNum, uint16_t queryOffset, bool &b_indicator)
{
	for (uint64_t hintIndex = 0; hintIndex < M; hintIndex++)
	{
		if (SelectCutoff[hintIndex] == 0)
		{ // Invalid hint
			continue;
		}
		b_indicator = (IndicatorBit[hintIndex / 8] >> (hintIndex % 8)) & 1;
		if (ExtraPart[hintIndex] == queryPartNum && ExtraOffset[hintIndex] == queryOffset)
		{ // Query is the extra entry that the hint stores
			return hintIndex;
		}
		uint32_t r = prf.PRF4Idx(HintID[hintIndex], queryPartNum);
		if ((r ^ query) & (PartSize - 1))
		{ // Check if r == query mod PartSize
			continue;
		}
		bool b = prf.PRF4Select(HintID[hintIndex], queryPartNum, SelectCutoff[hintIndex]);
		if (b == b_indicator)
		{
			return hintIndex;
		}
	}
	return M + 1;
}

OneSVClient::OneSVClient(uint32_t LogN, uint32_t EntryB,uint64_t p) : Client(LogN, EntryB)
{
	// Allocate storage for hints. One server version stores M more hint parities and cutoffs as backup hints.
	SelectCutoff = new uint32_t[M * 2]; // Used to determine the median value
	Parity = new uint64_t[M * 2 * B];	// XOR value
	plainModulus=p;
	prfSelectVals = new uint32_t[PartNum * 4]; // Temporary variable to store intermediate values
	DBPart = new uint64_t[PartSize];  // B is always 1, only load a part

	encZeroCache.clear();
	encZeroNext = 0;
}

void OneSVClient::precomputeEncZeros(size_t count, BatchEncoder &encoder, Encryptor &encryptor)
{
	// Pre-generate Enc(0) cache: used for "encrypt 0 and add" randomization/refresh during online phase.
	// Note: This generates public key encryption of all-zero plaintext; creation overhead is large, so amortized in offline stage.
	encZeroCache.clear();
	encZeroCache.resize(count);
	encZeroNext = 0;

	// Construct all-zero plaintext (length PartSize, only poly[PartSize-1] will be used in online logic)
	std::vector<uint64_t> zero_vec(PartSize, 0);
	troy::Plaintext zero_plain = encoder.encode_polynomial_new(zero_vec);

	for (size_t i = 0; i < count; ++i)
	{
		encZeroCache[i] = encryptor.encrypt_asymmetric_new(zero_plain);
	}
}

const troy::Ciphertext& OneSVClient::getNextEncZero()
{
	if (encZeroCache.empty())
	{
		throw std::runtime_error("Enc(0) cache is empty: Please call precomputeEncZeros() in Offline phase first");
	}
	// Loop reuse: avoid crash due to number of queries exceeding pre-generated count
	const size_t idx = encZeroNext++ % encZeroCache.size();
	return encZeroCache[idx];
}

void OneSVClient::Offline(OneSVServer &server, BatchEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator)
{
	// Setup encryption parameters.
	ciParity.resize(M * 2);
	std::vector<troy::Ciphertext *> ciParityPtrs(M * 2);
	for (size_t i = 0; i < M * 2; i++)
	{
		ciParityPtrs[i] = &ciParity[i];
	}
	encryptor.encrypt_zero_asymmetric_batched(ciParityPtrs);
	Plaintext encodedTemp;
	BackupUsedAgain = 0;							 // Whether and how many times backupHints were used during query process; frequent use indicates a problem
	memset(Parity, 0, sizeof(uint64_t) * B * M * 2); // Initialize parity to 0
	// For offline generation the indicator bit is always set to 1.
	memset(IndicatorBit, 255, (M + 7) / 8); // Set all hint indicator bits to 1

	uint32_t InvalidHints = 0;
	uint32_t prfOut[4];
	for (uint32_t hint_i = 0; hint_i < M + M / 2; hint_i++)
	{ // Calculate M+M/2 thresholds
		// Find the cutoffs for each hint
		if ((hint_i % 4) == 0)
		{
			for (uint32_t k = 0; k < PartNum; k++)
			{													   // PartNum is number of partitions
				prf.evaluate((uint8_t *)prfOut, hint_i / 4, k, 1); // Output, four at a time, for each partition, 1 represents select
				for (uint8_t l = 0; l < 4; l++)
				{
					prfSelectVals[PartNum * l + k] = prfOut[l];
				}
			}
		}
		SelectCutoff[hint_i] = FindCutoff(prfSelectVals + PartNum * (hint_i % 4), PartNum); // prfSelectVals + PartNum*(hint_i%4) points to current hint's choice start position, select PartNum items, calculate hint value
		InvalidHints += !SelectCutoff[hint_i];
	}
	cout << "Offline: cutoffs done, invalid hints: " << InvalidHints << endl;

	uint16_t prfIndices[8];
	for (uint32_t hint_i = 0; hint_i < M; hint_i++)
	{
		HintID[hint_i] = hint_i;

		uint16_t ePart;
		bool b = 1;
		while (b)
		{
			// Keep picking until hitting an un-selected partition
			ePart = NextDummyIdx() % PartNum;
			b = prf.PRF4Select(hint_i, ePart, SelectCutoff[hint_i]); // Determine if partition is selected
		}
		uint16_t eIdx = NextDummyIdx() % PartSize;
		ExtraPart[hint_i] = ePart;
		ExtraOffset[hint_i] = eIdx;
	}
	cout << "Offline: extra indices done." << endl;
	// Run Algorithm 4
	// Simulates streaming the entire database one partition at a time.
	for (uint32_t part_i = 0; part_i < PartNum; part_i++)
	{
		Ciphertext temp;
		for (uint32_t hint_i = 0; hint_i < M + M / 2; hint_i++)
		{
			// Compute parities for all hints involving the current loaded partition.
			if ((hint_i % 4) == 0)
			{
				// Each prf evaluation generates the v values for 4 consecutive hints
				prf.evaluate((uint8_t *)prfOut, hint_i / 4, part_i, 1);
			}
			if ((hint_i % 8) == 0)
			{
				// Each prf evaluation generates the in-partition offsets for 8 consecutive hints
				prf.evaluate((uint8_t *)prfIndices, hint_i / 8, part_i, 2);
			}
			bool b = prfOut[hint_i % 4] < SelectCutoff[hint_i];	  // Dummy or real query
			uint16_t r = prfIndices[hint_i % 8] & (PartSize - 1); // Offset
			temp = server.encryptedDB[part_i];
			
			if (hint_i < M)
			{
				if (b)
				{
					// B=1, removed loop: multiply by x^r and add to previous parity
					evaluator.negacyclic_shift_inplace(temp, PartSize - r - 1);
					evaluator.add_inplace(ciParity[hint_i], temp);
				}
				else if (ExtraPart[hint_i] == part_i)
				{
					// B=1, removed loop: multiply by offset of hit extra index and add to previous parity
					evaluator.negacyclic_shift_inplace(temp, PartSize - ExtraOffset[hint_i] - 1);
					evaluator.add_inplace(ciParity[hint_i], temp);
				}
			}
			else
			{
				// construct backup hints in pairs
				uint32_t dst = hint_i + b * M / 2;
				// B=1, removed loop: multiply by x^r and add to previous parity
				evaluator.negacyclic_shift_inplace(temp, PartSize - r - 1);
				evaluator.add_inplace(ciParity[dst], temp);
			}
		}
	}
	NextHintIndex = M;
}
/*
void OneSVClient::Offline(OneSVServer &server, BatchEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator, uint32_t &bgvRingSize, troy::HeContextPointer &context, troy::KeyGenerator &keygen)
{
	// Setup encryption parameters.
	Decryptor decryptor(context, keygen.secret_key());
	ciParity.resize(M * 2);
	std::vector<troy::Ciphertext *> ciParityPtrs(M * 2);
	for (size_t i = 0; i < M * 2; i++)
	{
		ciParityPtrs[i] = &ciParity[i];
	}
	encryptor.encrypt_zero_asymmetric_batched(ciParityPtrs);
	Plaintext encodedTemp;
	BackupUsedAgain = 0;							 // Whether and how many times backupHints were used during query process; frequent use indicates a problem
	memset(Parity, 0, sizeof(uint64_t) * B * M * 2); // Initialize parity to 0
	// For offline generation the indicator bit is always set to 1.
	memset(IndicatorBit, 255, (M + 7) / 8); // Set all hint indicator bits to 1

	uint32_t InvalidHints = 0;
	uint32_t prfOut[4];
	for (uint32_t hint_i = 0; hint_i < M + M / 2; hint_i++)
	{ // Calculate M+M/2 thresholds
		// Find the cutoffs for each hint
		if ((hint_i % 4) == 0)
		{
			for (uint32_t k = 0; k < PartNum; k++)
			{													   // PartNum is the number of partitions
				prf.evaluate((uint8_t *)prfOut, hint_i / 4, k, 1); // Output, four at a time, for each partition, 1 represents select
				for (uint8_t l = 0; l < 4; l++)
				{
					prfSelectVals[PartNum * l + k] = prfOut[l];
				}
			}
		}
		SelectCutoff[hint_i] = FindCutoff(prfSelectVals + PartNum * (hint_i % 4), PartNum); // prfSelectVals + PartNum*(hint_i%4) points to current hint's choice start position, select PartNum items, calculate hint value
		InvalidHints += !SelectCutoff[hint_i];
	}
	cout << "Offline: cutoffs done, invalid hints: " << InvalidHints << endl;

	uint16_t prfIndices[8];
	for (uint32_t hint_i = 0; hint_i < M; hint_i++)
	{
		HintID[hint_i] = hint_i;

		uint16_t ePart;
		bool b = 1;
		while (b)
		{
			// Keep picking until hitting an un-selected partition
			ePart = NextDummyIdx() % PartNum;
			b = prf.PRF4Select(hint_i, ePart, SelectCutoff[hint_i]); // Determine if partition is selected
		}
		uint16_t eIdx = NextDummyIdx() % PartSize;
		ExtraPart[hint_i] = ePart;
		ExtraOffset[hint_i] = eIdx;
	}
	cout << "Offline: extra indices done." << endl;
	// Run Algorithm 4
	// Simulates streaming the entire database one partition at a time.
	uint64_t *DBPart = new uint64_t[PartSize * B];
	uint32_t bgvRingSize = encoder.slot_count(); // Get slot count from encoder
	std::vector<uint64_t> bgvRingVec(bgvRingSize, 0);
	std::vector<Plaintext> encodeVector; // Initially empty
	std::vector<Ciphertext> tempVector;
	std::vector<Ciphertext> ciParityVector;
	for (uint32_t part_i = 0; part_i < PartNum; part_i++)
	{
		for (uint32_t j = 0; j < PartSize; j++)
		{
			server.getEntry(part_i * PartSize + j, DBPart + j * B); // Copy j-th record of current partition from server database to corresponding position in local buffer DBPart
		}
		Ciphertext temp;
		encodeVector.clear(); // Clear previous data, size=0
		tempVector.clear();
		ciParityVector.clear();
		encodeVector.reserve(M + M / 2); // Reserve memory, won't change size
		tempVector.reserve(M + M / 2);
		ciParityVector.reserve(M + M / 2);
		for (uint32_t hint_i = 0; hint_i < M + M / 2; hint_i++)
		{
			// Compute parities for all hints involving the current loaded partition.
			if ((hint_i % 4) == 0)
			{
				// Each prf evaluation generates the v values for 4 consecutive hints
				prf.evaluate((uint8_t *)prfOut, hint_i / 4, part_i, 1);
			}
			if ((hint_i % 8) == 0)
			{
				// Each prf evaluation generates the in-partition offsets for 8 consecutive hints
				prf.evaluate((uint8_t *)prfIndices, hint_i / 8, part_i, 2);
			}
			bool b = prfOut[hint_i % 4] < SelectCutoff[hint_i];	  // Dummy or real query
			uint16_t r = prfIndices[hint_i % 8] & (PartSize - 1); // Offset
			temp = server.encryptedDB[part_i];
			if (hint_i < M)
			{
				if (b)
				{
					for (uint32_t l = 0; l < B; l++)
					{

						bgvRingVec[PartSize - r - 1] = 1;
						Plaintext qq = encoder.encode_polynomial_new(bgvRingVec);
						encodeVector.push_back(qq);
						tempVector.push_back(temp);
						ciParityVector.push_back(ciParity[hint_i]);
						Parity[hint_i * B + l] ^= DBPart[r * B + l];
					}
				}
				else if (ExtraPart[hint_i] == part_i)
				{
					for (uint32_t l = 0; l < B; l++)
					{
						Parity[hint_i * B + l] ^= DBPart[ExtraOffset[hint_i] * B + l];
						bgvRingVec[PartSize - ExtraOffset[hint_i] - 1] = 1;
						Plaintext qq = encoder.encode_polynomial_new(bgvRingVec);
						encodeVector.push_back(qq);
						tempVector.push_back(temp);
						ciParityVector.push_back(ciParity[hint_i]);
						bgvRingVec[PartSize - ExtraOffset[hint_i] - 1] = 0;
					}
				}
			}
			else
			{
				// construct backup hints in pairs
				uint32_t dst = hint_i * B + b * B * M / 2;
				for (uint32_t l = 0; l < B; l++)
				{
					Parity[dst + l] ^= DBPart[r * B + l];
					bgvRingVec[PartSize - r - 1] = 1;
					Plaintext qq = encoder.encode_polynomial_new(bgvRingVec);
					encodeVector.push_back(qq);
					tempVector.push_back(temp);
					ciParityVector.push_back(ciParity[dst]);
					bgvRingVec[PartSize - r - 1] = 0;
				}
			}
		}

		std::vector<const Plaintext *> encodePtrVec;
		encodePtrVec.reserve(encodeVector.size());

		for (auto &pt : encodeVector)
		{
			encodePtrVec.push_back(&pt); // &pt is of type Plaintext*, can be implicitly converted to const Plaintext*
		}
		std::vector<Ciphertext *> tempPtrVec;
		for (auto &ct : tempVector)
		{
			tempPtrVec.push_back(&ct);
		}

		std::vector<Ciphertext *> ciParityPtrVec;
		for (auto &ct : ciParityVector)
		{
			ciParityPtrVec.push_back(&ct);
		}

		evaluator.multiply_plain_inplace_batched(tempPtrVec, encodePtrVec);
		std::vector<const Ciphertext *> tempInputPtrVec;
		for (auto &ct : tempVector)
		{
			tempInputPtrVec.push_back(&ct);
		}
		evaluator.add_inplace_batched(ciParityPtrVec, tempInputPtrVec);
	}
	NextHintIndex = M;
	std::cout << "Done" << endl;
}
*/
uint64_t getSecureRandom64()
{
	std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
	uint64_t number;
	urandom.read(reinterpret_cast<char *>(&number), sizeof(number));
	return number;
}

void OneSVClient::Online(OneSVServer &server, uint32_t query, uint64_t *result, troy::BatchEncoder &encoder, troy::Encryptor &encryptor, troy::Evaluator &evaluator)
{
	assert(query <= N);
	uint16_t queryPartNum = query / PartSize;
	uint16_t queryOffset = query & (PartSize - 1);
	bool b_indicator = 0;

	// Run Algorithm 2
	// Find a hint that has our desired query index
	uint64_t hintIndex = find_hint(query, queryPartNum, queryOffset, b_indicator);
	assert(hintIndex < M);

	// Build a query.
	uint32_t hintID = HintID[hintIndex];
	uint32_t cutoff = SelectCutoff[hintIndex]; // Median
	// Randomize the selector bit that is sent to the server.
	bool shouldFlip = rand() & 1;

	if (hintID > M)
	{
		BackupUsedAgain++;
	}

	for (uint32_t part = 0; part < PartNum; part++)
	{
		if (part == queryPartNum)
		{
			// Current partition is the queried partition
			bvec[part] = !b_indicator ^ shouldFlip;		  // Assign to dummy query 0/1 group
			Svec[part] = NextDummyIdx() & (PartSize - 1); // Offset
			continue;
		}
		else if (ExtraPart[hintIndex] == part)
		{
			// Current partition is the hint's extra partition
			bvec[part] = b_indicator ^ shouldFlip; // Assign to real query
			Svec[part] = ExtraOffset[hintIndex];
			continue;
		}

		bool b = prf.PRF4Select(hintID, part, cutoff);
		bvec[part] = b ^ shouldFlip;
		if (b == b_indicator)
		{
			// Assign part to real query
			Svec[part] = prf.PRF4Idx(hintID, part) & (PartSize - 1);
		}
		else
		{
			// Assign part to dummy query
			Svec[part] = NextDummyIdx() & (PartSize - 1);
		}
	}
	uint64_t rando = getSecureRandom64() % plainModulus; // Get random value
	std::vector<uint64_t> ran(PartSize, 0);
	ran[PartSize - 1] = rando;
	troy::Plaintext ra = encoder.encode_polynomial_new(ran);
	Ciphertext ci_copy = ciParity[hintIndex]; 
	evaluator.add_plain_inplace(ci_copy, ra);// Add encoded random value to hit hint
	// Make our query
	memset(Response_b0, 0, sizeof(uint64_t) * B);
	memset(Response_b1, 0, sizeof(uint64_t) * B);
	server.onlineQuery(bvec, Svec, Response_b0, Response_b1, ci_copy, encoder);// Send bit array, offset array, and value to be decrypted to server

	// Set the query result to the correct response.
	uint64_t *QueryResult = (!b_indicator ^ shouldFlip) ? Response_b0 : Response_b1;

	for (uint32_t l = 0; l < B; l++)
	{
		// result[l] = QueryResult[l] ^ Parity[hintIndex * B + l];
		if(QueryResult[l]>=rando)
		{
			result[l] = QueryResult[l] - rando; 
		}
		else
		{
			result[l]=plainModulus+QueryResult[l]-rando;// Need modulo, negative number
		}

	}

	while (SelectCutoff[NextHintIndex] == 0)
	{
		// skip invalid hints
		NextHintIndex++;
	}

	// Run Algorithm 5
	// Replenish a hint using a backup hint.
	HintID[hintIndex] = NextHintIndex;
	SelectCutoff[hintIndex] = SelectCutoff[NextHintIndex];
	ExtraPart[hintIndex] = queryPartNum;
	ExtraOffset[hintIndex] = queryOffset;
	// Set the indicator bit to exclude queryPartNum
	b_indicator = !prf.PRF4Select(NextHintIndex, queryPartNum, SelectCutoff[NextHintIndex]);
	IndicatorBit[hintIndex / 8] = (IndicatorBit[hintIndex / 8] & ~(1 << (hintIndex % 8))) | (b_indicator << (hintIndex % 8));
	uint32_t parity_i = NextHintIndex * B;
	parity_i += ((IndicatorBit[hintIndex / 8] >> (hintIndex % 8)) & 1) * B * M / 2;
	std::vector<uint64_t> ve(PartSize, 0);
	ve[PartSize - 1] = result[0];
	Plaintext pl = encoder.encode_polynomial_new(ve);
	for (uint32_t l = 0; l < B; l++)
	{
		// Parity[hintIndex * B + l] = Parity[parity_i + l] ^ result[l];
		ciParity[hintIndex] = evaluator.add_plain_new(ciParity[parity_i], pl);
	}
	NextHintIndex++;
	assert(NextHintIndex < (M + M / 2));
}

// Explicit instantiation of template classes
template class Client<PRFHintID>;
