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
//template <class PRF>: 是一个模板声明。Client 类不是一个具体的类，而是一个类模板。PRF（伪随机函数）是一个占位符，允许你在实例化客户端时指定不同的随机算法
template <class PRF>
Client<PRF>::Client(uint32_t LogN, uint32_t embDim) : prf(AES_KEY)
{
	assert(LogN < 32);
	// assert(EntryB >= 8);
	N = 1 << LogN; // Database size
	// B is the size of one entry in uint64s
	// B = EntryB / 8; // Size of each entry
	EmbeddingDim = embDim;

	PartNum = 1 << (LogN / 2);			   // Number of partitions sqrt(n)
	PartSize = 1 << (LogN / 2 + LogN % 2); // Size of each partition   需要改吗
	lambda = LAMBDA;
	M = lambda * PartSize;

	// Allocate memory for making requests to servers and receiving responses from servers
	bvec = new bool[PartNum];	   // Decides if this partition is a real or dummy query
	Svec = new uint32_t[PartNum];  // Specific query offset for each partition
	Response_b0 = new uint64_t[EmbeddingDim]; // Two responses
	Response_b1 = new uint64_t[EmbeddingDim];
	// tmpEntry = new uint64_t[EmbeddingDim]; // Decryption result
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

OneSVClient::OneSVClient(uint32_t LogN, uint32_t embDim,uint64_t p) : Client(LogN, embDim)
{
	// Allocate storage for hints. One server version stores M more hint parities and cutoffs as backup hints.
	SelectCutoff = new uint32_t[M * 2]; // Used to determine the median value
	Parity = new uint64_t[M * 2 * EmbeddingDim];	// XOR value
	plainModulus=p;
	prfSelectVals = new uint32_t[PartNum * 4]; // Temporary variable to store intermediate values
	DBPart = new uint64_t[PartSize*EmbeddingDim];  // B is always 1, only load a part

	encZeroCache.clear();
	encZeroNext = 0;
	client_share.resize(EmbeddingDim, 0);
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
	std::vector<troy::Ciphertext *> ciParityPtrs(M * 2); //提示指针数组
	for (size_t i = 0; i < M * 2; i++)
	{
		ciParityPtrs[i] = &ciParity[i];
	}
	//调用底层的 Troy 库，使用公钥批量生成 2M 个初始值为 0 的同态密文。累加的起点
	encryptor.encrypt_zero_asymmetric_batched(ciParityPtrs);
	// Plaintext encodedTemp;
	BackupUsedAgain = 0;							 // Whether and how many times backupHints were used during query process; frequent use indicates a problem
	memset(Parity, 0, sizeof(uint64_t) * EmbeddingDim * M * 2); // Initialize parity to 0
	// For offline generation the indicator bit is always set to 1.
	memset(IndicatorBit, 255, (M + 7) / 8); // Set all hint indicator bits to 1

	uint32_t InvalidHints = 0;
	uint32_t prfOut[4]; //用于接收 PRF (伪随机函数) 输出的缓冲数组
	for (uint32_t hint_i = 0; hint_i < M + M / 2; hint_i++) //
	{ // Calculate M+M/2 thresholds
		// Find the cutoffs for each hint
		//因为 PRF 算一次能吐出 4 个值，所以每 4 个 Hint 算一次就行。
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

	uint16_t prfIndices[8]; // 用于接收 PRF 算出的块内偏移量
	for (uint32_t hint_i = 0; hint_i < M; hint_i++) //为主提示加入额外的元素
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
			// temp = server.encryptedDB[part_i];
			
			if (hint_i < M)
			{
				if (b)
				{
					// B=1, removed loop: multiply by x^r and add to previous parity
					// evaluator.negacyclic_shift_inplace(temp, PartSize - r - 1);
					// evaluator.add_inplace(ciParity[hint_i], temp);
					// 算出在全局数据库中的绝对索引
                    uint32_t absolute_idx = part_i * PartSize + r;
                    Ciphertext temp = server.encryptedDB[absolute_idx];
                    evaluator.add_inplace(ciParity[hint_i], temp);
				}
				else if (ExtraPart[hint_i] == part_i)
				{
					// B=1, removed loop: multiply by offset of hit extra index and add to previous parity
					// evaluator.negacyclic_shift_inplace(temp, PartSize - ExtraOffset[hint_i] - 1);
					// evaluator.add_inplace(ciParity[hint_i], temp);
					// 算出 Extra 元素在全局数据库中的绝对索引
                    uint32_t extra_absolute_idx = part_i * PartSize + ExtraOffset[hint_i];
                    Ciphertext extra_temp = server.encryptedDB[extra_absolute_idx];
                    evaluator.add_inplace(ciParity[hint_i], extra_temp);
				}
			}
			else
			{
				// construct backup hints in pairs
				uint32_t dst = hint_i + b * M / 2;
				// B=1, removed loop: multiply by x^r and add to previous parity
				// evaluator.negacyclic_shift_inplace(temp, PartSize - r - 1);
				// evaluator.add_inplace(ciParity[dst], temp);
				uint32_t absolute_idx = part_i * PartSize + r;
                Ciphertext temp = server.encryptedDB[absolute_idx];
                evaluator.add_inplace(ciParity[dst], temp);
			}
		}
	}
	NextHintIndex = M;
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
	uint64_t modulus_q = encryptor.context()->key_context_data().value()->parms().coeff_modulus()[0].value();
	// uint64_t rando = getSecureRandom64() % plainModulus; // Get random value
	std::vector<uint64_t> ran(EmbeddingDim, 0);
	// ran[PartSize - 1] = rando;
	for (uint32_t i = 0; i < EmbeddingDim; i++) {
        ran[i] = getSecureRandom64() % plainModulus;
    }
	troy::Plaintext ra = encoder.encode_polynomial_new(ran);
	// cout << "ra[0]"<< ran[0]<< endl;
	Ciphertext ci_copy = ciParity[hintIndex]; 

	evaluator.add_plain_inplace(ci_copy, ra);// Add encoded random value to hit hint
	// Make our query
	memset(Response_b0, 0, sizeof(uint64_t) * EmbeddingDim);
	memset(Response_b1, 0, sizeof(uint64_t) * EmbeddingDim);
	troy::Ciphertext ci_s_share;
	server.onlineQuery(bvec, Svec, Response_b0, Response_b1, ci_copy, encoder,encryptor,ci_s_share);// Send bit array, offset array, and value to be decrypted to server
	// cout << "Response_b0[0]:"<<Response_b0[0]<<"Response_b1[0]"<<Response_b1[0]<<endl;
	// Set the query result to the correct response.
	uint64_t *QueryResult = (!b_indicator ^ shouldFlip) ? Response_b0 : Response_b1;
	//添加noise形式
	// uint64_t q = modulus_q;
    // uint64_t p = plainModulus;
	// for (uint32_t l = 0; l < EmbeddingDim; l++)
	// {
	// 	// 1. Scale-and-Round: 将数据从密文空间(q)按比例缩放回明文空间(p)
    //     // 使用 uint128_t 防止乘法溢出 (56 bits + 33 bits = 89 bits)
    //     uint128_t val = QueryResult[l];
    //     val = (val * p + (q / 2)) / q; 
    //     uint64_t res = (uint64_t)val % p;

    //     // 2. 减去当初加上的随机数掩码
    //     if(res >= ran[l])
    //     {
    //         result[l] = res - ran[l]; 
    //     }
    //     else
    //     {
    //         result[l] = p + res - ran[l]; // 安全的模减法
    //     }
	// }

	//秘密份额形式
	uint64_t p = plainModulus;

    for (uint32_t l = 0; l < EmbeddingDim; l++)
    {
        if(QueryResult[l] >= ran[l])
        {
            result[l] = QueryResult[l] - ran[l]; 
        }
        else
        {
            result[l] = p + QueryResult[l] - ran[l]; // 安全的模减法
        }
		client_share[l] = result[l];
    }
	// cout <<"QueryResult[0]" <<QueryResult[0]<<"client_share[0]:" <<client_share[0]<<"result[0]:"<<result[0]<<endl;

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
	uint32_t parity_i = NextHintIndex;
	parity_i += ((IndicatorBit[hintIndex / 8] >> (hintIndex % 8)) & 1) * M / 2;
	std::vector<uint64_t> vec(result, result + EmbeddingDim);
	Plaintext pl_c_share = encoder.encode_polynomial_new(vec); 

	ciParity[hintIndex] = evaluator.add_new(ciParity[parity_i], ci_s_share); 

	evaluator.add_plain_inplace(ciParity[hintIndex], pl_c_share);
	// for (uint32_t l = 0; l < B; l++)
	// {
	// 	// Parity[hintIndex * B + l] = Parity[parity_i + l] ^ result[l];
	// 	ciParity[hintIndex] = evaluator.add_plain_new(ciParity[parity_i], pl);
	// }
	NextHintIndex++;
	assert(NextHintIndex < (M + M / 2));
}

// Explicit instantiation of template classes
template class Client<PRFHintID>;
