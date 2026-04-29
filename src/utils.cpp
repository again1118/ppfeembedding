#include "utils.h"

// void getEntryFromDB(uint64_t* DB, uint32_t index, uint64_t *result, uint32_t EntrySize)
// {
// #ifdef DEBUG
// 	uint64_t dummyData = index;
// 	dummyData <<= 1;
// 	for (uint32_t l = 0; l < EntrySize / 8; l++)
// 		result[l] = dummyData + l; 
// 	return;
// #endif

// 	#ifdef SimLargeServer
// 		memcpy(result, ((uint8_t*) DB) + index, EntrySize);	
// 	#else
// 		memcpy(result, DB + index * (EntrySize / 8), EntrySize); 
// 	#endif	
// };

void getEntryFromDB(uint64_t* DB, uint32_t index, uint64_t *result, uint32_t embeddingdim)
{
    // 【终极修复】：去掉原版所有除以 8 的恶心逻辑！
    // 直接按维度进行纯正的指针偏移和拷贝！
#ifdef SimLargeServer
    memcpy(result, ((uint8_t*) DB) + index * embeddingdim * sizeof(uint64_t), embeddingdim * sizeof(uint64_t));	
#else
    memcpy(result, DB + index * embeddingdim, embeddingdim * sizeof(uint64_t)); 
#endif	
};


void initDatabase(uint64_t** DB, uint64_t kLogDBSize, uint64_t embeddingdim, uint64_t plainModulus){
// #ifdef SimLargeServer
// 	uint64_t DBSizeInUint64 = ((uint64_t) 1 << (kLogDBSize-3)) + embedDingdim;		
// #else
// 	uint64_t DBSizeInUint64 = ((uint64_t) embedDingdim) << kLogDBSize;
// #endif	
	uint64_t DBSizeInUint64 = ((uint64_t) embeddingdim) << kLogDBSize;
	*DB = new uint64_t [DBSizeInUint64];
	cout << "[Utils] Allocated DB with " << DBSizeInUint64 << " dimensions." << endl;
	/*ifstream frand("/dev/urandom"); 
	frand.read((char*) *DB, DBSizeInUint64);
	frand.close();*/
	 for (uint64_t i = 0; i < DBSizeInUint64; i++) {
        (*DB)[i] = (i) % plainModulus;
    }
}

uint32_t FindCutoff(uint32_t *prfVals, uint32_t PartNum) {
	uint32_t LowerFilter = 0x80000000 - (1 << 28);
	uint32_t UpperFilter = 0x80000000 + (1 << 28);

	uint32_t LowerCnt = 0, UpperCnt = 0, MiddleCnt = 0;	
	for (uint32_t k = 0; k < PartNum; k++)
  	{
		if (prfVals[k] < LowerFilter)
			LowerCnt++;
		else if (prfVals[k] > UpperFilter)
			UpperCnt++;
		else
		{
			prfVals[MiddleCnt] = prfVals[k];	// move to beginning, ok to overwrite filtered stuff
			MiddleCnt++;
		} 	
	}
	if (LowerCnt >= PartNum / 2 || UpperCnt >= PartNum / 2)
	{
	// cout << "Filtered too much" << endl;
		return 0;	// filtered too many, just give up this hint	

	}

	uint32_t *median = prfVals + PartNum / 2 - LowerCnt;
	nth_element(prfVals, median, prfVals + MiddleCnt);
	uint32_t cutoff = *median;
	*median = 0;
	for (uint32_t k = 0; k < MiddleCnt; k++){
		if (prfVals[k] == cutoff) return 0;
	}
	return cutoff;
}

uint64_t getSecureRandom64()
{
	std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
	uint64_t number;
	urandom.read(reinterpret_cast<char *>(&number), sizeof(number));
	return number;
}
