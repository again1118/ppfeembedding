#include <cassert>
#include <cstdlib>
#include <cmath>
#include <ctime>

#include "server.h"
#include "utils.h"

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdint>
#include <cstring>
using namespace troy;

//Server构造函数（数据库指针，数据库大小，每个条目字节大小，同态加密上下文对象（参数），密钥生成器，明文模数）
OneSVServer::OneSVServer(uint64_t *DB_ptr, uint32_t LogN, uint32_t embDim, troy::HeContextPointer &context, troy::KeyGenerator &keygen, uint64_t p)
	: decryptor(context, keygen.secret_key())
{
	
	EmbeddingDim = embDim;
	assert(LogN < 32);
	// assert(EntryB >= 8);
	N = 1 << LogN;
	// B = EntryB / 8;		// How many u64s are needed
	EntrySize = EmbeddingDim; 
	DB = DB_ptr;
	PartNum = 1 << (LogN / 2);
	PartSize = 1 << (LogN / 2 + LogN % 2);
	lambda = LAMBDA;
	M = lambda * PartSize;
	// tmpEntry = new uint64_t[B]; // For the server to temporarily store a database entry
	plainModulus = p;
	server_share.resize(EmbeddingDim, 0);
}
//Server同态加密明文（编码器，用于将原始 uint64_t 数据映射到加密方案的明文多项式槽（slots）中。加密器，用于执行实际的加密操作）
void OneSVServer::preprocessDatabase(troy::BatchEncoder &encoder, troy::Encryptor &encryptor)
{
	encryptedDB.resize(N); 
	std::vector<troy::Plaintext> p(N); 
	std::vector<uint64_t> vec(EmbeddingDim);  // Fix: should be PartSize instead of PartSize*B
	
	
	// Check whether PartSize exceeds the encoder capacity
	cout << "encoder.slot_count():"<<encoder.slot_count()<< endl;
	// 3. [核心修复] 检查的是 EmbeddingDim 是否超出了底层密码学的支持上限
    if (EmbeddingDim > encoder.slot_count()) {
        std::cerr << "[Error] EmbeddingDim (" << EmbeddingDim << ") exceeds encoder slot_count (" 
                  << encoder.slot_count() << ")" << std::endl;
        std::cerr << "[Error] Need to increase bgvRingSize to at least " << EmbeddingDim << std::endl;
        throw std::runtime_error("EmbeddingDim exceeds encoder capacity");
    }
	
	for (uint32_t i = 0; i < N; i++)
	{
		std::copy(DB + i * EmbeddingDim, DB + (i + 1) * EmbeddingDim, vec.begin()); 
		encoder.encode_polynomial(vec, p[i]);
	}
	
	std::vector<troy::Ciphertext *> ciParityPtrs(N);
	std::vector<const troy::Plaintext *> pptr(N);
	for (size_t i = 0; i < N; i++)
	{
		ciParityPtrs[i] = &encryptedDB[i];
		pptr[i] = &p[i];
	}
	encryptor.encrypt_asymmetric_batched(pptr, ciParityPtrs);
	std::cout << "[Server] Database preprocessing complete, encrypted" << std::endl;
}
//Server获取指定DB数据
void OneSVServer::getEntry(uint32_t index, uint64_t *result)
{
	getEntryFromDB(DB, index, result, EntrySize);
}


//Server在线查表
void OneSVServer::onlineQuery(bool *bvec, uint32_t *Svec, uint64_t *b0, uint64_t *b1, troy::Ciphertext &c, troy::BatchEncoder &encoder, troy::Encryptor &encryptor, troy::Ciphertext &ci_s_share_out)
{
    // 1. Decrypt query ciphertext from client to get plaintext vector.
    //    This vector contains client query info and potential random mask.
    // std::vector<uint64_t> vec = encoder.decode_polynomial_new(decryptor.decrypt_new(c));
	// 1. Decrypt query ciphertext from client, perform linear calculation: c1 + c0*s (mod q)
	//    No full decoding and scaling, direct BFV decryption on ciphertext modulus q.
	troy::Plaintext decrypted = decryptor.bfv_decrypt_without_scaling_down_new(c);

	// Set Plaintext attributes to be correctly handled by decode_polynomial_new.
	// decode_polynomial_slice requires: !is_ntt_form() && parms_id() == parms_id_zero
	// Plaintext returned by bfv_decrypt_without_scaling_down_new doesn't meet these requirements and needs manual setting.
	decrypted.parms_id() = troy::parms_id_zero;  // [MODIFIED, UNCERTAIN] Set to zero parameter ID, indicating not at a specific parameter level
	decrypted.is_ntt_form() = false;       // [MODIFIED, UNCERTAIN] Set to non-NTT form

	// 2. Decode decrypted plaintext polynomial into coefficient vector.
	//    Coefficients in vec are still under ciphertext modulus q (result of bfv_decrypt_without_scaling_down_new)
	//    decode_polynomial_new simply copies Plaintext coefficient data without modulus conversion.
	//    This vector represents client query polynomial coefficients, the last element contains random mask added by client.
	//    Used for subsequent database query calculations: b0 and b1 initialization are based on this vector.
	std::vector<uint64_t> vec = encoder.decode_polynomial_new(decrypted);


	// 3. Initialize two candidate results: b0 and b1.
	//    Both set to the value of the last element in the decrypted vector (containing random mask added by client).
	for (uint32_t i = 0; i < EmbeddingDim; i++) {
		b0[i] = 0;
		b1[i] = 0;
	}

	

	// 4. Process each partition.
	//    Based on client's bvec choice bits, add database entries to candidate results.
	for (uint32_t k = 0; k < PartNum; k++) {
    	uint32_t target_row = k * PartSize + Svec[k];
        
        for (uint32_t i = 0; i < EmbeddingDim; i++) {
            // 直接算出绝对内存偏移并读取
            uint64_t val = DB[target_row * EmbeddingDim + i];
            
            if (bvec[k]) {
                b1[i] = (b1[i] + val) % plainModulus;
            } else {
                b0[i] = (b0[i] + val) % plainModulus;
            }
        }
	}
	//添加noise的形式
	// // Get ciphertext modulus q for modulo operations
	// uint64_t modulus_q = decryptor.context()->key_context_data().value()->parms().coeff_modulus()[0].value();
	
	// // In BFV, plaintext vector needs to be multiplied by delta (ciphertext modulus / plaintext modulus) to be correctly represented in ciphertext domain
	// double delta = static_cast<double>(modulus_q) / static_cast<double>(plainModulus);  // delta = q/p
	// static bool seeded = false;

	// if (!seeded) {
	// 	srand(time(NULL));
	// 	seeded = true;
	// }

	// for (uint32_t i = 0; i < EmbeddingDim; i++){
	// 	uint64_t scaled_b0 = static_cast<uint64_t>(static_cast<double>(b0[i]) * delta) % modulus_q;
	// 	uint64_t scaled_b1 = static_cast<uint64_t>(static_cast<double>(b1[i]) * delta) % modulus_q;
	// 	// Remove plaintext b0[0] and b1[0] from corresponding positions in vec.
	// 	// vec is coefficient vector in ciphertext modulus domain, need to subtract scaled plaintext values.
	// 	b0[i] = (vec[i] + modulus_q - scaled_b0) % modulus_q;  // Remove b0
	// 	b1[i] = (vec[i] + modulus_q - scaled_b1) % modulus_q;  // Remove b1
	// 	// Generate Gaussian noise, size approx 10 bits (standard deviation approx 1024).
	// 	// Generate different Gaussian noise for b0[0] and b1[0] respectively.
		

	// 	// Generate noise for b0[0]
	// 	double u1 = (double)rand() / RAND_MAX;
	// 	double u2 = (double)rand() / RAND_MAX;
	// 	double z0 = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
	// 	int64_t noise = (int64_t)(z0 * 64 *1048576.0);  // 20 bit noise, standard deviation 2^20

	// 	// Add same noise to b0[0] and b1[0], keeping within modulus_q range
	// 	b0[i] = (b0[i] + modulus_q + (uint64_t)noise) % modulus_q;
	// 	b1[i] = (b1[i] + modulus_q + (uint64_t)noise) % modulus_q;

	//秘密份额的形式
	uint64_t modulus_q = decryptor.context()->key_context_data().value()->parms().coeff_modulus()[0].value();
    uint64_t p = plainModulus;
    uint64_t q = modulus_q;
	for (uint32_t i = 0; i < EmbeddingDim; i++) {
		// 1. Scale-and-Round: 将密文缩放回明文空间，得到纯净的 (Ghost + Target + ra)
        __uint128_t val = vec[i];
        val = (val * p + (q / 2)) / q;
        uint64_t ci_plain = (uint64_t)val % p; 
        
        // 2. 魔法时刻：消灭幽灵！
        // 用 (Ghost + Target + ra) 减去算出来的 Ghost (即 b0 或 b1)
        uint64_t target_plus_ra_0 = (ci_plain + p - b0[i]) % p;
        uint64_t target_plus_ra_1 = (ci_plain + p - b1[i]) % p;

        // 3. MPC 秘密分享：扣除服务器的份额
        server_share[i] = getSecureRandom64() % plainModulus; 
        
        // 发给客户端的残差：(Target + ra - server_share)
        b0[i] = (target_plus_ra_0 + p - server_share[i]) % p;
        b1[i] = (target_plus_ra_1 + p - server_share[i]) % p;

		troy::Plaintext pt_s = encoder.encode_polynomial_new(server_share);
    
		// 生成密文盲盒，传给客户端
		ci_s_share_out = encryptor.encrypt_asymmetric_new(pt_s);

    }
	// cout << "server_share[0]:"<< server_share[0]<<"b0[0]:"<<b0[0]<<"b1[0]"<<b1[0]<<endl;
	// Finally: only one of b0 and b1 contains correct result (all redundant terms subtracted), the other contains incorrect result.
	// Client selects correct one based on its choice bit.
	// OT sending moved to main thread persistent session in server_main.cpp, no OT network communication here.

}
