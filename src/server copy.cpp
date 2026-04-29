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

OneSVServer::OneSVServer(uint64_t *DB_ptr, uint32_t LogN, uint32_t EntryB, troy::HeContextPointer &context, troy::KeyGenerator &keygen, uint64_t p)
	: decryptor(context, keygen.secret_key())
{
	assert(LogN < 32);
	assert(EntryB >= 8);
	N = 1 << LogN;
	B = EntryB / 8;		// How many u64s are needed
	EntrySize = EntryB; // Keep the original number of bytes
	DB = DB_ptr;
	PartNum = 1 << (LogN / 2);
	PartSize = 1 << (LogN / 2 + LogN % 2);
	lambda = LAMBDA;
	M = lambda * PartSize;
	tmpEntry = new uint64_t[B]; // For the server to temporarily store a database entry
	plainModulus = p;
}
void OneSVServer::preprocessDatabase(troy::BatchEncoder &encoder, troy::Encryptor &encryptor)
{
	encryptedDB.resize(PartNum);
	std::vector<troy::Plaintext> p(PartNum);
	std::vector<uint64_t> vec(PartSize);  // Fix: should be PartSize instead of PartSize*B
	
	
	// Check whether PartSize exceeds the encoder capacity
	if (PartSize > encoder.slot_count()) {
		std::cerr << "[Error] PartSize (" << PartSize << ") exceeds encoder slot_count (" 
		          << encoder.slot_count() << ")" << std::endl;
		std::cerr << "[Error] Need to increase bgvRingSize to at least " << PartSize << std::endl;
		throw std::runtime_error("PartSize exceeds encoder capacity");
	}
	
	for (uint32_t i = 0; i < PartNum; i++)
	{
		std::copy(DB + i * PartSize, DB + (i + 1) * PartSize, vec.begin());
		encoder.encode_polynomial(vec, p[i]);
	}
	
	std::vector<troy::Ciphertext *> ciParityPtrs(PartNum);
	std::vector<const troy::Plaintext *> pptr(PartNum);
	for (size_t i = 0; i < PartNum; i++)
	{
		ciParityPtrs[i] = &encryptedDB[i];
		pptr[i] = &p[i];
	}
	encryptor.encrypt_asymmetric_batched(pptr, ciParityPtrs);
	std::cout << "[Server] Database preprocessing complete, encrypted" << std::endl;
}
void OneSVServer::getEntry(uint32_t index, uint64_t *result)
{
	getEntryFromDB(DB, index, result, EntrySize);
}

void OneSVServer::onlineQuery(bool *bvec, uint32_t *Svec, uint64_t *b0, uint64_t *b1, troy::Ciphertext &c, troy::BatchEncoder &encoder)
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
	// b1[0] = vec[PartSize - 1];
	// b0[0] = vec[PartSize - 1];
	b1[0] = 0; // [MODIFIED, now calculating sum in plaintext space]
	b0[0] = 0; // [MODIFIED, now calculating sum in plaintext space]

	// 4. Process each partition.
	//    Based on client's bvec choice bits, add database entries to candidate results.
	for (uint32_t k = 0; k < PartNum; k++)
	{
		// Get database entry with specified offset in current partition
		getEntryFromDB(DB, k * PartSize + Svec[k], tmpEntry, EntrySize);
		uint64_t entry_val = tmpEntry[0];  // B=1, only one element

		if (bvec[k]) {
			// If choice bit is 1, add this database entry to b1 (modulo plaintext modulus operation)
			// b1 += entry_val (mod plainModulus)
			b1[0] = (b1[0] + entry_val) % plainModulus;
		} else {
			// If choice bit is 0, add this database entry to b0 (modulo plaintext modulus operation)
			// b0 += entry_val (mod plainModulus)
			b0[0] = (b0[0] + entry_val) % plainModulus;
		}
	}
	// Get ciphertext modulus q for modulo operations
	uint64_t modulus_q = decryptor.context()->key_context_data().value()->parms().coeff_modulus()[0].value();
	
	// In BFV, plaintext vector needs to be multiplied by delta (ciphertext modulus / plaintext modulus) to be correctly represented in ciphertext domain
	double delta = static_cast<double>(modulus_q) / static_cast<double>(plainModulus);  // delta = q/p
	uint64_t scaled_b0 = static_cast<uint64_t>(static_cast<double>(b0[0]) * delta) % modulus_q;
	uint64_t scaled_b1 = static_cast<uint64_t>(static_cast<double>(b1[0]) * delta) % modulus_q;

	// Remove plaintext b0[0] and b1[0] from corresponding positions in vec.
	// vec is coefficient vector in ciphertext modulus domain, need to subtract scaled plaintext values.
	uint64_t vec_value = vec[PartSize - 1];
	b0[0] = (vec_value + modulus_q - scaled_b0) % modulus_q;  // Remove b0
	b1[0] = (vec_value + modulus_q - scaled_b1) % modulus_q;  // Remove b1

	// Generate Gaussian noise, size approx 10 bits (standard deviation approx 1024).
	// Generate different Gaussian noise for b0[0] and b1[0] respectively.
	static bool seeded = false;

	if (!seeded) {
		srand(time(NULL));
		seeded = true;
	}

	// Generate noise for b0[0]
	double u1_b0 = (double)rand() / RAND_MAX;
	double u2_b0 = (double)rand() / RAND_MAX;
	double z0_b0 = sqrt(-2.0 * log(u1_b0)) * cos(2.0 * M_PI * u2_b0);
	int64_t noise_b0 = (int64_t)(z0_b0 * 64 *1048576.0);  // 20 bit noise, standard deviation 2^20

	// Add same noise to b0[0] and b1[0], keeping within modulus_q range
	b0[0] = (b0[0] + modulus_q + (uint64_t)noise_b0) % modulus_q;
	b1[0] = (b1[0] + modulus_q + (uint64_t)noise_b0) % modulus_q;
	// Finally: only one of b0 and b1 contains correct result (all redundant terms subtracted), the other contains incorrect result.
	// Client selects correct one based on its choice bit.
	// OT sending moved to main thread persistent session in server_main.cpp, no OT network communication here.

}
