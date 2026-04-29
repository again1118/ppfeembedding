#include <fstream>
#include <chrono>
#include <vector>
#include <type_traits>
#include <unistd.h>

#include "client.h"
#include "server.h"
#include "utils.h"
#include "troy.h"
using namespace std;
using namespace troy;
uint64_t *DB;

struct Options
{
	uint64_t Log2DBSize;
	uint64_t EntrySize;
	string OutputFile;
	bool OneSV;
};

void print_usage()
{
	cout << "Usage:	" << endl
		 << "\t./PPFE --one-server <Log2 DB Size> <Entry Size> <Output File>" << endl
		 << "\t./PPFE --two-server <Log2 DB Size> <Entry Size> <Output File>" << endl
		 << "Runs the PPFE protocol on a database with <Log2 DB Size> number of entries and entries of <Entry Size> bytes with either the one server or two server variant. If <Output File> doesn't exist, creates <Output File> and adds profiling data to the file in csv format. Otherwise append it to the end of the file.  " << endl
		 << endl;
}

Options parse_options(int argc, char *argv[])
{
	Options options{false, false};

	try
	{
		if (argc == 5)
		{
			if (strcmp(argv[1], "--two-server") == 0)
			{
				options.OneSV = 0;
			}
			else if (strcmp(argv[1], "--one-server") == 0)
			{
				options.OneSV = 1;
			}
			else
			{
				print_usage();
				exit(0);
			}
			options.Log2DBSize = stoi(argv[2]);
			options.EntrySize = stoi(argv[3]);
			options.OutputFile = argv[4];
			return options;
		}
		print_usage();
		exit(0);
	}
	catch (...)
	{
		print_usage();
		exit(0);
	}
}

// Helper function since clients have different function signatures between variants
inline void test_client_query(OneSVClient &client, OneSVServer &server, uint32_t &query, uint64_t *result, troy::BatchEncoder &encoder, troy::Encryptor &encryptor, troy::Evaluator &evaluator)
{
	client.Online(server, query, result, encoder, encryptor, evaluator);
}

template <typename Client, typename Server>
void test_pir(uint64_t kLogDBSize, uint64_t kEntrySize, ofstream &output_csv, BatchEncoder &encoder, Encryptor &encryptor, Evaluator &evaluator, uint32_t &bgvRingSize, KeyGenerator &keygen, HeContextPointer &context, uint64_t plainModulus)
{
	if (is_same<Client, OneSVClient>::value && is_same<Server, OneSVServer>::value)
	{
		cout << "== One server variant ==" << endl;
		output_csv << "One server, ";
	}
	uint32_t EmbeddingDim = kEntrySize;
	cout << "LogDBSize: " << kLogDBSize << "\nEmbeddingDim: " << EmbeddingDim << "维" << endl;
	output_csv << kLogDBSize << ", " << EmbeddingDim << ", ";
	uint32_t datasize = 8 ;//向量每一位数据占字节数
	// cout << "[DEBUG] 1. Initializing Database (initDatabase)..." << endl;
	initDatabase(&DB, kLogDBSize, EmbeddingDim*datasize, plainModulus);// Initialize database
	// cout << "[DEBUG] 2. Initializing Client constructor..." << endl;
	Client client(kLogDBSize, EmbeddingDim, plainModulus);					  // client initialization
	// cout << "[DEBUG] 3. Initializing Server constructor..." << endl;
	Server server(DB, kLogDBSize, EmbeddingDim, context, keygen, plainModulus); // server initialization
	// cout << "[DEBUG] 4. Setting up Decryptor..." << endl;
	Decryptor decryptor(context, keygen.secret_key());
	// cout << "[DEBUG] 5. Starting Server Preprocess (server.preprocessDatabase)..." << endl;
	server.preprocessDatabase(encoder, encryptor);//server database encoding
	cout << "Running offline phase.." << endl;
	auto start = chrono::high_resolution_clock::now();
	// cout << "[DEBUG] 6. Starting Client Offline phase (client.Offline)..." << endl;
	client.Offline(server, encoder, encryptor, evaluator); // client offline phase
	// cout << "[DEBUG] -> Client Offline Finished!" << endl;
	auto end = chrono::high_resolution_clock::now();
	auto offline_time = chrono::duration_cast<chrono::milliseconds>(end - start);
	cout << "Offline: " << (double)offline_time.count() / 1000.0 << " s" << endl;
	start = chrono::high_resolution_clock::now();
	// cout << "[DEBUG] 7. Allocating result array of size " << EmbeddingDim << "..." << endl;
	uint64_t *result = new uint64_t[EmbeddingDim];		  // Can represent 64bit, requires number of bytes / 8
	int num_queries = 1 << (kLogDBSize / 2 + kLogDBSize % 2); // Database size is N, query sqrt(N) times
	// int num_queries=1;
	cout << "Running " << num_queries << " queries" << endl;
	int progress = 0;
	int milestones = num_queries / 5;
	bool boo = true;
	for (uint32_t i = 0; i < num_queries; i++)
	{
		if (i % milestones == 0)
		{
			cout << "Completed: " << progress * 20 << "%" << endl;
			progress++;
		}

		uint16_t part = i % (1 << kLogDBSize / 2);
		uint16_t offset = i % (1 << kLogDBSize / 2);
		uint32_t query = (part << (kLogDBSize / 2)) + offset;											  // query=part*sqrt(N)+offset
		// cout << "[DEBUG] 8. Executing test_client_query for Target Query ID = " << query << "..." << endl;
        test_client_query(client, server, query, result, encoder, encryptor, evaluator); 
        // cout << "[DEBUG] -> test_client_query Finished!" << endl;
        
        // cout << "[DEBUG] 9. Verifying full dimension results..." << endl;
		// std::cout<<DB[i]<<" "<<result[0]<<std::endl;
		bool current_query_correct = true;
		//添加noise的形式
        // for (uint32_t d = 0; d < EmbeddingDim; d++) {
        //     // DB 是一维铺平的数组，通过 query * EmbeddingDim + d 寻址
        //     uint64_t expected_val = DB[query * EmbeddingDim + d];
        //     if (expected_val != result[d]) {
        //         current_query_correct = false;
        //         cout << "[Error] Query " << query << " Dim " << d 
        //              << ": Expected " << expected_val 
        //              << ", Got " << result[d] << endl;
        //         break; // 只要有一维错，这条查询就算错
        //     }
        // }

		//秘密份额形式
		for (uint32_t d = 0; d < EmbeddingDim; d++) {
            uint64_t expected_val = DB[query * EmbeddingDim + d];
            
            // Client Share + Server Share (mod p)
            uint128_t sum_shares = (uint128_t)result[d] + (uint128_t)server.server_share[d];
            uint64_t reconstructed_val = (uint64_t)(sum_shares % plainModulus);
            
            if (expected_val != reconstructed_val) {
                current_query_correct = false;
                cout << "[Error] Query " << query << " Dim " << d 
                     << ": Expected " << expected_val 
                     << ", Got " << reconstructed_val 
                     << " (C_Share: " << result[d] << " + S_Share: " << server.server_share[d] << ")="<<result[d]+server.server_share[d]<< endl;
                break; 
            }
			if (d==0){cout<<"T"<<query<<"[0]="<<result[d]+server.server_share[d]-8589905921<< endl;}
        }
		if (!current_query_correct)
			boo = false;
	}
	// cout << "\n[DEBUG] 10. Loop Finished. Finalizing..." << endl;
	if (boo == true)
		std::cout << "All correct" << std::endl;
	else
		std::cout << "Errors exist" << std::endl;
	end = chrono::high_resolution_clock::now();
	auto total_online_time = chrono::duration_cast<chrono::milliseconds>((end - start));
	double online_time = ((double)total_online_time.count()) / num_queries;

	cout << "Ran " << num_queries << " queries" << endl;
	cout << "Online: " << total_online_time.count() << " ms" << endl;
	cout << "Cost Per Query: " << online_time << " ms" << endl;

	output_csv << num_queries << ", " << (double)offline_time.count() / 1000.0 << ", " << online_time;
	if (is_same<Client, OneSVClient>::value && is_same<Server, OneSVServer>::value)
	{
		double amortized_compute_time_per_query = ((double)offline_time.count()) / (0.5 * LAMBDA * (1 << (kLogDBSize / 2))) + online_time;
		cout << "Amortized compute time per query: " << amortized_compute_time_per_query << " ms" << endl;
		output_csv << ", " << amortized_compute_time_per_query;
	}
	output_csv << endl;
	cout << endl;
}

int main(int argc, char *argv[])
{
	Options options = parse_options(argc, argv);
	if (!options.OneSV)
	{
		std::cerr << "Error: --one-server must be specified" << std::endl;
		return 0;
	}
	// if (options.EntrySize != 8)
	// {
	// 	std::cerr << "Error: EntrySize must be 8, current input is " << options.EntrySize << std::endl;
	// 	return 0;
	// }
	ofstream output_csv;
	// If output file doesn't exist then add the headers
	if (access(options.OutputFile.c_str(), F_OK) == -1)
	{
		output_csv.open(options.OutputFile);
		output_csv << "Variant, Log2 DBSize, EntrySize(Bytes), NumQueries, Offline Time (s), Online Time (ms),  Amortized Compute Time Per Query (ms)" << endl;
	}
	else
	{
		output_csv.open(options.OutputFile, ofstream::out | ofstream::app);
	}
	uint32_t bgvRingSize = 2048;
	uint32_t bgvQSize = 56;			  // Within 56 // lambda becomes 30
	uint32_t bgvPlainModuluSize = 33; // Decryption correct
	EncryptionParameters params(SchemeType::BFV);
	params.set_poly_modulus_degree(bgvRingSize);
	params.set_coeff_modulus(CoeffModulus::create(bgvRingSize, {bgvQSize}));
	params.set_plain_modulus(PlainModulus::batching(bgvRingSize, bgvPlainModuluSize));

	HeContextPointer context = HeContext::create(params, true, SecurityLevel::Nil);
	BatchEncoder encoder(context);
	/*
	context->to_device_inplace();
	encoder.to_device_inplace();*/
	KeyGenerator keygen(context);
	troy::PublicKey public_key = keygen.create_public_key(false);
	Encryptor encryptor(context);
	encryptor.set_public_key(public_key);
	Evaluator evaluator(context);
	uint64_t plainModulus = params.plain_modulus()->value();
	// cout<<"p:"<<plainModulus<<endl;
	if (options.OneSV)
	{
		test_pir<OneSVClient, OneSVServer>(options.Log2DBSize, options.EntrySize, output_csv, encoder, encryptor, evaluator, bgvRingSize, keygen, context, plainModulus); // Important
	}
	output_csv.close();
	//utils::MemoryPool::Destroy();
}