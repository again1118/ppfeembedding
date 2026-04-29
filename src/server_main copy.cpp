#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include "server.h"
#include "utils.h"
#include "network.h"
#include "troy.h"

// OT persistent connection support
#include "libOTe/Base/SimplestOT.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "coproto/Socket/AsioSocket.h"

using namespace std;
using namespace troy;

uint64_t *DB;

struct ServerOptions
{
    uint64_t Log2DBSize;
    uint64_t EntrySize;
    int Port;
};

void print_usage()
{
    cout << "Usage:" << endl
         << "\t./PPFE_server <Log2 DB Size> <Entry Size> <Port>" << endl
         << "Description:" << endl
         << "\tLog2 DB Size: Logarithm of database size" << endl
         << "\tEntry Size: Number of bytes per entry" << endl
         << "\tPort: Server listening port" << endl;
}

ServerOptions parse_options(int argc, char *argv[])
{
    ServerOptions options{0, 0, 0};

    try
    {
        if (argc == 4)
        {
            options.Log2DBSize = stoi(argv[1]);
            options.EntrySize = stoi(argv[2]);
            options.Port = stoi(argv[3]);
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

namespace osuCrypto
{
#ifdef COPROTO_ENABLE_BOOST
    struct SimplestOTServerSession
    {
        PRNG prng;
        SimplestOT otSender;
        cp::AsioSocket sock;

        explicit SimplestOTServerSession(const std::string &listen_ip)
            : prng(sysRandomSeed()), sock(cp::asioConnect(listen_ip, true))
        {
        }

        void sendOne(uint64_t msg0, uint64_t msg1)
        {
            const int totalOTs = 1;
            AlignedVector<std::array<block, 2>> msgPairs(totalOTs);
            msgPairs[0][0] = block(msg0);
            msgPairs[0][1] = block(msg1);

            coproto::sync_wait(otSender.sendChosen(
                span<std::array<block, 2>>(msgPairs.data(), msgPairs.size()),
                prng,
                sock));

            cp::sync_wait(sock.flush());
        }
        void sendVector(const uint64_t* msg0, const uint64_t* msg1, size_t length, int plainSocket)
        {
            // 1. 生成两把 128 位的随机钥匙 (Seed)
            block seed0 = prng.get<block>();
            block seed1 = prng.get<block>();

            // 2. 通过纯正的 OT 协议，把这两把钥匙发出去
            AlignedVector<std::array<block, 2>> msgPairs(1);
            msgPairs[0][0] = seed0;
            msgPairs[0][1] = seed1;
            coproto::sync_wait(otSender.sendChosen(
                span<std::array<block, 2>>(msgPairs.data(), 1), prng, sock));
            cp::sync_wait(sock.flush());

            // 3. 用这两把钥匙作为流密码，把 2048 维数组加密成乱码
            PRNG prng0(seed0);
            PRNG prng1(seed1);
            std::vector<uint64_t> cipher0(length), cipher1(length);
            for(size_t i = 0; i < length; i++) {
                cipher0[i] = msg0[i] ^ prng0.get<uint64_t>(); // 异或加密
                cipher1[i] = msg1[i] ^ prng1.get<uint64_t>();
            }

            // 4. 把两个加密后的箱子，通过普通的 Socket 网络全扔给客户端
            NetworkHelper::sendUint64Array(plainSocket, cipher0.data(), length);
            NetworkHelper::sendUint64Array(plainSocket, cipher1.data(), length);
        }
    };
#else
    struct SimplestOTServerSession
    {
        explicit SimplestOTServerSession(const std::string &)
        {
            throw std::runtime_error("Error: COPROTO Boost support must be enabled! Please add -DCOPROTO_ENABLE_BOOST=ON when compiling libOTe");
        }
        void sendOne(uint64_t, uint64_t) {}
    };
#endif
}

int main(int argc, char *argv[])
{
    ServerOptions options = parse_options(argc, argv);

    // if (options.EntrySize != 8)
    // {
    //     cerr << "Error: EntrySize must be 8, current input is " << options.EntrySize << endl;
    //     return 1;
    // }

    cout << "========== PPFE Server ==========" << endl;
    cout << "Database Size (Log2): " << options.Log2DBSize << endl;
    cout << "Entry Size: " << options.EntrySize << " bytes" << endl;
    cout << "Listening Port: " << options.Port << endl;
    cout << "=================================" << endl;

    // Set encryption parameters
    // uint32_t PartSize = 1 << (options.Log2DBSize / 2 + options.Log2DBSize % 2);
    uint32_t PartSize = 1 << (options.Log2DBSize / 2 + options.Log2DBSize % 2);

    // Select appropriate bgvRingSize based on PartSize (must be a power of 2 and >= PartSize)
    uint32_t bgvRingSize = 2048;
    if (PartSize > 2048)
    {
        bgvRingSize = 4096;
    }
    if (PartSize > 4096)
    {
        bgvRingSize = 8192;
    }

    while (bgvRingSize < PartSize && bgvRingSize < 32768)
    {
        bgvRingSize *= 2;
    }

    if (bgvRingSize < PartSize)
    {
        cerr << "[Error] PartSize (" << PartSize << ") exceeds maximum supported bgvRingSize (32768)" << endl;
        cerr << "[Error] Please decrease the Log2DBSize parameter" << endl;
        return 1;
    }

    cout << "[Server] PartSize=" << PartSize << ", bgvRingSize=" << bgvRingSize << endl;
    uint32_t bgvQSize = 54;
    uint32_t bgvPlainModuluSize = 20;

    EncryptionParameters params(SchemeType::BFV);
    params.set_poly_modulus_degree(bgvRingSize);
    params.set_coeff_modulus(CoeffModulus::create(bgvRingSize, {bgvQSize}));
    params.set_plain_modulus(PlainModulus::batching(bgvRingSize, bgvPlainModuluSize));
    HeContextPointer context = HeContext::create(params, true, SecurityLevel::Classical128);

    KeyGenerator keygen(context);
    troy::PublicKey public_key = keygen.create_public_key(false);

    BatchEncoder encoder(context);
    Encryptor encryptor(context);
    encryptor.set_public_key(public_key);

    uint64_t plainModulus = params.plain_modulus()->value();

    // Initialize database (plainModulus is now known)
    cout << "[Server] Initializing database..." << endl;
    initDatabase(&DB, options.Log2DBSize, options.EntrySize, plainModulus);
    cout << "[Server] Database initialization complete" << endl;

    // Create server object
    OneSVServer server(DB, options.Log2DBSize, options.EntrySize, context, keygen, plainModulus);

    // Preprocess database
    cout << "[Server] Preprocessing database (encrypting)..." << endl;
    auto offline_encrypt_start = chrono::high_resolution_clock::now();
    server.preprocessDatabase(encoder, encryptor);
    auto offline_encrypt_end = chrono::high_resolution_clock::now();
    auto offline_encrypt_time = chrono::duration_cast<chrono::milliseconds>(offline_encrypt_end - offline_encrypt_start);
    cout << "[Server] Database preprocessing complete" << endl;
    cout << "[Server] Offline encryption time: " << offline_encrypt_time.count() << " ms" << endl;

    // Start network service
    ServerNetwork network(options.Port);
    if (!network.start())
    {
        cerr << "[Server] Start failed" << endl;
        return 1;
    }

    // Calculate parameters
    uint32_t PartNum = 1 << (options.Log2DBSize / 2);
    PartSize = 1 << (options.Log2DBSize / 2 + options.Log2DBSize % 2);
    uint32_t B = options.EntrySize / 8;

    cout << "[Server] Waiting for client connection..." << endl;

    // Accept client connection
    int clientSocket = network.acceptClient();
    if (clientSocket < 0)
    {
        cerr << "[Server] Failed to accept client connection" << endl;
        return 1;
    }
    // cout << "[Server] plainModulus"<< plainModulus << endl;
    // Send server parameters to client
    cout << "[Server] Sending configuration parameters..." << endl;
    NetworkHelper::sendData(clientSocket, &options.Log2DBSize, sizeof(options.Log2DBSize));
    NetworkHelper::sendData(clientSocket, &options.EntrySize, sizeof(options.EntrySize));
    NetworkHelper::sendData(clientSocket, &plainModulus, sizeof(plainModulus));

    // Send encryption parameters
    cout << "[Server] Sending encryption parameters..." << endl;
    NetworkHelper::sendData(clientSocket, &bgvRingSize, sizeof(bgvRingSize));
    NetworkHelper::sendData(clientSocket, &bgvQSize, sizeof(bgvQSize));
    NetworkHelper::sendData(clientSocket, &bgvPlainModuluSize, sizeof(bgvPlainModuluSize));

    // Send public key
    cout << "[Server] Sending public key..." << endl;
    if (!NetworkHelper::sendPublicKey(clientSocket, public_key, context))
    {
        cerr << "[Server] Failed to send public key" << endl;
        network.closeClient(clientSocket);
        return 1;
    }

    // Send encrypted database to client (for Offline phase)
    cout << "[Server] Sending encrypted database (" << server.encryptedDB.size() << " ciphertexts)..." << endl;
    if (!NetworkHelper::sendCiphertextVector(clientSocket, server.encryptedDB, context))
    {
        cerr << "[Server] Failed to send encrypted database" << endl;
        network.closeClient(clientSocket);
        return 1;
    }
    cout << "[Server] Encrypted database sending complete" << endl;

    // ==================== OT persistent connection: one accept, multiple OTs ====================
    // Important: OT connection must be established after Offline phase main connection communication is complete to avoid blocking each other.
    cout << "[Server] Waiting for client to establish OT connection (8081)..." << endl;
    osuCrypto::SimplestOTServerSession otSession("0.0.0.0:8081");
    cout << "[Server] OT connection established" << endl;

    // Reset communication stats, preparing for online phase stats
    NetworkHelper::resetStats();
    cout << "[Server] Reset communication stats, starting online phase" << endl;

    // Process queries
    cout << "[Server] Preparing to process queries..." << endl;

    bool *bvec = new bool[PartNum];
    unsigned char *bvec_bytes = new unsigned char[PartNum]; // Used for network reception
    uint32_t *Svec = new uint32_t[PartNum];
    uint64_t *Response_b0 = new uint64_t[B];
    uint64_t *Response_b1 = new uint64_t[B];

    int queryCount = 0;

    while (true)
    {
        // Receive query type
        uint8_t queryType;
        if (!NetworkHelper::recvData(clientSocket, &queryType, sizeof(queryType)))
        {
            cout << "[Server] Client disconnected" << endl;
            break;
        }

        if (queryType == 0xFF)
        { // Client sends end signal
            cout << "[Server] Received end signal" << endl;
            break;
        }

        if (queryType == 0x02)
        { // Batch query mode
            // Receive batch queries.
            // Variables received include:
            // - batchQueries: vector<BatchQuery> - Batch query data, each BatchQuery contains:
            //   * bvec: vector<bool> - Query bit vector, indicating database indices to query
            //   * Svec: vector<uint32_t> - Offset vector, used to determine query position in database
            //   * ciphertext: troy::Ciphertext - Encrypted query ciphertext, containing homomorphically encrypted query info
            vector<NetworkHelper::BatchQuery> batchQueries;
            uint32_t batchSize;
            if (!NetworkHelper::recvBatchQueries(clientSocket, batchQueries, batchSize, PartNum, context))
            {
                cerr << "[Server] Failed to receive batch queries" << endl;
                break;
            }

            // Process all batch queries
            auto online_server_compute_start = chrono::high_resolution_clock::now();
            vector<NetworkHelper::BatchResponse> batchResponses(batchSize);
            for (uint32_t i = 0; i < batchSize; i++)
            {
                batchResponses[i].Response_b0.resize(B);
                batchResponses[i].Response_b1.resize(B);

                // std::vector<bool> does not support .data(), need to convert to bool array
                std::vector<bool> bvec_bool(PartNum);
                for (uint32_t j = 0; j < PartNum; j++)
                {
                    bvec_bool[j] = batchQueries[i].bvec[j];
                }
                // Convert back to actual bool array (not vector<bool>)
                bool *bvec_array = new bool[PartNum];
                for (uint32_t j = 0; j < PartNum; j++)
                {
                    bvec_array[j] = bvec_bool[j];
                }
                server.onlineQuery(bvec_array, batchQueries[i].Svec.data(),
                                   batchResponses[i].Response_b0.data(),
                                   batchResponses[i].Response_b1.data(),
                                   batchQueries[i].ciphertext, encoder);

                // Send b0/b1 via OT persistent connection (one connection, multiple OTs)
                // Note: b0/b1 here are uint64 in ciphertext modulus q domain (output after scaling/removal/noise addition in server.cpp)
                // otSession.sendOne(batchResponses[i].Response_b0[0], batchResponses[i].Response_b1[0]);
                otSession.sendVector(batchResponses[i].Response_b0.data(), 
                     batchResponses[i].Response_b1.data(), 
                     B, clientSocket);
                // ==================== 【新增：网络发送 S_share】 ====================
                // 1. 发送服务端份额的密文盲盒 (用于后续状态机融合)
                troy::Ciphertext ci_s_share;
                NetworkHelper::sendCiphertext(clientSocket, ci_s_share, context);
                // 2. 发送明文 server_share 后门 (仅作我们在本地终端校验 All correct 使用)
                NetworkHelper::sendUint64Array(clientSocket, server.server_share.data(), B);
                // ====================================================================
                delete[] bvec_array; // Free memory
            }
            auto online_server_compute_end = chrono::high_resolution_clock::now();
            auto online_server_compute_time = chrono::duration_cast<chrono::microseconds>(online_server_compute_end - online_server_compute_start);
            // cout << "[Server] Online server compute time: " << online_server_compute_time.count() / 1000.0 << " ms (batch " << batchSize << " )" << endl;

            // Send batch responses
            // Variables sent include:
            // - batchResponses: vector<BatchResponse> - Batch response data, each BatchResponse contains:
            //   * Response_b0: vector<uint64_t> - First part of query result (result when b=0)
            //   * Response_b1: vector<uint64_t> - Second part of query result (result when b=1)
            //   These responses are results calculated by server based on query parameters and encrypted database
            queryCount += batchSize;
            // cout << "[Server] Processed batch queries: " << batchSize << " , total: " << queryCount << endl;
        }
        else
        { // Single query mode (queryType == 0x01)
            // Receive query parameters
            if (!NetworkHelper::recvBoolArray(clientSocket, bvec_bytes, PartNum))
            {
                cerr << "[Server] Failed to receive bvec" << endl;
                break;
            }

            // Convert unsigned char to bool
            for (uint32_t i = 0; i < PartNum; i++)
            {
                bvec[i] = bvec_bytes[i];
            }

            if (!NetworkHelper::recvUint32Array(clientSocket, Svec, PartNum))
            {
                cerr << "[Server] Failed to receive Svec" << endl;
                break;
            }

            Ciphertext queryCiphertext;
            if (!NetworkHelper::recvCiphertext(clientSocket, queryCiphertext, context))
            {
                cerr << "[Server] Failed to receive Ciphertext" << endl;
                break;
            }

            // Process query
            server.onlineQuery(bvec, Svec, Response_b0, Response_b1, queryCiphertext, encoder);

            // Send response
            if (!NetworkHelper::sendUint64Array(clientSocket, Response_b0, B))
            {
                cerr << "[Server] Failed to send Response_b0" << endl;
                break;
            }

            if (!NetworkHelper::sendUint64Array(clientSocket, Response_b1, B))
            {
                cerr << "[Server] Failed to send Response_b1" << endl;
                break;
            }

            queryCount++;
            if (queryCount % 100 == 0)
            {
                cout << "[Server] Processed " << queryCount << " queries" << endl;
            }
        }
    }

    cout << "[Server] Total queries processed: " << queryCount << endl;

    // Cleanup
    delete[] bvec;
    delete[] bvec_bytes;
    delete[] Svec;
    delete[] Response_b0;
    delete[] Response_b1;

    network.closeClient(clientSocket);
    network.stop();

    cout << "[Server] Server shutdown" << endl;

    return 0;
}
