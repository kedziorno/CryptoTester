#include <iostream>
#include <string>
#include <string.h>
#include <fstream>
#include <memory>
#include <chrono>
#include <vector>
#include <sstream>

#include <sodium.h>

template<typename T>
std::string bin2hex(void * data, size_t size) {
	T *d = reinterpret_cast<T*>(data);
	const char hex[] = "0123456789ABCDEF";
	std::ostringstream oss;
	for (size_t index = 0; index < size; index++) {
		if (hex[d[index] >> 4] == 0) {
			oss << "0";
		} else {
			oss << hex[d[index] >> 4];
		}
		if (hex[d[index] & 0x0f] == 0) {
			oss << "0";
		} else {
			oss << hex[d[index] & 0x0f];
		}
		oss << " ";
	}
	return oss.str();
}

int main(int argc, char *argv[]) {
	if (sodium_init() == -1) {
		std::cout << "sodium_init == -1" << std::endl;
		exit(1);
	}

	std::string file_name = argv[1];
	int number_tests = std::atoi(argv[2]);
	std::string csv_file;
	bool use_csv = false;
	if (argv[3] != nullptr) {
		csv_file.append(std::string(argv[3], strlen(argv[3])));
		std::cout << "output to CSV file " << csv_file << std::endl;
		use_csv = true;
	} else {
		std::cout << "CSV not used" << std::endl;
	}

	std::ifstream random_input_file(file_name, std::ifstream::in | std::ifstream::binary);
	random_input_file.seekg(0,random_input_file.end);
	size_t file_size = random_input_file.tellg();
	random_input_file.seekg(0,random_input_file.beg);
	std::cout << file_name << " have size " << file_size << " bytes" << std::endl;
	std::unique_ptr<unsigned char[]> file_buffer(new unsigned char[file_size]); // XXX 4gb - throw bad_alloc
	if (random_input_file) {
		random_input_file.read(reinterpret_cast<char *>(file_buffer.get()), file_size);
		random_input_file.close();
	} else {
		std::cout << "Error on read, maybe file " << file_name << " dont exists" << std::endl;
		exit(2);
	}

	std::ofstream csv_output_file;
	if (use_csv == true) {
		csv_output_file.open(csv_file, std::ofstream::out);
		if (!csv_output_file.is_open()) {
			std::cout << "Error on open CSV file " << csv_file << std::endl;
		}
	}

	// for ed25519 we have constant keys - only for tests
	unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES] = { 0x90,0xca,0xf3,0x48,0x28,0xf5,0x5a,0x5f,0x1e,0x54,0x2a,0x1e,0x1d,0x4f,0xbb,0xb2,0x99,0x19,0x75,0x73,0xa1,0x24,0xe0,0x52,0x01,0xb7,0x67,0xcf,0x2e,0x3c,0x5d,0x42,0xa6,0xfa,0x14,0x46,0xba,0xc6,0xbf,0xbc,0x28,0x4b,0x63,0x2d,0x92,0x11,0x10,0xfb,0x8c,0x37,0xdd,0xe3,0xf7,0x42,0xfe,0xd1,0x12,0x03,0x1f,0xc4,0xd0,0x26,0x1e,0xc6 };
	unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
//	crypto_sign_ed25519_sk_to_pk(pk, sk);
	std::array<unsigned char, crypto_sign_ed25519_SEEDBYTES> seed;
	seed.fill({0});
	crypto_sign_ed25519_sk_to_seed(seed.data(), sk);
	crypto_sign_ed25519_seed_keypair(pk, sk, seed.data());
	// we dont see pk and sk
	//pfp_fact("sk : " << n_pfp::dbgstr_hex(sk, crypto_sign_ed25519_SECRETKEYBYTES));
	//pfp_fact("pk : " << n_pfp::dbgstr_hex(pk, crypto_sign_ed25519_PUBLICKEYBYTES));

	// for blake2b we have constant key - only for tests
	unsigned char key[crypto_generichash_blake2b_keybytes()] = { 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2 };
	//randombytes_buf(key, sizeof(key));


	#define NO_HASHES 5
	enum hashes {
		sha256,
		sha512,
		blake2b,
		ed25519_final,
		ed25519_verify
	};

	std::chrono::system_clock::time_point begin, end;
	std::vector<std::vector<size_t>> report;
	report.resize(NO_HASHES);

	report.at(hashes::sha256);
	report.at(hashes::sha512);
	report.at(hashes::blake2b);
	report.at(hashes::ed25519_final);
	report.at(hashes::ed25519_verify);

	for (size_t index = 0; index < number_tests; index++) {
		// sha256
		{
			std::unique_ptr<unsigned char[]> buffer1(new unsigned char[crypto_hash_sha256_bytes()]);
			begin = std::chrono::system_clock::now();
			crypto_hash_sha256_state state;
			crypto_hash_sha256_init(&state);
			crypto_hash_sha256_update(&state, file_buffer.get(), file_size);
			crypto_hash_sha256_final(&state, buffer1.get());
			end = std::chrono::system_clock::now();
			std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
			//std::cout << "sha256 Time : " << ms.count() << " ms" << std::endl;
			//std::cout << "sha256 : " << bin2hex<unsigned char>(buffer1.get(), crypto_hash_sha256_bytes()) << std::endl;
			report.at(hashes::sha256).push_back(ms.count());
		}
	}

	for (size_t index = 0; index < number_tests; index++) {
		// sha512
		{
			std::unique_ptr<unsigned char[]> buffer1(new unsigned char[crypto_hash_sha512_bytes()]);
			begin = std::chrono::system_clock::now();
			crypto_hash_sha512_state state;
			crypto_hash_sha512_init(&state);
			crypto_hash_sha512_update(&state, file_buffer.get(), file_size);
			crypto_hash_sha512_final(&state, buffer1.get());
			end = std::chrono::system_clock::now();
			std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
			//std::cout << "sha512 Time : " << ms.count() << " ms" << std::endl;
			//std::cout << "sha512 : " << bin2hex<unsigned char>(buffer1.get(), crypto_hash_sha512_bytes()) << std::endl;
			report.at(hashes::sha512).push_back(ms.count());
		}
	}

	for (size_t index = 0; index < number_tests; index++) {
		// blake2b
		{
			std::unique_ptr<unsigned char[]> buffer1(new unsigned char[crypto_generichash_blake2b_bytes()]);
			begin = std::chrono::system_clock::now();
			crypto_generichash_blake2b_state state;
			crypto_generichash_blake2b_init(&state, key, sizeof(key), crypto_generichash_blake2b_bytes());
			crypto_generichash_blake2b_update(&state, file_buffer.get(), file_size);
			crypto_generichash_blake2b_final(&state, buffer1.get(), crypto_generichash_blake2b_bytes());
			end = std::chrono::system_clock::now();
			std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
			//std::cout << "blake2b Time : " << ms.count() << " ms" << std::endl;
			//std::cout << "blake2b : " << bin2hex<unsigned char>(buffer1.get(), crypto_generichash_blake2b_bytes()) << std::endl;
			report.at(hashes::blake2b).push_back(ms.count());
		}
	}

	{
		std::array<unsigned char, crypto_sign_ed25519_BYTES> ed25519_signature;
		ed25519_signature.fill({0});
		crypto_sign_ed25519ph_state state_c, state_f;

		for (size_t index = 0; index < number_tests; index++) {
			// ed25519 create
			{
				std::chrono::milliseconds ms;
				// create sign ed25519
				begin = std::chrono::system_clock::now();
				crypto_sign_ed25519ph_init(&state_c);
				crypto_sign_ed25519ph_update(&state_c, file_buffer.get(), file_size);
				crypto_sign_ed25519ph_final_create(&state_c, ed25519_signature.data(), NULL, sk);
				end = std::chrono::system_clock::now();
				ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
				//std::cout << "ed25519 final create Time : " << ms.count() << " ms" << std::endl;
				//std::cout << "ed25519 : " << bin2hex<unsigned char>(ed25519_signature.data(), ed25519_signature.size()) << std::endl;
				report.at(hashes::ed25519_final).push_back(ms.count());
			}
		}

		for (size_t index = 0; index < number_tests; index++) {
			// ed25519 verify
			{
				std::chrono::milliseconds ms;
				// verify sign ed25519
				begin = std::chrono::system_clock::now();
				crypto_sign_ed25519ph_init(&state_f);
				crypto_sign_ed25519ph_update(&state_f, file_buffer.get(), file_size);
				int status = crypto_sign_ed25519ph_final_verify(&state_f, ed25519_signature.data(), pk);
				end = std::chrono::system_clock::now();
				ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);
				report.at(hashes::ed25519_verify).push_back(ms.count());
				//std::cout << "ed25519 final verify Time : " << ms.count() << " ms" << std::endl;
				//std::cout << "ed25519 : " << bin2hex<unsigned char>(ed25519_signature.data(), ed25519_signature.size()) << std::endl;
				if (status != 0) {
					//std::cout << "ed25519 message forged!" << std::endl;
				} else {
					//std::cout << "ed25519 message good sign!" << std::endl;
				}
			}
		}
	}

	// calculate
	if (use_csv == true) {
		csv_output_file << "sha256,sha512,blake2b,ed25519_final,ed25519_verify" << std::endl;
	}
	std::cout << "file : " << file_name << " , " << "number tests : " << number_tests << std::endl;

	size_t t_sha256 {0};
	size_t t_sha512 {0};
	size_t t_blake2b {0};
	size_t t_ed25519_f {0};
	size_t t_ed25519_v {0};
	for (size_t index = 0; index < number_tests; index++) {
		t_sha256 += report.at(hashes::sha256).at(index);
		t_sha512 += report.at(hashes::sha512).at(index);
		t_blake2b += report.at(hashes::blake2b).at(index);
		t_ed25519_f += report.at(hashes::ed25519_final).at(index);
		t_ed25519_v += report.at(hashes::ed25519_verify).at(index);
		if (use_csv == true) {
			std::ostringstream oss_record;
			oss_record << report.at(hashes::sha256).at(index) << "," << report.at(hashes::sha512).at(index) << "," << report.at(hashes::blake2b).at(index) << "," << report.at(hashes::ed25519_final).at(index) << "," << report.at(hashes::ed25519_verify).at(index) << std::endl;
			std::string record(oss_record.str());
			csv_output_file.write(record.data(),record.size());
		}
	}
	std::cout << "avg time sha256         : " << t_sha256 / number_tests << " ms" << std::endl;
	std::cout << "avg time sha512         : " << t_sha512 / number_tests << " ms" << std::endl;
	std::cout << "avg time blake2b        : " << t_blake2b / number_tests << " ms" << std::endl;
	std::cout << "avg time ed25519_final  : " << t_ed25519_f / number_tests << " ms" << std::endl;
	std::cout << "avg time ed25519_verify : " << t_ed25519_v / number_tests << " ms" << std::endl;
	if (use_csv == true) {
		csv_output_file.close();
	}
}
