#include <iostream>
#include <vector>
#include <thread>
#include <future>
#include <fstream>
#include <unordered_map>
#include <typeindex>
#include <type_traits>

#include <sodium.h>

#include "pfp-cpp/pfplog/pfplog.hpp"
#include "pfp-cpp/pfplog/dbgstr.hpp"
#include "pfp-cpp/stdpfp/xint.hpp"

template<class T, typename hash_init, typename hash_update, typename hash_final, typename hash_verify>
class crypto_tester {
private:
	std::string m_filename;
	size_t m_filesize;
public:
	crypto_tester();
	crypto_tester(const std::string & file_name, hash_init hi, hash_update hu, hash_final hf, hash_verify hv) : m_filename(file_name) {
		if (sodium_init() == -1) {
			pfp_throw_error_runtime_oss("Sodium failed");
		};

		std::ifstream m_ifs(m_filename, std::ifstream::out | std::ifstream::binary);
		T m_state;
		size_t m_cpus = std::thread::hardware_concurrency();

		if (m_ifs.is_open()) { // get the file size
			m_ifs.seekg(0, m_ifs.end);
			m_filesize = m_ifs.tellg();
			pfp_fact("seek end , file size : " << m_filesize);
			m_ifs.seekg(0, m_ifs.beg);
			if (m_filesize <= 0) {
				pfp_throw_error_runtime_oss("File size is 0");
			}
		} else {
			pfp_throw_error_runtime_oss("File not open");
		}

		// sha256
		if constexpr (std::is_same<T, crypto_hash_sha256_state>::value) {
			hi(&m_state);
		}

		// sha512
		if constexpr (std::is_same<T, crypto_hash_sha512_state>::value) {
			hi(&m_state);
		}

		// ed25519
		if constexpr (std::is_same<T, crypto_sign_ed25519ph_state>::value) {
			hi(&m_state);
		}

		// blake2b
		unsigned char hash[crypto_generichash_blake2b_bytes()];
		if constexpr (std::is_same<T, crypto_generichash_blake2b_state>::value) {
			unsigned char key[crypto_generichash_blake2b_keybytes()];
			randombytes_buf(&key, sizeof(key));
			hi(&m_state, key, sizeof(key), sizeof(hash));
		}

		using Task_type = void(std::ifstream &, T *, hash_update);
		std::vector<std::unique_ptr<std::packaged_task<Task_type>>> vector_packed_tasks;
		std::vector<std::unique_ptr<std::future<void>>> vector_futures;
		std::vector<std::thread> vector_threads;

		for (size_t index = 0; index < m_cpus; index++) {
			vector_packed_tasks.push_back(std::make_unique<std::packaged_task<Task_type>>(wrapper_new));
		}

		for (size_t index = 0; index < m_cpus; index++) {
			vector_futures.push_back(std::make_unique<std::future<void>>(vector_packed_tasks.at(index).get()->get_future()));
		}

		for (size_t index = 0; index < m_cpus; index++) {
			try {

				std::thread t ([&m_ifs, index, &vector_packed_tasks, &m_state, &hu](){
					{
						size_t no_task = index;
						pfp_fact("Run thread #" << index << " on CPU #" << sched_getcpu() << " , typeid(state).name = " << typeid(m_state).name());
						std::packaged_task<Task_type> *pt = vector_packed_tasks.at(no_task).get();
						(*pt)(m_ifs, &m_state, hu);
					}
				});
				std::thread::native_handle_type nht = t.native_handle();
				int pthread_rc = -1;
				cpu_set_t cpuset;
				CPU_ZERO(&cpuset);
				CPU_SET(index, &cpuset);
				pthread_rc = pthread_setaffinity_np(nht, sizeof(cpu_set_t), &cpuset); // pin to cpuX
				if (pthread_rc != 0) {
					pfp_fact("Failed to pin cpu" << index << ": " << std::strerror(errno));
				} else {
					pfp_fact("pin cpu" << index << " to thread 0x" << std::hex << t.get_id());
				}
				if (t.joinable()) { // in good order
					pfp_fact("Join thread id : " << "0x" << std::hex << t.get_id());
					t.join();
				}
				vector_threads.push_back(std::move(t));
			} catch(std::exception & e) {
				pfp_throw_error_runtime_oss("Exception : " << e.what());
			}
		}

		for (size_t index = 0; index < m_cpus; index++) {
			if (vector_threads.at(index).joinable()) {
				pfp_fact("Join thread id : " << "0x" << std::hex << vector_threads.at(index).get_id());
				vector_threads.at(index).join();
			}
		}

		if constexpr (std::is_same_v<T, crypto_hash_sha256_state>) {
			std::unique_ptr<unsigned char[]> buffer(new unsigned char[sizeof(m_state.state)]);
			hf(&m_state, buffer.get());
			pfp_fact("Hash sha256 : " << n_pfp::dbgstr_hex(buffer.get(), sizeof(m_state.state)));
		}

		if constexpr (std::is_same_v<T, crypto_hash_sha512_state>) {
			std::unique_ptr<unsigned char[]> buffer(new unsigned char[sizeof(m_state.state)]);
			hf(&m_state, buffer.get());
			pfp_fact("Hash sha512 : " << n_pfp::dbgstr_hex(buffer.get(), sizeof(m_state.state)));
		}

		if constexpr (std::is_same_v<T, crypto_sign_ed25519ph_state>) {
			unsigned char pk[crypto_sign_PUBLICKEYBYTES];
			unsigned char sk[crypto_sign_SECRETKEYBYTES];
			crypto_sign_ed25519_keypair(pk, sk);
			std::unique_ptr<unsigned char[]> buffer(new unsigned char[crypto_sign_BYTES]);
			hf(&m_state, buffer.get(), NULL, sk);
			pfp_fact("Hash ed25519 : " << n_pfp::dbgstr_hex(buffer.get(), sizeof(m_state.hs.state)));
			if (hv(&m_state, buffer.get(), pk) == 0) {
				pfp_fact("Hash ed25519 ok");
			} else {
				pfp_fact("Hash ed25519 failed");
			}
		}

		if constexpr (std::is_same_v<T, crypto_generichash_blake2b_state>) {
			unsigned char hash[crypto_generichash_blake2b_bytes()];
			hf(&m_state, hash, sizeof(hash));
			pfp_fact("Hash blake2b : " << n_pfp::dbgstr_hex(hash, sizeof(hash)));
		}
	}

private:
	static void wrapper_old(std::ifstream & random_input_file, size_t offset_in_file, size_t piece_of_file, T *state, size_t num_c, hash_update hu) {
		std::thread::id ct = std::this_thread::get_id();
		pfp_fact("Run thread 0x" << std::hex << ct << " on CPU #" << sched_getcpu() << " , offset_in_file = " << std::dec << offset_in_file << " , piece_of_file = " << std::dec << piece_of_file);
		{
			const size_t const_number_concurenncy = num_c;
			size_t buffer_size = const_number_concurenncy * 1024 * 1024;
			std::unique_ptr<char[]> buffer(new char[buffer_size]); // TODO std::vector<char> buffer(buffer_size, 0);
			size_t end_offset = offset_in_file + piece_of_file;
			random_input_file.seekg(offset_in_file, random_input_file.beg);
			while (offset_in_file < end_offset) {
				random_input_file.seekg(offset_in_file, random_input_file.beg); // TODO .cur ?
				random_input_file.read(buffer.get(), buffer_size);
				if (random_input_file) {
					hu(state, reinterpret_cast<const unsigned char *>(buffer.get()), reinterpret_cast<long unsigned int>(buffer_size));
					offset_in_file += buffer_size;
				} else {
					pfp_fact("Only " << random_input_file.gcount() << " bytes readed");
					break;
				}
			}
		}
	}
	static void wrapper_new(std::ifstream & random_input_file, T *state, hash_update hu) {
		std::thread::id ct = std::this_thread::get_id();
		size_t m_cpus = std::thread::hardware_concurrency();
		pfp_fact("Run thread 0x" << std::hex << ct << " on CPU #" << std::dec << sched_getcpu() << " , typeid().name = " << typeid(T).name());
		{
			size_t buffer_size = m_cpus * 1024 * 1024;
			size_t offset_in_file = 0;
			std::unique_ptr<char[]> buffer(new char[buffer_size]); // TODO std::vector<char> buffer(buffer_size, 0);
			random_input_file.seekg(0, random_input_file.beg);
			while (offset_in_file < random_input_file.tellg()) {
				pfp_fact("of : " << offset_in_file << " , " << "fs : " << random_input_file.tellg());
				random_input_file.seekg(offset_in_file, random_input_file.beg); // TODO .cur ?
				random_input_file.read(buffer.get(), buffer_size);
				if (random_input_file) {
					hu(state, reinterpret_cast<const unsigned char *>(buffer.get()), reinterpret_cast<long unsigned int>(buffer_size));
					offset_in_file += buffer_size;
				} else {
					pfp_fact("Only " << random_input_file.gcount() << " bytes readed");
					break;
				}
			}
		}
	}
};

int main(int argc, char *argv[])
{
	typedef int (*hi256)(crypto_hash_sha256_state *);
	typedef int (*hu256)(crypto_hash_sha256_state *, const unsigned char *, unsigned long long);
	typedef int (*hf256)(crypto_hash_sha256_state *, unsigned char *);
	typedef int (*null_verify_sha256)(crypto_hash_sha256_state *);
	typedef int (*hi512)(crypto_hash_sha512_state *);
	typedef int (*hu512)(crypto_hash_sha512_state *, const unsigned char *, unsigned long long);
	typedef int (*hf512)(crypto_hash_sha512_state *, unsigned char *);
	typedef int (*null_verify_sha512)(crypto_hash_sha512_state *);
	typedef int (*sed25519i)(crypto_sign_ed25519ph_state *);
	typedef int (*sed25519u)(crypto_sign_ed25519ph_state *, const unsigned char *, unsigned long long);
	typedef int (*sed25519fc)(crypto_sign_ed25519ph_state *, unsigned char *, unsigned long long *, const unsigned char *);
	typedef int (*sed25519fv)(crypto_sign_ed25519ph_state *, const unsigned char *, const unsigned char *);
	typedef int (*b2bi)(crypto_generichash_blake2b_state *, const unsigned char *, const size_t, const size_t);
	typedef int (*b2bu)(crypto_generichash_blake2b_state *, const unsigned char *, unsigned long long);
	typedef int (*b2bf)(crypto_generichash_blake2b_state *, unsigned char *, const size_t);
	typedef int (*null_verify_blake2b)(crypto_generichash_blake2b_state *);

	crypto_tester<crypto_hash_sha256_state, hi256, hu256, hf256, null_verify_sha256> crypto_tester_256_1("rndfile_1g", crypto_hash_sha256_init, crypto_hash_sha256_update, crypto_hash_sha256_final, nullptr);
	crypto_tester<crypto_hash_sha512_state, hi512, hu512, hf512, null_verify_sha512> crypto_tester_512_1("rndfile_1g", crypto_hash_sha512_init, crypto_hash_sha512_update, crypto_hash_sha512_final, nullptr);
	crypto_tester<crypto_sign_ed25519ph_state, sed25519i, sed25519u, sed25519fc, sed25519fv> crypto_tester_ed25519_1("rndfile_1g", crypto_sign_ed25519ph_init, crypto_sign_ed25519ph_update, crypto_sign_ed25519ph_final_create, crypto_sign_ed25519ph_final_verify);
	crypto_tester<crypto_generichash_blake2b_state, b2bi, b2bu, b2bf, null_verify_blake2b> crypto_tester_blake2b_1("rndfile_1g", crypto_generichash_blake2b_init, crypto_generichash_blake2b_update, crypto_generichash_blake2b_final, nullptr);

	return 0;
}
