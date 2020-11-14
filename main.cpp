#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
//#include <thread>
#include <future>
#include <fstream>
#include <map>
#include <functional>
#include <typeindex>
#include <type_traits>
#include <cstring>
#include <ostream>
#include <memory>
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

//size_t n_cpus = std::thread::hardware_concurrency();

// for ed25519 we have constant keys - only for tests
unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES] = { 0x90,0xca,0xf3,0x48,0x28,0xf5,0x5a,0x5f,0x1e,0x54,0x2a,0x1e,0x1d,0x4f,0xbb,0xb2,0x99,0x19,0x75,0x73,0xa1,0x24,0xe0,0x52,0x01,0xb7,0x67,0xcf,0x2e,0x3c,0x5d,0x42,0xa6,0xfa,0x14,0x46,0xba,0xc6,0xbf,0xbc,0x28,0x4b,0x63,0x2d,0x92,0x11,0x10,0xfb,0x8c,0x37,0xdd,0xe3,0xf7,0x42,0xfe,0xd1,0x12,0x03,0x1f,0xc4,0xd0,0x26,0x1e,0xc6 };
unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];

// for blake2b we have constant keys - only for tests
unsigned char key[crypto_generichash_blake2b_KEYBYTES] = { 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2 };

// for blake2b_init
using key_size = size_t;
using hash_size = long long unsigned int; // we must have size_t for blake b2b_init

// sha256
typedef int (*sha256i)(crypto_hash_sha256_state *);
typedef int (*sha256u)(crypto_hash_sha256_state *, const unsigned char *, unsigned long long);
typedef int (*sha256f)(crypto_hash_sha256_state *, unsigned char *);
typedef int (*null_verify_sha256)(crypto_hash_sha256_state *);
// sha512
typedef int (*sha512i)(crypto_hash_sha512_state *);
typedef int (*sha512u)(crypto_hash_sha512_state *, const unsigned char *, unsigned long long);
typedef int (*sha512f)(crypto_hash_sha512_state *, unsigned char *);
typedef int (*null_verify_sha512)(crypto_hash_sha512_state *);
// blake2b
typedef int (*b2bi)(crypto_generichash_blake2b_state *, const unsigned char *, key_size, size_t); // in last argument we use hash_size below code
typedef int (*b2bu)(crypto_generichash_blake2b_state *, const unsigned char *, unsigned long long);
typedef int (*b2bf)(crypto_generichash_blake2b_state *, unsigned char *, const size_t);
typedef int (*null_verify_blake2b)(crypto_generichash_blake2b_state *);
// ed25519
typedef int (*ed25519i)(crypto_sign_ed25519ph_state *);
typedef int (*ed25519u)(crypto_sign_ed25519ph_state *, const unsigned char *, unsigned long long);
typedef int (*ed25519fc)(crypto_sign_ed25519ph_state *, unsigned char *, unsigned long long *, const unsigned char *);
typedef int (*ed25519fv)(crypto_sign_ed25519ph_state *, const unsigned char *, const unsigned char *);

template <typename T1, typename T, typename F, typename ... P>
class crypto_method {
public:
	crypto_method() {
//		pfp_info("constructor_0");
	};
	crypto_method(F f, P... p) : m_f{f} , m_p{p...} {
//		pfp_info("constructor_1");
	}
	T1 calculate() {
//		pfp_info("calculate");
		T1 status = m_f(&m_state, std::get<P>(m_p)...);
		return status;
	}
	T& get_state() { // dont work on constructor_0
		return m_state;
	}
	void set_state(const T& state) {
		m_state = state;
	}
private:
	T m_state;
	F m_f;
	std::tuple<P...> m_p;
};

class crypto_sha256 {
public:
	crypto_sha256() {
		m_init = crypto_method<int, crypto_hash_sha256_state, sha256i>(crypto_hash_sha256_init);
		m_init.calculate();
	}
	void update(const unsigned char * in, unsigned long long inlen) {
		m_update = crypto_method<int, crypto_hash_sha256_state, sha256u, const unsigned char *, unsigned long long>(crypto_hash_sha256_update, std::move(in), std::move(inlen));
		m_update.set_state(m_init.get_state());
		m_update.calculate();
	}
	void final(unsigned char * out) {
		m_final = crypto_method<int, crypto_hash_sha256_state, sha256f, unsigned char *>(crypto_hash_sha256_final, std::move(out));
		m_final.set_state(m_update.get_state());
		m_final.calculate();
	}
private:
	crypto_method<int, crypto_hash_sha256_state, sha256i> m_init;
	crypto_method<int, crypto_hash_sha256_state, sha256u, const unsigned char *, unsigned long long> m_update;
	crypto_method<int, crypto_hash_sha256_state, sha256f, unsigned char *> m_final;
};

class crypto_sha512 {
public:
	crypto_sha512() {
		m_init = crypto_method<int, crypto_hash_sha512_state, sha512i>(crypto_hash_sha512_init);
		m_init.calculate();
	}
	void update(const unsigned char * in, unsigned long long inlen) {
		m_update = crypto_method<int, crypto_hash_sha512_state, sha512u, const unsigned char *, unsigned long long>(crypto_hash_sha512_update, std::move(in), std::move(inlen));
		m_update.set_state(m_init.get_state());
		m_update.calculate();
	}
	void final(unsigned char * out) {
		m_final = crypto_method<int, crypto_hash_sha512_state, sha512f, unsigned char *>(crypto_hash_sha512_final, std::move(out));
		m_final.set_state(m_update.get_state());
		m_final.calculate();
	}
private:
	crypto_method<int, crypto_hash_sha512_state, sha512i> m_init;
	crypto_method<int, crypto_hash_sha512_state, sha512u, const unsigned char *, unsigned long long> m_update;
	crypto_method<int, crypto_hash_sha512_state, sha512f, unsigned char *> m_final;
};

class crypto_blake2b {
public:
	crypto_blake2b(const unsigned char * key) {
		std::memcpy(m_key, key, crypto_generichash_blake2b_KEYBYTES);
		m_key_size = sizeof(m_key);
		m_hash_size = crypto_generichash_blake2b_bytes();

		m_init = crypto_method<int, crypto_generichash_blake2b_state, b2bi, const unsigned char *, key_size, hash_size>(crypto_generichash_blake2b_init, m_key, static_cast<size_t>(m_key_size), static_cast<size_t>(m_hash_size));
		m_init.calculate();
	}
	void update(const unsigned char * in, size_t inlen) {
		m_update = crypto_method<int, crypto_generichash_blake2b_state, b2bu, const unsigned char *, size_t>(crypto_generichash_blake2b_update, std::move(in), std::move(inlen));
		m_update.set_state(m_init.get_state());
		m_update.calculate();
	}
	void final(unsigned char * out, size_t size) {
		m_final = crypto_method<int, crypto_generichash_blake2b_state, b2bf, unsigned char *, size_t>(crypto_generichash_blake2b_final, std::move(out), std::move(size));
		m_final.set_state(m_update.get_state());
		m_final.calculate();
	}
private:
	crypto_method<int, crypto_generichash_blake2b_state, b2bi, const unsigned char *, key_size, hash_size> m_init;
	crypto_method<int, crypto_generichash_blake2b_state, b2bu, const unsigned char *, size_t> m_update;
	crypto_method<int, crypto_generichash_blake2b_state, b2bf, unsigned char *, size_t> m_final;

	unsigned char m_key[crypto_generichash_blake2b_KEYBYTES];
	key_size m_key_size;
	hash_size m_hash_size;
};

class crypto_ed25519 {
public:
	crypto_ed25519(const unsigned char *secret_key, const unsigned char *public_key) {
	std::memcpy(m_secret_key, secret_key, crypto_sign_ed25519_SECRETKEYBYTES);
	std::memcpy(m_public_key, public_key, crypto_sign_ed25519_PUBLICKEYBYTES);
	// we dont see pk and sk
	//pfp_info("sk : " << n_pfp::dbgstr_hex(m_secret_key, crypto_sign_ed25519_SECRETKEYBYTES));
	//pfp_info("pk : " << n_pfp::dbgstr_hex(m_public_key, crypto_sign_ed25519_PUBLICKEYBYTES));

		m_init = crypto_method<int, crypto_sign_ed25519ph_state, ed25519i>(crypto_sign_ed25519ph_init);
		m_init.calculate();
	}
	void update(const unsigned char * in, size_t inlen) {
		m_update = crypto_method<int, crypto_sign_ed25519ph_state, ed25519u, const unsigned char *, unsigned long long>(crypto_sign_ed25519ph_update, std::move(in), std::move(inlen));
		m_update.set_state(m_init.get_state());
		m_update.calculate();
	}
	void final(unsigned char * out, unsigned long long *size) {
		m_final = crypto_method<int, crypto_sign_ed25519ph_state, ed25519fc, unsigned char *, unsigned long long *, const unsigned char *>(crypto_sign_ed25519ph_final_create, std::move(out), std::move(size), m_secret_key);
		m_final.set_state(m_update.get_state());
		m_final.calculate();
	}
	int verify(unsigned char * out) {
		m_verify = crypto_method<int, crypto_sign_ed25519ph_state, ed25519fv, unsigned char *, const unsigned char *>(crypto_sign_ed25519ph_final_verify, std::move(out), std::move(m_public_key));
		m_verify.set_state(m_update.get_state());
		return m_verify.calculate() != 0;
	}
private:
	crypto_method<int, crypto_sign_ed25519ph_state, ed25519i> m_init;
	crypto_method<int, crypto_sign_ed25519ph_state, ed25519u, const unsigned char *, unsigned long long> m_update;
	crypto_method<int, crypto_sign_ed25519ph_state, ed25519fc, unsigned char *, unsigned long long *, const unsigned char *> m_final;
	crypto_method<int, crypto_sign_ed25519ph_state, ed25519fv, unsigned char *, const unsigned char *> m_verify;

	unsigned char m_secret_key[crypto_sign_ed25519_SECRETKEYBYTES];
	unsigned char m_public_key[crypto_sign_ed25519_PUBLICKEYBYTES];
};

#define NO_HASHES 4 // XXX in order : sha256 sha512 blake2b ed25519 ...

enum hashes {
	sha256,
	sha512,
	blake2b,
	ed25519
};

typedef struct crypto_result { // store ms time for each hashes
	std::chrono::milliseconds m_hash_time[NO_HASHES];
} crypto_result;

typedef struct report {
	std::string m_filename;
	std::vector<crypto_result> m_result;
} report_result;

template<class C>
crypto_result calculate(unsigned char *mapped_file, size_t mapped_size) {
	//std::cout << "In ThreadID 0x" << std::hex << std::this_thread::get_id() << std::endl;
	std::chrono::system_clock::time_point begin, end;
	crypto_result result;
	size_t offset = 0;
	if constexpr (std::is_same_v<C,crypto_sha256>) {
		std::unique_ptr<unsigned char[]> hash(new unsigned char[crypto_hash_sha256_bytes()]);
		begin = std::chrono::system_clock::now();
		crypto_sha256 crypt;
		crypt.update(reinterpret_cast<const unsigned char *>(mapped_file), reinterpret_cast<size_t>(mapped_size));
		crypt.final(hash.get());
		end = std::chrono::system_clock::now();
		result.m_hash_time[hashes::sha256] = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin); // store the difference ms time between start and end crypto_init , crypto_update , crypto_final
		//std::cout << "SHA256 : " << bin2hex<unsigned char>(hash.get(), crypto_hash_sha256_bytes()) << std::endl;
	}
	if constexpr (std::is_same_v<C,crypto_sha512>) {
		std::unique_ptr<unsigned char[]> hash(new unsigned char[crypto_hash_sha512_bytes()]);
		begin = std::chrono::system_clock::now();
		crypto_sha512 crypt;
		crypt.update(reinterpret_cast<const unsigned char *>(mapped_file), reinterpret_cast<size_t>(mapped_size));
		crypt.final(hash.get());
		end = std::chrono::system_clock::now();
		result.m_hash_time[hashes::sha512] = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin); // store the difference ms time between start and end crypto_init , crypto_update , crypto_final
		//std::cout << "SHA512 : " << bin2hex<unsigned char>(hash.get(), crypto_hash_sha512_bytes()) << std::endl;
	}
	if constexpr (std::is_same_v<C,crypto_blake2b>) {
		std::unique_ptr<unsigned char[]> hash(new unsigned char[crypto_generichash_blake2b_bytes()]);
		begin = std::chrono::system_clock::now();
		crypto_blake2b crypt(key);
		crypt.update(reinterpret_cast<const unsigned char *>(mapped_file), reinterpret_cast<size_t>(mapped_size));
		crypt.final(hash.get(), crypto_generichash_blake2b_bytes());
		end = std::chrono::system_clock::now();
		result.m_hash_time[hashes::blake2b] = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin); // store the difference ms time between start and end crypto_init , crypto_update , crypto_final
		//std::cout << "BLAKE2B : " << bin2hex<unsigned char>(hash.get(), crypto_generichash_blake2b_bytes()) << std::endl;
	}
	if constexpr (std::is_same_v<C,crypto_ed25519>) {
		std::unique_ptr<unsigned char[]> hash(new unsigned char[crypto_sign_ed25519_bytes()]);
		begin = std::chrono::system_clock::now();
		crypto_ed25519 crypt(sk,pk);
		crypt.update(reinterpret_cast<const unsigned char *>(mapped_file), reinterpret_cast<size_t>(mapped_size));
		crypt.final(hash.get(), NULL);
		end = std::chrono::system_clock::now();
		result.m_hash_time[hashes::ed25519] = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin); // store the difference ms time between start and end crypto_init , crypto_update , crypto_final
		//std::cout << "ED25519 : " << bin2hex<unsigned char>(hash.get(), crypto_sign_ed25519_bytes()) << std::endl;
	}
	return result;
}

void pin_to_cpu(std::thread & t, size_t nr_cpu) {
	std::thread::native_handle_type nht;
	int pthread_rc = -1;
	cpu_set_t cpuset;

	nht = t.native_handle();
	CPU_ZERO(&cpuset);
	CPU_SET(nr_cpu, &cpuset);
	pthread_rc = pthread_setaffinity_np(nht, sizeof(cpu_set_t), &cpuset);
	if (pthread_rc != 0) {
	//std::cout << "Failed to pin cpu" << nr_cpu << " : " << std::strerror(errno) << std::endl;
	} else {
		//std::cout << "pin cpu" << nr_cpu << " to thread 0x" << std::hex << t.get_id() << std::endl;
	}
}

int main(int argc, char *argv[])
{
	if (sodium_init() == -1) {
		std::cout << "sodium_init == -1" << std::endl;
		exit(1);
	} else {
		// after sodium initialize, start rest...

		// init keys
		crypto_sign_ed25519_sk_to_pk(pk, sk);
	}

	report_result report;
	std::memchr(&report, 0, sizeof(report));

	std::string file_name(argv[1]);
	size_t NO_TESTS = std::atoi(argv[2]);
	std::string csv_file;
	bool use_csv = false;
	if (argv[3] != nullptr) {
		csv_file.append(std::string(argv[3], strlen(argv[3])));
		std::cout << "output to CSV file " << csv_file << std::endl;
		use_csv = true;
	} else {
		std::cout << "CSV not used" << std::endl;
	}

	std::ofstream csv_output_file;
	if (use_csv == true) {
		csv_output_file.open(csv_file, std::ofstream::out);
		if (!csv_output_file.is_open()) {
			std::cout << "Error on open CSV file " << csv_file << std::endl;
			exit(2);
		}
	}

	size_t file_size = -1;
	unsigned char *mapped_file = (unsigned char*)MAP_FAILED;

	int fd = open(file_name.c_str(), O_RDONLY);
	if (fd == -1) {
		std::cout << "file " << file_name << " not open, flag RDONLY : " << strerror(errno) << " , skipping..." << std::endl;
	} else {
		struct stat64 stat64_file;
		if (stat64(file_name.c_str(), &stat64_file) == -1) {
			std::cout << file_name << " cannot stat and get file size : " << strerror(errno) << std::endl;
		} else {
			file_size = stat64_file.st_size;
			std::cout << "use mmap64..." << std::endl;
			std::cout << file_name << " have " << file_size << " bytes" << std::endl;
			mapped_file = reinterpret_cast<unsigned char*>(mmap64(NULL, file_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0));
			if (mapped_file == (unsigned char *)MAP_FAILED) {
				std::cout << "cannot mmap64 size " << file_size << " : " << strerror(errno) << std::endl;
				exit(3);
			} else {
				std::cout << "mmap64 at pointer " << &mapped_file << std::endl;
			}
		}
	}

	for (size_t test_number = 0; test_number < NO_TESTS; test_number++) {
		//std::cout << "File : " << file_name << " , " << "Test number : " << test_number << std::endl; // + 1 to human readable
		report.m_filename = file_name; // store file name for result

		using Task_type = crypto_result(unsigned char *, size_t);
		std::array<std::unique_ptr<std::packaged_task<Task_type>>,NO_HASHES> vector_packed_tasks;
		std::array<std::unique_ptr<std::future<crypto_result>>, NO_HASHES> vector_futures;
		std::array<std::thread, NO_HASHES> vector_threads;

		// XXX in order : sha256 sha512 blake2b ed25519 ...
		vector_packed_tasks.at(hashes::sha256) = std::make_unique<std::packaged_task<Task_type>>(calculate<crypto_sha256>);
		vector_packed_tasks.at(hashes::sha512) = std::make_unique<std::packaged_task<Task_type>>(calculate<crypto_sha512>);
		vector_packed_tasks.at(hashes::blake2b) = std::make_unique<std::packaged_task<Task_type>>(calculate<crypto_blake2b>);
		vector_packed_tasks.at(hashes::ed25519) = std::make_unique<std::packaged_task<Task_type>>(calculate<crypto_ed25519>);
		vector_futures.at(hashes::sha256) = std::make_unique<std::future<crypto_result>>(vector_packed_tasks.at(hashes::sha256).get()->get_future());
		vector_futures.at(hashes::sha512) = std::make_unique<std::future<crypto_result>>(vector_packed_tasks.at(hashes::sha512).get()->get_future());
		vector_futures.at(hashes::blake2b) = std::make_unique<std::future<crypto_result>>(vector_packed_tasks.at(hashes::blake2b).get()->get_future());
		vector_futures.at(hashes::ed25519) = std::make_unique<std::future<crypto_result>>(vector_packed_tasks.at(hashes::ed25519).get()->get_future());

		// create and run threads
		try {
			for (size_t index = 0; index < vector_packed_tasks.size(); index++) {
				std::thread t([&vector_packed_tasks, &mapped_file, file_name, file_size, index](){
					std::packaged_task<Task_type> *pt = vector_packed_tasks.at(index).get();
					(*pt)(mapped_file, file_size);
				});
				pin_to_cpu(t, index);
				vector_threads[index] = std::move(t);
			}
		} catch(std::exception & e) {
			std::cout << "Thread Exception : " << e.what() << std::endl;
			exit(4);
		}

		// join threads
		for (size_t index = 0; index < vector_threads.size(); index++) {
			if (vector_threads.at(index).joinable()) {
				//std::cout << "Join thread id : " << "0x" << std::hex << vector_threads.at(index).get_id() << std::endl;
				vector_threads.at(index).join();
			}
		}

		struct crypto_result hash_time;
		std::future<crypto_result> *future_sha256 = vector_futures.at(hashes::sha256).get();
		if (future_sha256->valid()) {
			crypto_result result = future_sha256->get();
			hash_time.m_hash_time[hashes::sha256] = result.m_hash_time[hashes::sha256];
		}
		std::future<crypto_result> *future_sha512 = vector_futures.at(hashes::sha512).get();
		if (future_sha512->valid()) {
			crypto_result result = future_sha512->get();
			hash_time.m_hash_time[hashes::sha512] = result.m_hash_time[hashes::sha512];
		}
		std::future<crypto_result> *future_blake2b = vector_futures.at(hashes::blake2b).get();
		if (future_blake2b->valid()) {
			crypto_result result = future_blake2b->get();
			hash_time.m_hash_time[hashes::blake2b] = result.m_hash_time[hashes::blake2b];
		}
		std::future<crypto_result> *future_ed25519 = vector_futures.at(hashes::ed25519).get();
		if (future_ed25519->valid()) {
			crypto_result result = future_ed25519->get();
			hash_time.m_hash_time[hashes::ed25519] = result.m_hash_time[hashes::ed25519];
		}
		report.m_result.push_back(hash_time);
	} // no test

	close(fd);

	if (munmap(mapped_file, file_size) == -1) {
		//std::cout << "failed unmap : " << strerror(errno) << std::endl;
		exit(5);
	}

	// calculate report and print it
	if (use_csv == true) {
		csv_output_file << "sha256,sha512,blake2b,ed25519" << std::endl;
	}
	std::chrono::milliseconds time_result_sha256 {0};
	std::chrono::milliseconds time_result_sha512 {0};
	std::chrono::milliseconds time_result_blake2b {0};
	std::chrono::milliseconds time_result_ed25519 {0};
	for(size_t test_number = 0; test_number < NO_TESTS; test_number++) {
		time_result_sha256 += report.m_result.at(test_number).m_hash_time[hashes::sha256];
		time_result_sha512 += report.m_result.at(test_number).m_hash_time[hashes::sha512];
		time_result_blake2b += report.m_result.at(test_number).m_hash_time[hashes::blake2b];
		time_result_ed25519 += report.m_result.at(test_number).m_hash_time[hashes::ed25519];
		if (use_csv == true) {
			std::ostringstream oss_record;
			oss_record << report.m_result.at(test_number).m_hash_time[hashes::sha256].count() << "," << report.m_result.at(test_number).m_hash_time[hashes::sha512].count() << "," << report.m_result.at(test_number).m_hash_time[hashes::blake2b].count() << "," << report.m_result.at(test_number).m_hash_time[hashes::ed25519].count() << std::endl;
			std::string record(oss_record.str());
			csv_output_file.write(record.data(),record.size());
		}
	} // for index test
	std::cout << "Number tests : " << NO_TESTS << " , " << "file name : " << file_name << " , " << "avg. time result in milliseconds for sha256   : " << time_result_sha256.count() / NO_TESTS << " ms" << std::endl;
	std::cout << "Number tests : " << NO_TESTS << " , " << "file name : " << file_name << " , " << "avg. time result in milliseconds for sha512   : " << time_result_sha512.count() / NO_TESTS << " ms" << std::endl;
	std::cout << "Number tests : " << NO_TESTS << " , " << "file name : " << file_name << " , " << "avg. time result in milliseconds for blake2b  : " << time_result_blake2b.count() / NO_TESTS << " ms" << std::endl;
	std::cout << "Number tests : " << NO_TESTS << " , " << "file name : " << file_name << " , " << "avg. time result in milliseconds for ed25519  : " << time_result_ed25519.count() / NO_TESTS << " ms" << std::endl;
	if (use_csv == true) {
		csv_output_file.close();
	}
}
