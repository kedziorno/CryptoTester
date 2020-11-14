#include <iostream>
#include <vector>
#include <thread>
#include <future>
#include <fstream>

#include <sodium.h>

#include "pfp-cpp/pfplog/pfplog.hpp"
#include "pfp-cpp/pfplog/dbgstr.hpp"
#include "pfp-cpp/stdpfp/xint.hpp"

std::array<bool,4> b;
std::vector<std::mutex> vec_mtx(4);
std::vector<std::condition_variable> vec_cv(4);
std::mutex mtx;
std::vector<std::condition_variable> cv;

struct state_ctx {
	size_t index;
	crypto_hash_sha256_state state;
};

state_ctx wrapper(std::vector<std::condition_variable> & vector_cv, std::ifstream & random_input_file, size_t offset_in_file, size_t piece_of_file, crypto_hash_sha256_state *state, size_t index, size_t num_c) {
	std::thread::id ct = std::this_thread::get_id();

//	std::unique_lock<std::mutex> lock(mtx);
//	if (index != 0) {
//		pfp_fact("Wait on index = " << index);
//		while (!b[index - 1]) {
//			vector_cv[0].wait(lock);
//		}
//	} else {
//		pfp_fact("First thread 0x" << std::hex << std::this_thread::get_id() << " , " << "index = " << index);
//	}

	{
		const size_t const_number_concurenncy = num_c;
		size_t buffer_size = const_number_concurenncy * 1024 * 1024;
		std::vector<char> buffer(buffer_size, 0); // TODO std::unique_ptr<char[]> buffer(new char[buffer_size]); ?
		size_t end_offset = offset_in_file + piece_of_file;
		random_input_file.seekg(offset_in_file, random_input_file.beg);
		while (offset_in_file < end_offset) {
			random_input_file.seekg(offset_in_file, random_input_file.beg); // TODO .cur ?
			random_input_file.read(buffer.data(), buffer_size);
			if (random_input_file) {
//				pfp_fact("thread id 0x" << std::hex << ct << " - Read piece #" << std::hex << offset_in_file << " / " << std::hex << random_input_file.tellg());
//				pfp_fact("thread id 0x" << std::hex << ct << " - data : " << n_pfp::dbgstr_hex2(buffer.data(), buffer.size(), 16));
				crypto_hash_sha256_update(state, reinterpret_cast<const unsigned char *>(buffer.data()), reinterpret_cast<long unsigned int>(buffer_size));
				offset_in_file += buffer_size;
			} else {
				pfp_fact("Only " << random_input_file.gcount() << " bytes readed");
				break;
			}
		}
	}

//	b[index] = true;
//	vector_cv[0].notify_all();

//	{
//		pfp_fact("cv.wait on index = " << index);
//		vector_cv.at(index).wait(lock);
//	}
//	//lock.unlock();
//	{
//		size_t next = index + 1;
//		pfp_fact("cv.notify_one on index = " << index);
//		vector_cv.at(next).notify_one();
//	}

//	std::unique_lock<std::mutex> lock(vec_mtx.at(index));
//	if (index == num_c - 1) { // last
//		pfp_fact("thread id 0x" << std::hex << ct << " - We are on last, unsleeping from threads...");
//		for (size_t index = 0; index < num_c - 1; index++) {
//			pfp_fact("Set ready flag for index = " << index);
//			b[index] = true;
//		}
//	} else {
//		pfp_fact("thread id 0x" << std::hex << ct << " - cv.wait on index = " << index);
//		while(!b.at(index)) vec_cv.at(index).wait(lock);
//	}

//		if (index < num_c) {
//			size_t next = index + 1;
//			pfp_fact("thread id 0x" << std::hex << ct << " - cv.notify_one on index = " << index << " , next = " << next);
//			vector_cv.at(index).notify_one();
//		}

//		pfp_fact("thread id 0x" << std::hex << ct << " - We are on last, unsleeping from last to 0...");
//		for (size_t index = num_c - 1; index > 0; index--) {
//			pfp_fact("thread id 0x" << std::hex << ct << " - cv.notify_one on index = " << index - 1);
//			vector_cv.at(index-1).notify_one();
//		}

	{
		state_ctx sc;
		sc.index = index;
		std::copy(&state->buf[0], &state->buf[63], sc.state.buf);
		sc.state.count = state->count;
		std::copy(&state->state[0], &state->state[8], sc.state.state);
		pfp_fact("index = " << index << " , thread id 0x" << std::hex << std::this_thread::get_id() << " , org state : " << n_pfp::dbgstr_hex(state->state, 8));
		pfp_fact("index = " << index << " , thread id 0x" << std::hex << std::this_thread::get_id() << " , new state : " << n_pfp::dbgstr_hex(sc.state.state, 8));
		return sc;
	}

//	vector_cv.at(index-1).notify_one();
//	{
//		pfp_fact("cv.wait on index = " << index);
//		vector_cv.at(index).wait(lock);
//	}
//	{
//		if (0 < index && index <= num_c - 1) {
//			size_t prev = index - 1;
//			pfp_fact("cv.notify_one on prev index = " << prev);
//			vector_cv.at(prev).notify_one();
//		} else {
//			pfp_fact("cv.notify_one on 0 index");
//			vector_cv.at(0).notify_one();
//		}
//	}

}

void example2(unsigned int num_threads) {
	if (sodium_init() == -1) {
		std::cout << "Sodium failed" << std::endl;
		exit(1);
	} else {
		// case high priority: more tasks, less threads
		// unsigned num_c = std::thread::hardware_concurrency();
		size_t num_c = num_threads;

		size_t file_size = -1, piece_in_file = -1;
//		std::ifstream random_input_file("rndfile_4g", std::ifstream::out | std::ifstream::binary);
		std::ifstream random_input_file("rndfile_1g", std::ifstream::out | std::ifstream::binary);
		if (random_input_file.is_open()) {
			random_input_file.seekg(0, random_input_file.end);
			file_size = random_input_file.tellg();
			pfp_fact("seek end: " << file_size);
			random_input_file.seekg(0,random_input_file.beg);
		} else {
			pfp_fact("File not open");
		}

		// case low priority: less tasks, more threads
		if (file_size < num_c) {
			num_c = file_size;
			std::cout << "data.size < num_threads : " << file_size << " < " << num_threads << std::endl;
		} else
		// case mid priority: tasks == threads
		if (file_size == num_c) {
			num_c = file_size;
			std::cout << "data.size = num_threads : " << file_size << " = " << num_threads << std::endl;
		} else {
			std::cout << "data.size > num_threads : " << file_size << " > " << num_threads << std::endl;
		}

		if (file_size > 0) {
			piece_in_file = file_size / num_c;
		}

		std::vector<state_ctx> vector_states(0);
		std::vector<std::condition_variable> vector_cv(num_c);
		b.fill(false);

		crypto_hash_sha256_state sha256_state;
		crypto_hash_sha256_init(&sha256_state);

		using Task_type = state_ctx(std::vector<std::condition_variable> &, std::ifstream &, size_t, size_t, crypto_hash_sha256_state *, size_t, size_t);

		std::vector<std::unique_ptr<std::packaged_task<Task_type>>> vector_packed_tasks;
		std::vector<std::unique_ptr<std::future<state_ctx>>> vector_futures;
		std::vector<std::thread> vector_threads; // TODO maybe unique_ptr std::thread

		// packed_task
		for (size_t index = 0; index < num_c; index++) {
			vector_packed_tasks.push_back(std::make_unique<std::packaged_task<Task_type>>(wrapper));
		}

		// future
		for (size_t index = 0; index < num_c; index++) {
			vector_futures.push_back(std::make_unique<std::future<state_ctx>>(vector_packed_tasks.at(index).get()->get_future()));
		}

		// thread

		for (size_t index = 0; index < num_c; index++) {
			size_t offset = piece_in_file * index;
//			pfp_fact("offset_in_file : " << offset);
			try {
				std::thread t ([&vector_cv, &random_input_file, offset, piece_in_file, index, &vector_packed_tasks, &sha256_state, num_c](){
					{
						pfp_fact("-----------------------------------------------------------------");
						//std::lock_guard<std::mutex> iolock(m1);
						size_t no_task = index;
						pfp_fact("Run thread #" << index << " on CPU #" << sched_getcpu() << " , offset_in_file = " << offset);
						std::packaged_task<Task_type> *pt = vector_packed_tasks.at(no_task).get();
						(*pt)(vector_cv, random_input_file, offset, piece_in_file, &sha256_state, index, num_c);
						pfp_fact("index = " << index << " , state : " << n_pfp::dbgstr_hex(sha256_state.state, 8));
						pfp_fact("-----------------------------------------------------------------");
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
				// -2nd
//				if (t.joinable()) {
//					pfp_fact("Join thread id : " << "0x" << std::hex << t.get_id());
//					t.join();
//				}
				vector_threads.push_back(std::move(t));
			} catch(std::exception & e) {
				std::cout << "Exception : " << e.what() << std::endl;
				exit(1);
			}
		}

//		for (size_t index = 0; index < num_c; index++) {
//			pfp_fact("IN MAIN : cv.notify_one index = " << index);
//			vector_cv.at(index).notify_one();
//		}

		pfp_fact("-----------------------------------------------------------------");

//		for (size_t index = 0; index < num_c; index++) {
//			pfp_fact("IN MAIN : ready flag for index = " << index);
//			b[index] = true;
//		}

		// joining threads -2nd
		for (size_t index = 0; index < num_c; index++) {
			if (vector_threads.at(index).joinable()) {
				pfp_fact("Join thread id : " << "0x" << std::hex << vector_threads.at(index).get_id());
				vector_threads.at(index).join();
			}
		}

		pfp_fact("-----------------------------------------------------------------");

		// add crypto ctx from futures
		for (size_t index = 0; index < num_c; index++) {
			std::future<state_ctx> *fc = vector_futures.at(index).get();
			if (fc->valid()) {
				vector_states.push_back(fc->get());
				size_t vs_size = vector_states.size()-1;
				state_ctx *sc = &vector_states.at(vs_size);
				pfp_fact("vector_states size = " << vector_states.size() << " , " << "index = " << index << " , " << "state_index = " << sc->index << " , " << "state : " << n_pfp::dbgstr_hex(sc->state.state, 8));
			}
		}

		pfp_fact("-----------------------------------------------------------------");

		// execute ctx's on crypto final functions
		for (size_t index = 0; index < num_c; index++) {
			unsigned char out[crypto_hash_sha256_BYTES];
			state_ctx *sc = &vector_states.at(index);
			pfp_fact("vector_states size = " << vector_states.size() << " , " << "index = " << index << " , " << "state_index = " << sc->index << " , " << "state : " << n_pfp::dbgstr_hex(sc->state.state, 8));
			crypto_hash_sha256_final(&sc->state, out);
			pfp_fact("sha256 : " << n_pfp::dbgstr_hex(out, crypto_hash_sha256_BYTES)); // TODO exec console!=qtcreator
		}
	}
}

void example3() {
	std::vector<std::string> data;
	//	TODO sha256 from data is 0b3e4e625d89234675099ff36b5b5b8f3d7ecb270504ac0c31fbe912ca9fbd64
	data.push_back(std::string("1234"));
	data.push_back(std::string("5678"));
	data.push_back(std::string("90AB"));
	data.push_back(std::string("CDEF"));

	pfp_fact("Data size = " << data.size());

	constexpr size_t num_c = 4;
	std::array<crypto_hash_sha256_state, num_c> states;
	crypto_hash_sha256_state state;
	std::array<std::thread, num_c> threads;
	std::vector<std::condition_variable> vec_cv(num_c);
	std::vector<std::mutex> vec_mtx(num_c);
	std::condition_variable cv;
	std::mutex mtx;

	bool flag[num_c] = { false };

	// memset0 - TODO we overwrite above data ?!?!?!
//	for (size_t index = 0; index < num_c; index++) {
//		std::fill(&states[index].buf[0], &states[index].buf[0] + sizeof(states[index].buf), 0);
//		std::fill(&states[index].state[0], &states[index].state[0] + sizeof(states[index].state), 0);
//		states[index].count = 0;
//		pfp_fact("index = " << index << " , " << "state.buf = " << n_pfp::dbgstr_hex2(states[index].buf, 63, 8) << " , " << "state.state = " << n_pfp::dbgstr_hex2(states[index].state, 7, 8) << " , " << "state.count = " << states[index].count);
//	}

	// init struct
	for (size_t index = 0; index < num_c; index++) {
		pfp_fact("Init index = " << index);
		crypto_hash_sha256_init(&state);
		pfp_fact("Init index = " << index << " , " << "dump : " << n_pfp::dbgstr_hex(state.state, 8));
	}

	auto thread_function = [&state, &data, &cv, &mtx, &flag](size_t index){
		std::unique_lock<std::mutex> lock(mtx);
		if (index != 0) {
			pfp_fact("Wait on index = " << index);
			while (!flag[index - 1]) {
				cv.wait(lock);
			}
		} else {
			pfp_fact("First thread 0x" << std::hex << std::this_thread::get_id() << " , " << "index = " << index);
		}
		pfp_fact("After wait");
		if (index < data.size()) {
			crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char *>(data.at(index).c_str()), reinterpret_cast<long unsigned int>(data.at(index).size()));
		} else {
			pfp_fact("Data out of range : " << index << " > " << data.size());
		}
		pfp_fact("Update index = " << index << " , " << "dump : " << n_pfp::dbgstr_hex(state.state, 8));
		flag[index] = true;
		cv.notify_all();
	};

	// update
	for (size_t index = 0; index < num_c; index++) {
		threads[index] = std::thread(thread_function, index);
		pfp_fact("Create thread 0x" << std::hex << threads[index].get_id());
	}

	for (size_t index = 0; index < num_c; index++) {
		pfp_fact("Join thread 0x" << std::hex << threads[index].get_id());
		threads[index].join();
	}

	// final
	unsigned char out[crypto_hash_sha256_BYTES];
	crypto_hash_sha256_final(&state, out);
	pfp_fact("Final sha256 : " << n_pfp::dbgstr_hex(out, crypto_hash_sha256_BYTES)); // TODO exec console!=qtcreator
}

int main(int argc, char *argv[])
{
	std::cout << "Hello World!" << std::endl;

	if (argc == 1) {
		unsigned int num_c = std::thread::hardware_concurrency();
		pfp_fact("Use with no threads : " << num_c);
		example2(num_c);
	} else
	if (argc == 2) {
		unsigned int num_c = std::atoi(argv[1]);
		pfp_fact("Use with no threads : " << num_c);
		example2(num_c);
	}

//	example3();

	return 0;
}

//		std::vector<std::string> data;
//	TODO sha256 from data is 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
//		data.push_back(std::string("1234"));
//	TODO sha256 from data is ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f
//		data.push_back(std::string("1234"));
//		data.push_back(std::string("5678"));
//	TODO sha256 from data is 0b3e4e625d89234675099ff36b5b5b8f3d7ecb270504ac0c31fbe912ca9fbd64
//		data.push_back(std::string("1234"));
//		data.push_back(std::string("5678"));
//		data.push_back(std::string("90AB"));
//		data.push_back(std::string("CDEF"));

// normal hash
//		{
//			unsigned char hash_data_out[crypto_hash_sha256_BYTES];
//			crypto_hash_sha256_state hash_state;
//			crypto_hash_sha256_init(&hash_state);
//			size_t file_pos = 0;
//			constexpr size_t buffer_size = 1024 * 1024;
//			std::array<char, buffer_size> buffer; // TODO std::unique_ptr<char[]> buffer(new char[buffer_size]); ?
//			while (file_pos < file_size) {
//				buffer.fill(0);
//				random_input_file.read(buffer.data(), buffer_size);
//				if (random_input_file) {
//					pfp_fact("Read piece #" << std::hex << file_pos << " / " << std::hex << file_size);
//					pfp_fact("data : " << n_pfp::dbgstr_hex2(buffer.data(), buffer.size(), 16));
//					crypto_hash_sha256_update(&hash_state, reinterpret_cast<const unsigned char *>(buffer.data()), reinterpret_cast<long unsigned int>(buffer_size));
//					file_pos += buffer_size;
//					random_input_file.seekg(file_pos, random_input_file.beg); // TODO .cur ?
//				} else {
//					pfp_fact("Only " << random_input_file.gcount() << " bytes readed");
//					break;
//				}
//			}
//			crypto_hash_sha256_final(&hash_state, hash_data_out);
//			pfp_fact("sha256 : " << n_pfp::dbgstr_hex(hash_data_out, crypto_hash_sha256_BYTES));
//		}

//				sched_param sch_params = { 0 };
//				sch_params.__sched_priority = (index+1)*10;
//				pfp_fact("Set schedule priority " << sch_params.__sched_priority << " for thread 0x" << std::hex << t.get_id());
//				pthread_rc = pthread_setschedparam(nht, SCHED_FIFO, &sch_params);
//				if (pthread_rc != 0) {
//					pfp_fact("Failed to set thread scheduling : " << std::strerror(errno));
//				} else {
//					pfp_fact("set thread scheduling for 0x" << std::hex << t.get_id());
//				}
