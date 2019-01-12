#include "NanoLog.hpp"
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <cstdio>


// this test may eat up all the memory if too big

constexpr int32_t iterExp = 19;
    
uint64_t timestamp_now()
{
    constexpr int32_t sec2nsec = 1000*1000*1000LL;
    timespec t;
    clock_gettime( CLOCK_REALTIME, &t);
    return t.tv_sec * sec2nsec + t.tv_nsec;
}

void nanolog_benchmark()
{
    char const * const benchmark = "benchmark";
    uint64_t begin = timestamp_now();
    
    for (int i = 0; i < 1<<iterExp; ++i)
        LOG_INFO << "Logging " << benchmark << "       " << i  << "       " << 0  << "       " << 'K'  << "       "  << -42.42;
    
    long int avg_latency = (timestamp_now() - begin)>>iterExp;
    printf("\tAverage NanoLog Latency = %ld nanoseconds\n", avg_latency);
}

template < typename Function >
void run_benchmark(Function && f, int thread_count)
{
    printf("Thread count: %d cycle: %d\n", thread_count, 1<<iterExp);
    std::vector < std::thread > threads;
    for (int i = 0; i < thread_count; ++i)
    {
        threads.emplace_back(f);
    }
    for (int i = 0; i < thread_count; ++i)
    {
        threads[i].join();
    }
}

int main()
{
    // Ring buffer size is passed as 10 mega bytes.
    // Since each log line = 256 bytes, thats 40960 slots.
    nanolog::initialize(nanolog::GuaranteedLogger(), "/tmp/", "nanolog", 10);
    for (auto threads : { 1, 2, 3, 4, 5 })
    	run_benchmark(nanolog_benchmark, threads);

    return 0;
}

