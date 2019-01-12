#include "NanoLog.hpp"
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>
#include <atomic>
#include <cstdio>
#include <ctime>
#include <chrono>


uint64_t timestamp_now()
{
    constexpr int32_t sec2nsec = 1000*1000*1000LL;
    timespec t;
    clock_gettime( CLOCK_REALTIME, &t);
    return t.tv_sec * sec2nsec + t.tv_nsec;
}

void nanolog_benchmark()
{
    std::stringstream ss;
    std::cout << ss.str() << std::endl;
    constexpr int32_t iterExp = 4;
    int const iterations = 1<<iterExp;
    char const * const benchmark = " test ";
    uint64_t begin = timestamp_now();
    
    uint16_t    u16 = -116;
    int16_t     i16 = -216;
    uint32_t    u32 = -132;
    int32_t     i32 = -232;
    uint64_t    u64 = -164;
    int64_t     i64 = -264;
    float       f = 7000.0;
    double      d = 8000.0;
    void  *     vp = &u16;
    void  *     vp0 = nullptr;
    char        c = 'X';
    
    std::string ll(128,'X');
    ll += "0 123456789 0123456789 1 123456789 2 123456789 3 123456789 4 123456789 5 123456789 6 123456789 7 123456789 8 123456789";

    struct {
        int x1 = 0x12345678;
        int x2 = 0xABCDEF01;
        char x3 = 0xFF;
        int x4 = 0x12345678;
        char xxx[512];
    } xx1, xx2 ;
    
    uint64_t a1 = 1111;
    uint64_t a2 = 2222;
    uint64_t a3 = 3333;
    uint64_t a4 = 4444;
    uint64_t a5 = 5555;
    uint64_t a6 = 6666;
    uint64_t a7 = 7777;
    uint64_t a8 = 8888;
        
    LOG_DEBUG
        << " numbers " 
        << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2
        << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 
        << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 
        << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 
        << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2
        << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 
        << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 
        << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 
        << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2
        << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 
        << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 
        << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 
        << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2 << a1 << a2
        << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 << a3 << a4 
        << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 << a5 << a6 
        << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 << a7 << a8 
        ;

    LOG_INFO
        << " c " << c
        << " u16 " << u16 
        << " u32 " << u32
        << " u64 " << u64 
        << " f " << f
        << " i16 " << i16 
        << " i32 " << i32
        << " i64 " << i64 
        << " voidp " << vp
        << " nullp " << vp0
        << " d " << d
        ;

    LOG_TRACE 
        << " hexdump xx1 " << LOG_DUMPHEX(xx1)  
        << " xx2 " << LOG_DUMPHEX(xx2)  
        << " end 1 "
        << " end 2 "
        << " end 3 "
        << " end 4 "
        ;
        
    LOG_DEBUG
        << " ll " << ll
        << " end 1 "
        << " end 2 "
        << " end 3 "
        << " end 4 "
        ;

        
    long int avg_latency = (timestamp_now() - begin)>>iterExp;
    printf("\tAverage NanoLog Latency = %ld nanoseconds\n", avg_latency);
}

template < typename Function >
void run_benchmark(Function && f, int thread_count)
{
    printf("Thread count: %d\n", thread_count);
    std::vector < std::thread > threads;
    for (int i = 0; i < thread_count; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        threads.emplace_back(f);
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    for (int i = 0; i < thread_count; ++i)
    {
        threads[i].join();
    }
}

int main()
{
    nanolog::initialize(nanolog::NonGuaranteedLogger(10), "/tmp/", "", 1);
    for (auto threads : { 1, 2, 3 })
    	run_benchmark(nanolog_benchmark, threads);

    return 0;
}


