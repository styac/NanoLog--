all: 
	g++ -g -O3 -std=c++17 -pthread NanoLog.cpp test.cpp -o test
	g++ -g -O3 -std=c++17 -pthread NanoLog.cpp non_guaranteed_nanolog_benchmark.cpp -o non_guaranteed_nanolog_benchmark
#	g++ -g -O3 -std=c++17 -pthread NanoLog.cpp guaranteed_nanolog_benchmark.cpp -o guaranteed_nanolog_benchmark
