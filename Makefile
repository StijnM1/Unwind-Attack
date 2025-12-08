all: attack

CXX ?= g++
CXXFLAGS ?= -O3 -march=native

attack: attack.cpp
	$(CXX) -std=c++20 $(CXXFLAGS) attack.cpp -o attack

clean:
	rm attack
	