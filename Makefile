all: attack

CXX ?= g++
CXXFLAGS ?= -O3 -march=native

attack: attack.cpp
	$(CXX) -std=c++17 $(CXXFLAGS) attack.cpp -o attack

clean:
	rm attack
	