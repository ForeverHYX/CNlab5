CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -pedantic -pthread
LDFLAGS ?= -pthread
INCLUDES = -I../shared
SOURCES = client.cpp ../shared/protocol.cpp
TARGET = lab05_client

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
