CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib -lssl -lcrypto -lpthread


# Source files
SOURCES = main.cpp
TARGET = client

# Default target
all: $(TARGET)

# Compile the client
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

# Install dependencies (macOS)
install-deps:
	brew install openssl nlohmann-json

# Clean build files
clean:
	rm -f $(TARGET)

# Run the client
run: $(TARGET)
	./$(TARGET)

# Install OpenSSL on macOS if not present
install-openssl:
	brew install openssl

.PHONY: all clean run install-deps install-openssl 