CXX      := g++
CXXFLAGS := -g -std=c++17 -Wall -Wextra -Iinclude -DSODIUM_STATIC

CC       := gcc
CFLAGS   := -g -Wall -Wextra -Iinclude -DSODIUM_STATIC

LDFLAGS  := libs/libsodium.a -pthread

OBJ_DIR  := obj
SRC_DIR  := src
TARGET   := vault

# 1. SRCS finds files in src/ (e.g. src/main.cpp, src/disk.cpp)
CPP_SRCS     := $(wildcard $(SRC_DIR)/*.cpp)
C_SRCS     := $(wildcard $(SRC_DIR)/*.c)

# 2. OBJS maps src/file.cpp to obj/file.o
OBJS     := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(CPP_SRCS)) \
			$(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(C_SRCS))

all: $(TARGET)

# Linking step: Always use $(CXX) when mixing C and C++ objects!
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

# Pattern rule: compiles C++ files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Pattern rule: compiles C files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Order-only rule to automatically create the obj directory
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean