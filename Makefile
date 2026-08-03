CXX      := g++
CXXFLAGS := -g -std=c++17 -Wall -Wextra -Iinclude -DSODIUM_STATIC
LDFLAGS  := libs/libsodium.a -pthread

OBJ_DIR  := obj
SRC_DIR  := src
TARGET   := vault

# 1. SRCS finds files in src/ (e.g. src/main.cpp, src/disk.cpp)
SRCS     := $(wildcard $(SRC_DIR)/*.cpp)

# 2. OBJS maps src/file.cpp to obj/file.o
OBJS     := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

all: $(TARGET)

# Linking step: links obj/*.o files into the final executable
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

# Pattern rule: compiles src/%.cpp into obj/%.o
# | $(OBJ_DIR) creates the obj folder before running compiler if missing
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Order-only rule to automatically create the obj directory
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean rule: deletes the entire obj directory and executable
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean