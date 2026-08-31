MAKEFLAGS += -j12

CXX      := g++
# Added -MMD and -MP to automatically generate .d files
CXXFLAGS := -g -std=c++20 -Wall -Wextra -Iinclude -DSODIUM_STATIC -MMD -MP

CC       := gcc
# Added -MMD and -MP to automatically generate .d files
CFLAGS   := -g -Wall -Wextra -Iinclude -DSODIUM_STATIC -MMD -MP

LDFLAGS  := libs/libsodium.a -pthread

OBJ_DIR  := obj
SRC_DIR  := src
TARGET   := vault

# 1. Use the 'find' shell command to recursively find all .cpp and .c files in subdirectories
CPP_SRCS := $(shell find $(SRC_DIR) -name '*.cpp')
C_SRCS   := $(shell find $(SRC_DIR) -name '*.c')

# 2. OBJS maps src/path/to/file.cpp to obj/path/to/file.o
OBJS     := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(CPP_SRCS)) \
            $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(C_SRCS))

# 3. DEPS maps obj/path/to/file.o to obj/path/to/file.d
DEPS     := $(OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

# Automatically create the specific subdirectory inside obj/ before compiling
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# 4. Include the dependency files so Make knows about the headers
-include $(DEPS)

.PHONY: all clean