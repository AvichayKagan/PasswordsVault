CXX      := g++
# Added -MMD and -MP to automatically generate .d files
CXXFLAGS := -g -std=c++17 -Wall -Wextra -Iinclude -DSODIUM_STATIC -MMD -MP

CC       := gcc
# Added -MMD and -MP to automatically generate .d files
CFLAGS   := -g -Wall -Wextra -Iinclude -DSODIUM_STATIC -MMD -MP

LDFLAGS  := libs/libsodium.a -pthread

OBJ_DIR  := obj
SRC_DIR  := src
TARGET   := vault

# 1. SRCS finds files in src/
CPP_SRCS := $(wildcard $(SRC_DIR)/*.cpp)
C_SRCS   := $(wildcard $(SRC_DIR)/*.c)

# 2. OBJS maps src/file.cpp to obj/file.o
OBJS     := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(CPP_SRCS)) \
            $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(C_SRCS))

# 3. DEPS maps obj/file.o to obj/file.d
DEPS     := $(OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# 4. Include the dependency files so Make knows about the headers
-include $(DEPS)

.PHONY: all clean