CXX := g++
CXXFLAGS := -Ofast -std=c++20 -lcryptopp -fopenmp -mpclmul -no-pie 

TARGET := build/s3pir
INCLUDE := src/include
TROY_INCLUDE := encryption
TROY_LIB := encryption/libtroy.so

CUDA_INCLUDE := -I/usr/local/cuda/include
CUDA_LIB := -L/usr/local/cuda/lib64 -lcudart

OT_LIB_DIR := -L/usr/local/lib
OT_LIBS := -l:liblibOTe.a -lSimplestOT -lcryptoTools -lcoproto -lsodium -lpthread

SRC := src/client.cpp src/server.cpp src/main.cpp src/utils.cpp
NEW_SRC := src/new_client.cpp src/new_server.cpp src/new_main.cpp src/utils.cpp

SERVER_SRC := src/server.cpp src/server_main.cpp src/utils.cpp src/network.cpp
CLIENT_SRC := src/client.cpp src/client_main.cpp src/server.cpp src/utils.cpp src/network.cpp

DEPS := src/include/client.h src/include/server.h src/include/utils.h $(TROY_INCLUDE)/troy.h
NEW_DEPS := src/include/new_client.h src/include/new_server.h src/include/utils.h $(TROY_INCLUDE)/troy.h
NETWORK_DEPS := src/include/network.h $(DEPS)

all: $(TARGET) $(TARGET)_simlargeserver build/s3pir_server build/s3pir_client

debug: $(TARGET)_debug

clean: 
	rm -f build/*

.PHONY: all clean debug

$(TARGET): $(SRC) $(DEPS)
	$(CXX) -o $(TARGET) -I $(INCLUDE) -I $(TROY_INCLUDE) $(CUDA_INCLUDE) $(SRC) $(CXXFLAGS) $(TROY_LIB) $(CUDA_LIB) $(OT_LIB_DIR) $(OT_LIBS)

$(TARGET)_debug: $(SRC) $(DEPS)
	$(CXX) -DDEBUG -o $(TARGET)_debug -I $(INCLUDE) -I $(TROY_INCLUDE) $(CUDA_INCLUDE) $(SRC) $(CXXFLAGS) $(TROY_LIB) $(CUDA_LIB) $(OT_LIB_DIR) $(OT_LIBS)

$(TARGET)_simlargeserver: $(SRC) $(DEPS)
	$(CXX) -DSimLargeServer -o $(TARGET)_simlargeserver -I $(INCLUDE) -I $(TROY_INCLUDE) $(CUDA_INCLUDE) $(SRC) $(CXXFLAGS) $(TROY_LIB) $(CUDA_LIB) $(OT_LIB_DIR) $(OT_LIBS)

new_$(TARGET): $(NEW_SRC) $(NEW_DEPS)
	$(CXX) -o new_$(TARGET) -I $(INCLUDE) -I $(TROY_INCLUDE) $(CUDA_INCLUDE) $(NEW_SRC) $(CXXFLAGS) $(TROY_LIB) $(CUDA_LIB) $(OT_LIB_DIR) $(OT_LIBS)

build/s3pir_server: $(SERVER_SRC) $(NETWORK_DEPS)
	$(CXX) -o build/s3pir_server -I $(INCLUDE) -I $(TROY_INCLUDE) $(CUDA_INCLUDE) $(SERVER_SRC) $(CXXFLAGS) $(TROY_LIB) $(CUDA_LIB) $(OT_LIB_DIR) $(OT_LIBS)

build/s3pir_client: $(CLIENT_SRC) $(NETWORK_DEPS)
	$(CXX) -o build/s3pir_client -I $(INCLUDE) -I $(TROY_INCLUDE) $(CUDA_INCLUDE) $(CLIENT_SRC) $(CXXFLAGS) $(TROY_LIB) $(CUDA_LIB) $(OT_LIB_DIR) $(OT_LIBS)
