sources := $(wildcard *.cpp)
objects := $(sources: %.cpp=/%.o)
CC := g++
LIBS := -I./headers
gpu: 
	nvcc -arch=sm_50 -I../../../../common/inc $(LIBS) sources/main.cu -o gpu.o
test: $(objects)
	$(CC) $(objects) $(LIBS) -o AES -lm
$(objects): $(sources)
	$(CC) -c $(sources) $(LIBS) $@
clean:
	 rm -f *.o
