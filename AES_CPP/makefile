sources := $(wildcard sources/*.cpp)
objects := $(sources: sources/%.cpp=/%.o)
CC := g++
LIBS := -I./headers
main: $(objects)
	$(CC) $(objects) $(LIBS) -o AES -lm
$(objects): $(sources)
	$(CC) -c $(sources) $(LIBS) $@
clean:
	 rm -f *.o
