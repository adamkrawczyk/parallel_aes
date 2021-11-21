#!/bin/bash

if [ ! -d $1 ]; then
    echo "Katalog nie istnieje"
    exit 1
fi
rm makefile
cd "$1"

mainFile=""

for f in *.cpp; do
	if grep -q "main" $f; then
		mainFile=${f/.cpp/}
	fi
done



cd ..

echo 'sources := $(wildcard sources/*.cpp)' >> makefile
echo 'objects := $(sources: sources/%.cpp=/%.o)' >> makefile
echo 'CC := g++' >> makefile
echo 'LIBS := -I./headers' >> makefile


echo $mainFile: '$(objects)' >> makefile
echo -e '\t$(CC) $(objects) $(LIBS) -o AES -lm' >> makefile

echo '$(objects): $(sources)'>> makefile
echo -e '\t$(CC) -c $(sources) $(LIBS) $@'>> makefile

echo 'clean:' >> makefile
echo -e '\t rm -f *.o'  >> makefile