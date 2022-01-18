#include <iostream>
#include <fstream>
#include <experimental/filesystem>

int main()
{
    std::ifstream in_file;
	in_file.open("./../data/in_str.txt", std::ios::binary);
    std::size_t file_size = std::experimental::filesystem::file_size("./../data/in_str.txt");
    int padding = file_size % 16;
    char file_buf[file_size+padding];

    in_file.read(file_buf, file_size);

	std::string text;
	if(!in_file.is_open())
	{
		std::cout<<"file not open\n";
	}

    std::cout<<"file size is "<<file_size<<"\n";
	// }
	in_file.close();

    std::ofstream out_file;
    out_file.open("./../data/out_str.txt", std::ios::binary);
    out_file.write(file_buf, file_size);
    out_file.close();

    return 0;
}