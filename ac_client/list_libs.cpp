#include <iostream>
#include <vector>
#include <string>
#include <mach-o/dyld.h>

void listLoadedLibraries() {
    uint32_t count = _dyld_image_count(); // Get the number of loaded images (libraries)
    
    std::cout << "Loaded Libraries:\n";
    for (uint32_t i = 0; i < count; i++) {
        const char* image_name = _dyld_get_image_name(i);
        if (image_name) {
            std::cout << image_name << std::endl;
        }
    }
}

int main() {
    std::cout << "Listing all loaded libraries for the current process:\n";
    listLoadedLibraries();
    return 0;
}
