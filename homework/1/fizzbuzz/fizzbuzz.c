#include <stdint.h>

void magic(uint32_t* ptr) {
	for(int i = 0; i < 2048; i++) {
		if ((ptr[i] % 3) == 0) {
			if ((ptr[i] % 5) == 0) {
				ptr[i] = 2;
			} else {
				ptr[i] = 0;
			}
		} else if ((ptr[i] % 5) == 0) {
			ptr[i] = 1;
		} else {
			ptr[i] = 3;
		}
	}
}


void main() {
	uint32_t test[2048];
	magic(test);
}