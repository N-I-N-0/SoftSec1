from pwn import *
import string
from sys import argv
import os


context.arch = 'amd64'
info = log.info
#context.log_level = 'debug'

p = remote("tasks.ws24.softsec.rub.de", 32849)



known_answers = {
"Which syscall do you use for executing programs": "execve",
"Reverse Engineering (RE) is the process of analyzing a system to:": "identify its components and their interrelationships, and create representations of it in another form or at a higher level.",
"Which of these is the architecture that considers code as being the same as data":"von Neumann architecture",
"How is the number 1337 stored in memory (as a 32-bit value)?": "39050000",
"What idiom represents the same as multiplying a number by 2.": "shl rax, 1",
"When you find a bug lying around in a big company that your government runs. What would be the ethical response to this?": "Try to find a contact for responsible disclosure",
"What is the name of the well-known debugger from the GNU project?": "gdb",
"What is the Linux utility that helps track down which syscalls were invoked by a program?":"strace",
"How are arguments passed to system calls in Linux on x86_64?":"rdi / rsi / rdx / r10 / r8 / r9",
"How are integer arguments passed to functions in Linux on x86_64?": "rdi / rsi / rdx / rcx / r8 / r9, and the rest on the stack",
"Consider `int foo = INT_MAX`. What would be the value of foo if you add 1 to foo?": "-2147483648",
"What is the mechanism's name that ensures the stack does not contain code?": "NX"
}


def parse_single_question_via_recvline(connection):
    # Receive the first line as the question
    question = connection.recvline().strip().decode()
    print(question)
    
    # Receive the next four lines as the answers
    answers = []
    for _ in range(4):
        answer = connection.recvline().strip().decode()
        print(answer)
        answers.append(answer)
    
    print(p.recvuntil(b"> ").decode(), end="")
    
    # Return the question and answers as a dictionary
    return question, answers

def find_right_number(answers, known_answer):
    for i, a in enumerate(answers):
        if a[4:].startswith(known_answer):
            return i+1

print(p.recvline().decode())
for i in range(12):
    question, answers = parse_single_question_via_recvline(p)
    if question in known_answers:
        num = find_right_number(answers, known_answers[question])
        p.sendline(str(num).encode())
        print(num)
    p.recvline()

print(p.recvline().decode()) #softsec{oYRYvJyESbRgi_OMH2UByNBLIScSlIJzgRUlYn4SQ-ThGSL-skj7DkAbsJunO_t_}