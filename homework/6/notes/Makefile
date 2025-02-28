RELRO_FLAGS = -Wl,-z,relro,-z,now
FORTIFY_FLAGS = -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS=1
STACK_FLAGS = -fstack-protector-all -fstack-clash-protection
CET_FLAGS = -fcf-protection
CXX_FLAGS = -fno-rtti -fno-exceptions -g -O2 $(if $(CXX_23_NOT_SUPPORTED),-std=c++2b,-std=c++23)
W_FLAGS = -Wall -Wextra -Wpedantic -Werror

vuln: vuln.cpp
	$(CXX) $(RELRO_FLAGS) $(FORTIFY_FLAGS) $(STACK_FLAGS) $(CET_FLAGS) $(CXX_FLAGS) $(W_FLAGS) $^ -o $@

clean:
	$(RM) vuln vuln-debug

.PHONY: clean

