C_FLAGS = -g -Wall -Werror -Wno-unused-function
CXX_FLAGS = $(C_FLAGS) -std=c++11
OBJS = tcp.o checksum.o

%.o: %.cc *.h
	g++ $(CXX_FLAGS) $< -o $@ -c

%.o: %.c *.h
	gcc $(C_FLAGS) $< -o $@ -c

tcp: $(OBJS)
	g++ checksum.o $(FLAGS) $^ -o $@ checksum.o

.PHONY: run
run: tcp
	sudo ./tcp

.PHONY: clean
clean:
	-rm -rf $(OBJS) tcp
