C_FLAGS = -g -Wall -Werror -Wno-unused-function -DDEBUG
CXX_FLAGS = $(C_FLAGS) -std=c++11

.PHONY: all
all: wget

%.o: %.cc *.h
	g++ $(CXX_FLAGS) $< -o $@ -c
%.o: %.c *.h
	gcc $(C_FLAGS) $< -o $@ -c

# libtcp
LIBTCP_OBJS = libtcp.o checksum.o
libtcp.a: $(LIBTCP_OBJS)
	ar rcs $@ $^

# example program
WGET_OBJS = wget.o libtcp.a
wget: $(WGET_OBJS)
	g++ $(CXX_FLAGS) $^ -o $@

.PHONY: run
run: wget
	sudo ./wget

.PHONY: clean
clean:
	-rm -rf $(LIBTCP_OBJS) $(WGET_OBJS) wget
