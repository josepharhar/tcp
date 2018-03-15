C_FLAGS = -g -Wall -Werror -Wno-unused-function
CXX_FLAGS = $(C_FLAGS) -std=c++11

%.o: %.cc *.h
	g++ $(CXX_FLAGS) $< -o $@ -c

%.o: %.c *.h
	gcc $(C_FLAGS) $< -o $@ -c

# libtcp

LIBTCP_OBJS = libtcp.o checksum.o

libtcp.a: $(LIBTCP_OBJS)
	ar rcs $@ $^

# example program

WGET_OBJS = wget.o

wget: libtcp.a wget.o
	g++ $(CXX_FLAGS) $^ -o $@

#tcp: $(OBJS)
#	g++ $(FLAGS) $^ -o $@

.PHONY: run
run: tcp
	sudo ./tcp

.PHONY: clean
clean:
	-rm -rf $(LIBTCP_OBJS) $(WGET_OBJS) libtcp.a tcp wget
