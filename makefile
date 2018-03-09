FLAGS = -g -Wall -Werror
OBJS = tcp.o

%.o: %.cc *.h
	g++ -c $(FLAGS) $^ -o $@

tcp: $(OBJS)
	g++ $(FLAGS) $(OBJS) -o $@

.PHONY: run
run: tcp
	sudo ./tcp

.PHONY: clean
clean:
	-rm -rf $(OBJS) tcp
