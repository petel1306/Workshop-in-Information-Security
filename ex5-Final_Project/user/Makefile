OBJECTS = interface.c rules_handler.c log_handler.c conn_handler.c user.c

all: $(OBJECTS)
	gcc -O3 -Wall -std=c11 -o main $(OBJECTS)
clean:
	$(RM) main