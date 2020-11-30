OBJECTS = interface.c rules_handler.c log_handler.c user.c

all: $(OBJECTS)
	gcc -O0 -Wall -std=c11 -g -o main $(OBJECTS)
clean:
	$(RM) main