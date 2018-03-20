# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	load_balancer load_balancer-b
LIBNETMAP =

CLEANFILES = $(PROGS) *.o

SRCDIR ?= ../..
VPATH = $(SRCDIR)/apps/load_balancer

NO_MAN=
CFLAGS = -O2 -pipe
#CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -I $(SRCDIR)/sys -I $(SRCDIR)/apps/include
#CFLAGS += -Wextra

LDLIBS += -lpthread
ifeq ($(shell uname),Linux)
	LDLIBS += -lrt	# on linux
endif

PREFIX ?= /usr/local

all: $(PROGS)

clean:
	-@rm -rf $(CLEANFILES)

.PHONY: install
install: $(PROGS:%=install-%)

install-%:
	install -D $* $(DESTDIR)/$(PREFIX)/bin/$*

load_balancer-b: load_balancer-b.o

load_balancer-b.o: load_balancer.c
	$(CC) $(CFLAGS) -DBUSYWAIT -c $^ -o $@
