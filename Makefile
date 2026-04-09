CC ?= cc
CFLAGS ?= -Wall -std=c11
LDFLAGS ?=
TARGET := bic
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
SECPDIR := secp256k1
SECPLIB := $(SECPDIR)/.libs/libsecp256k1.a
SECPINC := $(SECPDIR)/include

all: $(TARGET)

$(TARGET): $(OBJS) $(SECPLIB)
	$(CC) $^ $(LDFLAGS) -o $@

$(OBJS): | $(SECPLIB)

%.o: %.c
	$(CC) $(CFLAGS) -I$(SECPINC) -c $< -o $@

$(SECPLIB):
	@if [ ! -f $(SECPDIR)/autogen.sh ]; then \
	  echo "error: run 'git submodule update --init' first"; exit 1; \
	fi
	cd $(SECPDIR) && ./autogen.sh && \
	./configure \
		--enable-static \
		--disable-shared \
		--disable-tests \
		--disable-benchmark && \
	$(MAKE)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
