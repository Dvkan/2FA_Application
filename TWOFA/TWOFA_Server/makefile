#compiler
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -std=c11 -Iinclude
CXXFLAGS = -Wall -Wextra -std=c++11 -Iinclude

#variables
SRCDIR = src
INCDIR = include
BUILDDIR = build
TARGET = server

# Sources and objects for C and C++ files
CSOURCES = $(wildcard $(SRCDIR)/*.c)
CXXSOURCES = $(wildcard $(SRCDIR)/*.cpp)
COBJECTS = $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(CSOURCES))
CXXOBJECTS = $(patsubst $(SRCDIR)/%.cpp, $(BUILDDIR)/%.o, $(CXXSOURCES))
OBJECTS = $(COBJECTS) $(CXXOBJECTS)

#ruleset
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CFLAGS) $(CXXFLAGS) -o $@ $^ -lssl -lcrypto -lsqlite3

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILDDIR) $(TARGET)
