# Makefile for Python version of pbl_dat_dump

.PHONY: all clean install

all: check_libs

check_libs:
	@echo "Checking for libpbl.so..."
	@if [ ! -f "./src/libpbl.so" ]; then \
		echo "Warning: libpbl.so not found in current directory. Please ensure it's available."; \
	else \
		echo "libpbl.so found"; \
	fi

install:
	pip install -e .

clean:
	rm -rf __pycache__ *.pyc *.egg-info build dist

