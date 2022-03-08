GXX = g++
PROJEKT = ipk-sniffer

CXXFLAGS = -lpcap

SOURCE = ipk-sniffer.cpp

all: $(PROJEKT)
$(PROJEKT):$(SOURCE)
	$(GXX) $(SOURCE) -lpcap -o $(PROJEKT)

clean:
	rm -f* .o* .out$(PROJEKT)


