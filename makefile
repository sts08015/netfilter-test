all: netfilter-test

netfilter-test:
	g++ netfilter-test.cpp -o netfilter-test -lnetfilter_queue

clean:
	rm -f ./netfilter-test
