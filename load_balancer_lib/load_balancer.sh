rm -f load_balancer
rm -f load_balancer.o && g++ -I ../../../sys/ -c -fpermissive -std=c++11 load_balancer.cpp
rm -f lib.o && g++ -I ../../../sys/ -c -fpermissive -std=c++11 lib.cpp
g++ -o load_balancer lib.o load_balancer.o -lboost_system
rm -f load_balancer.o
rm -f lib.o
