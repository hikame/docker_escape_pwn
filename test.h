#include "kaslr_bypass.h"

void test(){
    locate_first_writable();
    exit(0);
}