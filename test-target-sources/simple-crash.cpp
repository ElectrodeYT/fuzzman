// Taken from Fuzzing-Module exercise 1.
// https://github.com/alex-maleno/Fuzzing-Module/blob/main/exercise1/simple_crash.cpp

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

int main() {

   string str;

   cout << "enter input string: ";
   getline(cin, str);
   cout << str << endl << str [0] << endl;

    if(str[0] == 0 || str[str.length() - 1] == 0) {
        abort();
    }
    else {
        int count = 0;
        char prev_num = 'x';
        while (count != str.length() - 1) {
            char c = str[count];
            if(c >= 48 && c <= 57) {
                if(c == prev_num + 1) {
                    abort();
                }
                prev_num = c;
            }
            count++;
        }
    }

    return 0;
}