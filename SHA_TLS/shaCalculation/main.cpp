#include <iostream>

#include "sha1.h"
using namespace std;


int main() {
    std::string auth = "vJKwwHCzrRjMSPoDXLPUkUMHoKvxlHrUADyUNBSXalLlHLcYPKRTRzoALeYowVsO";
	string result = calculateSuffix(auth);
	cout << "the result is: " << result << endl;


	return 0;
}