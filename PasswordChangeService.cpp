#include <string>
#include <iostream>
#include <cstdlib>
#include <chrono>
#include <thread>
using namespace std;

void main()
{
	string scriptPath = "C:\\Users\\Administrator\\Desktop\\Scripts\\pwChange.ps1"; // Double slashes because of Windows formatting

	std::chrono::seconds timespan(3600);
	std::this_thread::sleep_for(timespan); // sleep for 1 hour

	int randomNum = rand() % 11; // random number between 1-10

	if (randomNum > 8) // 20% chance
	{
		string cmd = "powershell -ep bypass -F " + scriptPath; // run the script to change a user's PW
		system(cmd.c_str()); // convert to an array of characters because that's how system handles string, and since we're concatenating we need to specify
	}
}