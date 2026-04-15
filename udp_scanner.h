#pragma once
#include <string>

// Returns the secret key as a 16-byte string, and sets foundPort.
// Returns empty string if no open port found.
std::string scanUDP(int groupNumber, int &foundPort);