#pragma once
#include <winsock2.h>

// Network hook management
bool InstallNetworkHooks();
void UninstallNetworkHooks();
void SetForceOfflineNetwork(bool enable);
