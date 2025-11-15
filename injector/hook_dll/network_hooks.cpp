#include "network_hooks.h"
#include "logging.h"
#include <ws2tcpip.h>
#include <stdio.h>
// Note: winsock2.h is already included in network_hooks.h
// windows.h is NOT needed here as it conflicts with winsock2.h

static bool g_forceOfflineNetwork = true;

void SetForceOfflineNetwork(bool enable) {
    g_forceOfflineNetwork = enable;
}

static void DescribeSocketAddress(const sockaddr* name, int namelen, wchar_t* buffer, size_t bufferCount) {
    if (!buffer || bufferCount == 0) {
        return;
    }
    buffer[0] = 0;
    if (!name) {
        wcsncpy_s(buffer, bufferCount, L"(null)", _TRUNCATE);
        return;
    }
    switch (name->sa_family) {
    case AF_INET:
        if (namelen >= (int)sizeof(sockaddr_in)) {
            const sockaddr_in* ipv4 = reinterpret_cast<const sockaddr_in*>(name);
            wchar_t addr[64] = L"";
            if (InetNtopW(AF_INET, const_cast<IN_ADDR*>(&ipv4->sin_addr), addr, _countof(addr)) == NULL) {
                wcsncpy_s(addr, _countof(addr), L"<inet_ntop failed>", _TRUNCATE);
            }
            USHORT port = ntohs(ipv4->sin_port);
            swprintf_s(buffer, bufferCount, L"%s:%u (IPv4)", addr, port);
            return;
        }
        break;
    case AF_INET6:
        if (namelen >= (int)sizeof(sockaddr_in6)) {
            const sockaddr_in6* ipv6 = reinterpret_cast<const sockaddr_in6*>(name);
            wchar_t addr[80] = L"";
            if (InetNtopW(AF_INET6, const_cast<IN6_ADDR*>(&ipv6->sin6_addr), addr, _countof(addr)) == NULL) {
                wcsncpy_s(addr, _countof(addr), L"<inet_ntop failed>", _TRUNCATE);
            }
            USHORT port = ntohs(ipv6->sin6_port);
            swprintf_s(buffer, bufferCount, L"[%s]:%u (IPv6)", addr, port);
            return;
        }
        break;
    default:
        break;
    }
    swprintf_s(buffer, bufferCount, L"family=%d, len=%d", name->sa_family, namelen);
}

#ifdef USE_DETOURS
#include <detours.h>

static int (WINAPI* Real_connect)(SOCKET, const sockaddr*, int) = connect;

int WINAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen) {
    wchar_t dest[160];
    DescribeSocketAddress(name, namelen, dest, _countof(dest));
    wchar_t msg[256];
    swprintf_s(msg, 256, L"[NET] connect requested -> %s", dest);
    LogMessage(msg);

    if (g_forceOfflineNetwork) {
        LogMessage(L"[NET] Simulating offline environment, forcing failure");
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }

    int result = Real_connect(s, name, namelen);
    if (result == SOCKET_ERROR) {
        swprintf_s(msg, 256, L"[NET] connect failed (err=%d)", WSAGetLastError());
    } else {
        swprintf_s(msg, 256, L"[NET] connect succeeded (socket=%p)", s);
    }
    LogMessage(msg);
    return result;
}

bool InstallNetworkHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)Real_connect, Hook_connect);

    LONG error = DetourTransactionCommit();
    return (error == NO_ERROR);
}

void UninstallNetworkHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)Real_connect, Hook_connect);

    DetourTransactionCommit();
}

#else

bool InstallNetworkHooks() {
    LogMessage(L"[WARNING] Detours not enabled, network hook unavailable");
    return true;
}

void UninstallNetworkHooks() {}

#endif
