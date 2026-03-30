#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;

#endif