#include <libssh2.h>

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <unistd.h>
#endif

#include <iostream>
#include <string>
#include <cstdlib>

namespace
{
	constexpr const char* HOSTNAME = "127.0.0.1";
	constexpr const char* USERNAME = "todo1";
	constexpr const char* PASSWORD = "todo2";
	constexpr const char* COMMAND = "ls -la";
}

void bail(const std::string& message)
{
	std::cout << message << "\n\n\n";
	abort();
}

void initializeSsh()
{
    auto status = libssh2_init(0);
    if (status)
    {
    	bail("failed to init libssh2, return code = " + std::to_string(status));
    }
}

auto getEndpoint()
{
    sockaddr_in endpoint{};
    
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(22);
    endpoint.sin_addr.s_addr = inet_addr(HOSTNAME);

    return endpoint;
}

auto getConnectedSocket()
{	
    const auto socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (0 == socketDescriptor || -1 == socketDescriptor)
    {
    	bail("failed to open socket");
    }

    const auto endpoint = getEndpoint();
    if (connect(socketDescriptor, reinterpret_cast<const sockaddr*>(&endpoint), sizeof (endpoint)) < 0)
    {
    	bail("failed to connect to endpoint");
    }

    return socketDescriptor;
}

auto getSshSession()
{
	auto sshSession = libssh2_session_init();
    if (!sshSession)
    {
    	bail("failed to initialize SSH session");
    }

    return sshSession;
}

auto getSshChannel(LIBSSH2_SESSION* sshSession)
{
	auto* sshChannel = libssh2_channel_open_session(sshSession);
	if (!sshChannel)
	{
		bail("failed to initialize SSH channel");
	}

	return sshChannel;
}

void performHandshake(LIBSSH2_SESSION* sshSession, int socketDescriptor)
{
    auto result = libssh2_session_handshake(sshSession, socketDescriptor);
    if (result)
    {
    	bail("failed to handshake with the SSH server, reason = " + std::to_string(result));
    }
}

void performAuthentication(LIBSSH2_SESSION* sshSession)
{
	auto result = libssh2_userauth_password(sshSession, USERNAME, PASSWORD);
    if (result)
    {
    	bail("failed to authenticate (probably bad pwd), reason = " + std::to_string(result));
    }
}

void executeCommand(LIBSSH2_CHANNEL* sshChannel)
{
	auto result = libssh2_channel_exec(sshChannel, COMMAND);
    if (result)
    {
    	bail("failed to execute command, reason = " + std::to_string(result));
    }
}

void readCommandResult(LIBSSH2_CHANNEL* sshChannel)
{	
	char readBuffer[5000];
	std::size_t readSize = 1;

	while (readSize > 0)
	{
		readSize = libssh2_channel_read(sshChannel, readBuffer, sizeof (readBuffer));
		if (readSize > 0)
		{
			std::cout << std::string{readBuffer, readSize} << "\n\n";
		}
	}
}

void closeAndCleanup(LIBSSH2_SESSION* sshSession, LIBSSH2_CHANNEL* sshChannel, int socketDescriptor)
{
	libssh2_channel_close(sshChannel);

    libssh2_channel_free(sshChannel);
 
    libssh2_session_disconnect(sshSession, "");

    libssh2_session_free(sshSession);

    close(socketDescriptor);
 
    libssh2_exit();
}

int main(int argc, char *argv[])
{
	initializeSsh();

    auto socketDescriptor = getConnectedSocket();
    auto* sshSession = getSshSession();

    performHandshake(sshSession, socketDescriptor);
    performAuthentication(sshSession);

    auto* sshChannel = getSshChannel(sshSession);
    executeCommand(sshChannel);
    readCommandResult(sshChannel);

    closeAndCleanup(sshSession, sshChannel, socketDescriptor);

    return 0;
}
