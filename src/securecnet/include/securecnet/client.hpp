#pragma once
#include "securecnet/io_context.hpp"
#include "securecnet/message.hpp"
#include "securecnet/packet.hpp"
#include "securecnet/result.hpp"
#include "securecnet/socket_init.hpp"
#include "securecnet/udp_socket.hpp"

#include <array>
#include <functional>
#include <cstdint>
#include <deque>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace scn {

    class Client : private IoContextService {
    public:
        using OnPacketFn = std::function<void(const PacketView&)>;
        using OnMessageFn = std::function<void(const MsgView&)>;

        Client() = default;
        explicit Client(IoContext& ctx);
        ~Client();

        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        Result start(const Endpoint& server) {
            return connect(server);
        }

        Result connect(const Endpoint& server);
        Result connect(std::string_view host, std::string_view port);
        Result connect(std::string_view host, U16 port);
        void stop();

        Result tick();

        Result send_payload(const U8* data, ST len);
        Result send_payload(std::span<const U8> payload);
        Result send_message(Channel channel, U8 type, const void* data, U16 len);
        Result send(Channel channel, U8 type, std::span<const U8> payload);
        Result send_text(U8 type, std::string_view text);
        Result local_endpoint(Endpoint& out) const;

        void on_packet(OnPacketFn fn) { _on_packet = std::move(fn); }
        void on_message(OnMessageFn fn) { _on_message = std::move(fn); }

    private:
        struct PendingPacket {
            std::array<U8, NetConfig::MaxPacketBytes> bytes{};
            ST len{ 0 };
        };

        Result context_poll() override;
        Result runtime_status() const;
        Result queue_payload(const U8* data, ST len);
        Result flush_pending();
        Result pump_receive();
        void dispatch_packet_inline(const U8* data, ST len);
        void dispatch_packet_deferred(std::vector<U8> data);

        IoContext* _ctx{ nullptr };
        SocketInit _runtime{};
        UdpSocket _sock{};
        Endpoint _server{};

        U64 _conn_id{ 0xC1E17u }; // placeholder, real ID from handshake
        U64 _seq{ 1 };

        OnPacketFn _on_packet{};
        OnMessageFn _on_message{};
        U8 _rxbuf[NetConfig::MaxPacketBytes]{};
        std::deque<PendingPacket> _pending{};
    };

}
