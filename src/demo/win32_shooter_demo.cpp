#if !defined(_WIN32)
#error securecnet_win32_shooter is Windows-only and uses the Win32 API directly.
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <shellapi.h>
#include <windowsx.h>

#include "securecnet/scn.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using I16 = std::int16_t;
using U8 = std::uint8_t;
using U16 = std::uint16_t;
using U32 = std::uint32_t;
using U64 = std::uint64_t;

constexpr int kTimerId = 1;
constexpr int kFrameMs = 16;
constexpr float kWorldWidth = 900.0f;
constexpr float kWorldHeight = 600.0f;
constexpr int kMaxPlayers = 8;
constexpr int kMaxBullets = 32;
constexpr U8 kMsgInput = 80;
constexpr U8 kMsgWelcome = 81;
constexpr U8 kMsgSnapshot = 82;
constexpr U16 kDefaultPort = 27015;

struct Vec2 {
    float x{ 0.0f };
    float y{ 0.0f };
};

#pragma pack(push, 1)
struct WireClientInput {
    float move_x{ 0.0f };
    float move_y{ 0.0f };
    float aim_x{ 0.0f };
    float aim_y{ 0.0f };
    U32 client_tick{ 0 };
    U8 buttons{ 0 };
    U8 reserved0{ 0 };
    U8 reserved1{ 0 };
    U8 reserved2{ 0 };
};

struct WireWelcome {
    U32 player_id{ 0 };
};

struct WirePlayer {
    U32 id{ 0 };
    float x{ 0.0f };
    float y{ 0.0f };
    float angle{ 0.0f };
    I16 hp{ 100 };
    U8 alive{ 0 };
    U8 score{ 0 };
};

struct WireBullet {
    U32 owner_id{ 0 };
    float x{ 0.0f };
    float y{ 0.0f };
    float vx{ 0.0f };
    float vy{ 0.0f };
    U8 alive{ 0 };
    U8 pad0{ 0 };
    U8 pad1{ 0 };
    U8 pad2{ 0 };
};

struct WireSnapshot {
    U32 server_tick{ 0 };
    U8 player_count{ 0 };
    U8 bullet_count{ 0 };
    U8 reserved0{ 0 };
    U8 reserved1{ 0 };
    WirePlayer players[kMaxPlayers]{};
    WireBullet bullets[kMaxBullets]{};
};
#pragma pack(pop)

static_assert(sizeof(WireSnapshot) < scn::NetConfig::MaxSequencedMessageBytes,
    "Shooter snapshot must fit a single sequenced message packet.");

bool key_down(int vk) {
    return (GetAsyncKeyState(vk) & 0x8000) != 0;
}

float length(Vec2 v) {
    return std::sqrt(v.x * v.x + v.y * v.y);
}

Vec2 normalize(Vec2 v) {
    const float len = length(v);
    if (len <= 0.0001f) {
        return {};
    }
    return { v.x / len, v.y / len };
}

float clampf(float value, float lo, float hi) {
    return std::max(lo, std::min(value, hi));
}

template <class T>
std::span<const U8> bytes_of(const T& value) {
    return std::span<const U8>(reinterpret_cast<const U8*>(&value), sizeof(T));
}

template <class T>
bool read_wire(const scn::MsgView& msg, T& out) {
    if (msg.len != sizeof(T) || msg.data == nullptr) {
        return false;
    }
    std::memcpy(&out, msg.data, sizeof(T));
    return true;
}


const char* view_chars(std::string_view text) {
    return text.empty() ? "" : text.data();
}

std::string narrow(const wchar_t* text) {
    if (text == nullptr || *text == L'\0') {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return {};
    }
    std::string out(static_cast<std::size_t>(needed - 1), '\0');
    (void)WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

void draw_text(HDC dc, int x, int y, COLORREF color, std::string_view text) {
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    TextOutA(dc, x, y, text.data(), static_cast<int>(text.size()));
}

class GdiObject final {
public:
    explicit GdiObject(HGDIOBJ handle = nullptr) : _handle(handle) {}
    ~GdiObject() {
        if (_handle != nullptr) {
            DeleteObject(_handle);
        }
    }

    GdiObject(const GdiObject&) = delete;
    GdiObject& operator=(const GdiObject&) = delete;

    HGDIOBJ get() const { return _handle; }

private:
    HGDIOBJ _handle{ nullptr };
};

struct ServerPlayer {
    bool active{ false };
    U32 id{ 0 };
    U64 conn_id{ 0 };
    scn::Server::Peer peer{};
    Vec2 pos{};
    float angle{ 0.0f };
    int hp{ 100 };
    int score{ 0 };
    int fire_cooldown{ 0 };
    WireClientInput input{};
};

struct ServerBullet {
    bool active{ false };
    U32 owner_id{ 0 };
    Vec2 pos{};
    Vec2 vel{};
    float ttl{ 0.0f };
};

class ShooterServerGame final {
public:
    void add_peer(scn::Server::Peer peer) {
        remove_peer(peer);

        for (int i = 0; i < kMaxPlayers; ++i) {
            ServerPlayer& player = _players[static_cast<std::size_t>(i)];
            if (player.active) {
                continue;
            }

            player = {};
            player.active = true;
            player.id = static_cast<U32>(i + 1);
            player.conn_id = peer.conn_id();
            player.peer = peer;
            player.pos = spawn_position(i);
            player.hp = 100;
            player.input.aim_x = kWorldWidth * 0.5f;
            player.input.aim_y = kWorldHeight * 0.5f;
            _peer_to_slot[peer.conn_id()] = i;

            WireWelcome welcome{};
            welcome.player_id = player.id;
            (void)peer.send_reliable(kMsgWelcome, bytes_of(welcome));
            return;
        }

        (void)peer.close(scn::CloseReason::RateLimited);
    }

    void remove_peer(scn::Server::Peer peer) {
        const auto it = _peer_to_slot.find(peer.conn_id());
        if (it == _peer_to_slot.end()) {
            return;
        }
        _players[static_cast<std::size_t>(it->second)] = {};
        _peer_to_slot.erase(it);
    }

    void handle_message(scn::Server::Peer peer, const scn::MsgView& msg) {
        if (msg.type != kMsgInput) {
            return;
        }

        WireClientInput input{};
        if (!read_wire(msg, input)) {
            return;
        }

        const auto it = _peer_to_slot.find(peer.conn_id());
        if (it == _peer_to_slot.end()) {
            return;
        }

        ServerPlayer& player = _players[static_cast<std::size_t>(it->second)];
        input.move_x = clampf(input.move_x, -1.0f, 1.0f);
        input.move_y = clampf(input.move_y, -1.0f, 1.0f);
        input.aim_x = clampf(input.aim_x, 0.0f, kWorldWidth);
        input.aim_y = clampf(input.aim_y, 0.0f, kWorldHeight);
        player.input = input;
    }

    void update_and_broadcast() {
        step();
        WireSnapshot snapshot = make_snapshot();
        for (ServerPlayer& player : _players) {
            if (player.active) {
                (void)player.peer.send_latest(kMsgSnapshot, bytes_of(snapshot));
            }
        }
    }

private:
    static Vec2 spawn_position(int slot) {
        constexpr std::array<Vec2, kMaxPlayers> spawns{
            Vec2{ 120.0f, 120.0f }, Vec2{ 780.0f, 480.0f }, Vec2{ 780.0f, 120.0f }, Vec2{ 120.0f, 480.0f },
            Vec2{ 450.0f, 100.0f }, Vec2{ 450.0f, 500.0f }, Vec2{ 210.0f, 300.0f }, Vec2{ 690.0f, 300.0f }
        };
        return spawns[static_cast<std::size_t>(slot % kMaxPlayers)];
    }

    void step() {
        constexpr float dt = 1.0f / 60.0f;
        constexpr float player_speed = 210.0f;
        constexpr float bullet_speed = 560.0f;
        ++_tick;

        for (ServerPlayer& player : _players) {
            if (!player.active) {
                continue;
            }

            Vec2 move{ player.input.move_x, player.input.move_y };
            move = normalize(move);
            player.pos.x = clampf(player.pos.x + move.x * player_speed * dt, 20.0f, kWorldWidth - 20.0f);
            player.pos.y = clampf(player.pos.y + move.y * player_speed * dt, 20.0f, kWorldHeight - 20.0f);

            const Vec2 aim_delta{ player.input.aim_x - player.pos.x, player.input.aim_y - player.pos.y };
            if (length(aim_delta) > 0.01f) {
                player.angle = std::atan2(aim_delta.y, aim_delta.x);
            }

            if (player.fire_cooldown > 0) {
                --player.fire_cooldown;
            }

            constexpr U8 fire_button = 1;
            if ((player.input.buttons & fire_button) != 0 && player.fire_cooldown == 0) {
                const Vec2 dir{ std::cos(player.angle), std::sin(player.angle) };
                spawn_bullet(player.id,
                    { player.pos.x + dir.x * 22.0f, player.pos.y + dir.y * 22.0f },
                    { dir.x * bullet_speed, dir.y * bullet_speed });
                player.fire_cooldown = 10;
            }
        }

        for (ServerBullet& bullet : _bullets) {
            if (!bullet.active) {
                continue;
            }

            bullet.ttl -= dt;
            bullet.pos.x += bullet.vel.x * dt;
            bullet.pos.y += bullet.vel.y * dt;
            if (bullet.ttl <= 0.0f || bullet.pos.x < 0.0f || bullet.pos.x > kWorldWidth ||
                bullet.pos.y < 0.0f || bullet.pos.y > kWorldHeight) {
                bullet.active = false;
                continue;
            }

            for (ServerPlayer& player : _players) {
                if (!player.active || player.id == bullet.owner_id) {
                    continue;
                }

                const Vec2 delta{ player.pos.x - bullet.pos.x, player.pos.y - bullet.pos.y };
                if (length(delta) > 17.0f) {
                    continue;
                }

                bullet.active = false;
                player.hp -= 25;
                if (player.hp <= 0) {
                    award_score(bullet.owner_id);
                    respawn(player);
                }
                break;
            }
        }
    }

    void spawn_bullet(U32 owner_id, Vec2 pos, Vec2 vel) {
        for (ServerBullet& bullet : _bullets) {
            if (bullet.active) {
                continue;
            }
            bullet.active = true;
            bullet.owner_id = owner_id;
            bullet.pos = pos;
            bullet.vel = vel;
            bullet.ttl = 1.2f;
            return;
        }
    }

    void award_score(U32 owner_id) {
        for (ServerPlayer& player : _players) {
            if (player.active && player.id == owner_id) {
                player.score = std::min(player.score + 1, 255);
                return;
            }
        }
    }

    void respawn(ServerPlayer& player) {
        const int slot = static_cast<int>(player.id) - 1;
        player.pos = spawn_position(slot);
        player.hp = 100;
        player.fire_cooldown = 20;
    }

    WireSnapshot make_snapshot() const {
        WireSnapshot snapshot{};
        snapshot.server_tick = _tick;

        for (const ServerPlayer& player : _players) {
            if (!player.active || snapshot.player_count >= kMaxPlayers) {
                continue;
            }
            WirePlayer& out = snapshot.players[snapshot.player_count++];
            out.id = player.id;
            out.x = player.pos.x;
            out.y = player.pos.y;
            out.angle = player.angle;
            out.hp = static_cast<I16>(std::max(0, player.hp));
            out.alive = 1;
            out.score = static_cast<U8>(std::min(player.score, 255));
        }

        for (const ServerBullet& bullet : _bullets) {
            if (!bullet.active || snapshot.bullet_count >= kMaxBullets) {
                continue;
            }
            WireBullet& out = snapshot.bullets[snapshot.bullet_count++];
            out.owner_id = bullet.owner_id;
            out.x = bullet.pos.x;
            out.y = bullet.pos.y;
            out.vx = bullet.vel.x;
            out.vy = bullet.vel.y;
            out.alive = 1;
        }

        return snapshot;
    }

    U32 _tick{ 0 };
    std::array<ServerPlayer, kMaxPlayers> _players{};
    std::array<ServerBullet, kMaxBullets> _bullets{};
    std::unordered_map<U64, int> _peer_to_slot{};
};

struct SharedClientState {
    std::mutex mutex{};
    WireSnapshot snapshot{};
    bool have_snapshot{ false };
    U32 local_player_id{ 0 };
    std::string status{ "starting" };
};

enum class LaunchMode {
    Host,
    Client,
    DedicatedServer,
};

struct LaunchOptions {
    LaunchMode mode{ LaunchMode::Host };
    std::string host{ "127.0.0.1" };
    U16 port{ kDefaultPort };
};

struct ViewTransform {
    float scale{ 1.0f };
    float ox{ 0.0f };
    float oy{ 0.0f };
};

ViewTransform make_transform(const RECT& rc) {
    const float width = static_cast<float>(std::max(1L, rc.right - rc.left));
    const float height = static_cast<float>(std::max(1L, rc.bottom - rc.top));
    const float scale = std::min(width / kWorldWidth, height / kWorldHeight);
    return { scale, (width - kWorldWidth * scale) * 0.5f, (height - kWorldHeight * scale) * 0.5f };
}

POINT world_to_screen(Vec2 p, const ViewTransform& tx) {
    POINT out{};
    out.x = static_cast<LONG>(std::lround(tx.ox + p.x * tx.scale));
    out.y = static_cast<LONG>(std::lround(tx.oy + p.y * tx.scale));
    return out;
}

Vec2 screen_to_world(POINT p, const ViewTransform& tx) {
    return {
        clampf((static_cast<float>(p.x) - tx.ox) / tx.scale, 0.0f, kWorldWidth),
        clampf((static_cast<float>(p.y) - tx.oy) / tx.scale, 0.0f, kWorldHeight)
    };
}

class ShooterApp final {
public:
    explicit ShooterApp(LaunchOptions options) : _options(std::move(options)) {}
    ~ShooterApp() { stop_network(); }

    scn::Result start_network() {
        _server_game = std::make_unique<ShooterServerGame>();

        if (_options.mode == LaunchMode::Host) {
            _server = std::make_unique<scn::Server>(_io);
            attach_server_callbacks();
            auto rc = _server->listen(_options.port);
            if (!rc.ok()) {
                return rc;
            }
        }

        _client = std::make_unique<scn::Client>(_io);
        attach_client_callbacks();
        auto rc = _client->connect(_options.host, _options.port);
        if (!rc.ok()) {
            return rc;
        }

        rc = _io.run_async();
        if (!rc.ok()) {
            return rc;
        }

        set_status(_options.mode == LaunchMode::Host
            ? "hosting local server; connecting client"
            : "connecting to server");
        return scn::Result::success();
    }

    void stop_network() {
        if (_network_stopped.exchange(true)) {
            return;
        }
        _io.stop();
        (void)_io.join();
        _client.reset();
        _server.reset();
        _server_game.reset();
    }

    void set_window(HWND hwnd) {
        _hwnd = hwnd;
    }

    void update_mouse(int x, int y) {
        _mouse.x = x;
        _mouse.y = y;
    }

    void frame() {
        RECT rc{};
        GetClientRect(_hwnd, &rc);
        const ViewTransform tx = make_transform(rc);
        const Vec2 aim = screen_to_world(_mouse, tx);
        WireClientInput input{};
        input.move_x = (key_down('D') ? 1.0f : 0.0f) - (key_down('A') ? 1.0f : 0.0f);
        input.move_y = (key_down('S') ? 1.0f : 0.0f) - (key_down('W') ? 1.0f : 0.0f);
        input.aim_x = aim.x;
        input.aim_y = aim.y;
        input.client_tick = ++_client_tick;
        input.buttons = (key_down(VK_LBUTTON) || _mouse_down) ? 1 : 0;

        _io.post([this, input] {
            if (_options.mode == LaunchMode::Host && _server_game) {
                _server_game->update_and_broadcast();
            }
            if (_client && _client->state() == scn::ConnectionState::Established) {
                (void)_client->send_latest(kMsgInput, bytes_of(input));
            }
        });
    }

    void set_mouse_down(bool down) {
        _mouse_down = down;
    }

    void paint(HDC target) {
        RECT rc{};
        GetClientRect(_hwnd, &rc);
        const int width = static_cast<int>(std::max(1L, rc.right - rc.left));
        const int height = static_cast<int>(std::max(1L, rc.bottom - rc.top));

        HDC mem_dc = CreateCompatibleDC(target);
        HBITMAP bitmap = CreateCompatibleBitmap(target, width, height);
        HGDIOBJ old_bitmap = SelectObject(mem_dc, bitmap);

        render(mem_dc, rc);

        BitBlt(target, 0, 0, width, height, mem_dc, 0, 0, SRCCOPY);
        SelectObject(mem_dc, old_bitmap);
        DeleteObject(bitmap);
        DeleteDC(mem_dc);
    }

private:
    void attach_server_callbacks() {
        _server->on_peer_connected([this](scn::Server::Peer peer) {
            if (_server_game) {
                _server_game->add_peer(peer);
            }
        });
        _server->on_peer_disconnected([this](scn::Server::Peer peer, scn::CloseReason) {
            if (_server_game) {
                _server_game->remove_peer(peer);
            }
        });
        _server->on_message([this](scn::Server::Peer peer, const scn::MsgView& msg) {
            if (_server_game) {
                _server_game->handle_message(peer, msg);
            }
        });
    }

    void attach_client_callbacks() {
        _client->on_connected([this] {
            set_status("connected");
        });
        _client->on_disconnected([this](scn::CloseReason) {
            set_status("disconnected");
        });
        _client->on_error([this](scn::Result rc) {
            std::string status = "network error: ";
            status.append(rc.name());
            if (!rc.msg.empty()) {
                status.append(" - ");
                status.append(rc.msg.data(), rc.msg.size());
            }
            set_status(status);
        });
        _client->on_message([this](const scn::MsgView& msg) {
            if (msg.type == kMsgWelcome) {
                WireWelcome welcome{};
                if (read_wire(msg, welcome)) {
                    std::lock_guard<std::mutex> lock(_shared.mutex);
                    _shared.local_player_id = welcome.player_id;
                    _shared.status = "connected as P" + std::to_string(welcome.player_id);
                }
                return;
            }

            if (msg.type == kMsgSnapshot) {
                WireSnapshot snapshot{};
                if (read_wire(msg, snapshot)) {
                    snapshot.player_count = std::min<U8>(snapshot.player_count, static_cast<U8>(kMaxPlayers));
                    snapshot.bullet_count = std::min<U8>(snapshot.bullet_count, static_cast<U8>(kMaxBullets));
                    std::lock_guard<std::mutex> lock(_shared.mutex);
                    _shared.snapshot = snapshot;
                    _shared.have_snapshot = true;
                }
            }
        });
    }

    void set_status(std::string status) {
        std::lock_guard<std::mutex> lock(_shared.mutex);
        _shared.status = std::move(status);
    }

    void render(HDC dc, const RECT& rc) {
        WireSnapshot snapshot{};
        bool have_snapshot = false;
        U32 local_id = 0;
        std::string status;
        {
            std::lock_guard<std::mutex> lock(_shared.mutex);
            snapshot = _shared.snapshot;
            have_snapshot = _shared.have_snapshot;
            local_id = _shared.local_player_id;
            status = _shared.status;
        }

        HBRUSH background = CreateSolidBrush(RGB(13, 18, 28));
        FillRect(dc, &rc, background);
        DeleteObject(background);

        const ViewTransform tx = make_transform(rc);
        draw_grid(dc, rc, tx);
        draw_arena(dc, tx);

        if (have_snapshot) {
            for (U8 i = 0; i < snapshot.bullet_count; ++i) {
                draw_bullet(dc, snapshot.bullets[i], tx);
            }
            for (U8 i = 0; i < snapshot.player_count; ++i) {
                draw_player(dc, snapshot.players[i], snapshot.players[i].id == local_id, tx);
            }
        } else {
            draw_text(dc, 28, 76, RGB(210, 220, 235), "Waiting for first server snapshot...");
        }

        draw_crosshair(dc);
        draw_hud(dc, status, local_id, snapshot);
    }

    void draw_grid(HDC dc, const RECT& rc, const ViewTransform& tx) {
        GdiObject grid_pen(CreatePen(PS_SOLID, 1, RGB(29, 40, 58)));
        HGDIOBJ old_pen = SelectObject(dc, grid_pen.get());
        for (int x = 0; x <= static_cast<int>(kWorldWidth); x += 50) {
            const POINT a = world_to_screen({ static_cast<float>(x), 0.0f }, tx);
            const POINT b = world_to_screen({ static_cast<float>(x), kWorldHeight }, tx);
            MoveToEx(dc, a.x, a.y, nullptr);
            LineTo(dc, b.x, b.y);
        }
        for (int y = 0; y <= static_cast<int>(kWorldHeight); y += 50) {
            const POINT a = world_to_screen({ 0.0f, static_cast<float>(y) }, tx);
            const POINT b = world_to_screen({ kWorldWidth, static_cast<float>(y) }, tx);
            MoveToEx(dc, a.x, a.y, nullptr);
            LineTo(dc, b.x, b.y);
        }
        SelectObject(dc, old_pen);

        GdiObject star_pen(CreatePen(PS_SOLID, 1, RGB(80, 94, 120)));
        old_pen = SelectObject(dc, star_pen.get());
        const int width = static_cast<int>(std::max(1L, rc.right - rc.left));
        const int height = static_cast<int>(std::max(1L, rc.bottom - rc.top));
        for (int i = 0; i < 80; ++i) {
            const int sx = (i * 97 + 53) % width;
            const int sy = (i * 61 + 29) % height;
            SetPixel(dc, sx, sy, RGB(50 + (i % 30), 62 + (i % 25), 82 + (i % 35)));
        }
        SelectObject(dc, old_pen);
    }

    void draw_arena(HDC dc, const ViewTransform& tx) {
        const POINT tl = world_to_screen({ 0.0f, 0.0f }, tx);
        const POINT br = world_to_screen({ kWorldWidth, kWorldHeight }, tx);
        GdiObject pen(CreatePen(PS_SOLID, 2, RGB(87, 118, 166)));
        HGDIOBJ old_pen = SelectObject(dc, pen.get());
        HGDIOBJ old_brush = SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
        Rectangle(dc, tl.x, tl.y, br.x, br.y);
        SelectObject(dc, old_brush);
        SelectObject(dc, old_pen);
    }

    void draw_player(HDC dc, const WirePlayer& player, bool local, const ViewTransform& tx) {
        const Vec2 center{ player.x, player.y };
        const Vec2 forward{ std::cos(player.angle), std::sin(player.angle) };
        const Vec2 side{ -forward.y, forward.x };

        POINT body[3]{};
        body[0] = world_to_screen({ center.x + forward.x * 20.0f, center.y + forward.y * 20.0f }, tx);
        body[1] = world_to_screen({ center.x - forward.x * 15.0f + side.x * 13.0f, center.y - forward.y * 15.0f + side.y * 13.0f }, tx);
        body[2] = world_to_screen({ center.x - forward.x * 15.0f - side.x * 13.0f, center.y - forward.y * 15.0f - side.y * 13.0f }, tx);

        const COLORREF fill = local ? RGB(75, 180, 255) : RGB(238, 92, 92);
        const COLORREF edge = local ? RGB(210, 242, 255) : RGB(255, 205, 190);
        GdiObject brush(CreateSolidBrush(fill));
        GdiObject pen(CreatePen(PS_SOLID, local ? 3 : 2, edge));
        HGDIOBJ old_brush = SelectObject(dc, brush.get());
        HGDIOBJ old_pen = SelectObject(dc, pen.get());
        Polygon(dc, body, 3);

        const POINT barrel_a = world_to_screen(center, tx);
        const POINT barrel_b = world_to_screen({ center.x + forward.x * 30.0f, center.y + forward.y * 30.0f }, tx);
        MoveToEx(dc, barrel_a.x, barrel_a.y, nullptr);
        LineTo(dc, barrel_b.x, barrel_b.y);
        SelectObject(dc, old_pen);
        SelectObject(dc, old_brush);

        const POINT hp0 = world_to_screen({ center.x - 20.0f, center.y - 33.0f }, tx);
        const POINT hp1 = world_to_screen({ center.x + 20.0f, center.y - 27.0f }, tx);
        RECT back{ hp0.x, hp0.y, hp1.x, hp1.y };
        HBRUSH dark = CreateSolidBrush(RGB(35, 35, 35));
        FillRect(dc, &back, dark);
        DeleteObject(dark);
        const int hp_width = static_cast<int>((hp1.x - hp0.x) * clampf(static_cast<float>(player.hp) / 100.0f, 0.0f, 1.0f));
        RECT hp{ hp0.x, hp0.y, hp0.x + hp_width, hp1.y };
        HBRUSH green = CreateSolidBrush(local ? RGB(86, 255, 170) : RGB(255, 190, 96));
        FillRect(dc, &hp, green);
        DeleteObject(green);

        const POINT label = world_to_screen({ center.x - 12.0f, center.y + 24.0f }, tx);
        std::string name = "P" + std::to_string(player.id) + "  " + std::to_string(player.score);
        draw_text(dc, label.x, label.y, local ? RGB(210, 242, 255) : RGB(255, 220, 210), name);
    }

    void draw_bullet(HDC dc, const WireBullet& bullet, const ViewTransform& tx) {
        if (bullet.alive == 0) {
            return;
        }
        const POINT center = world_to_screen({ bullet.x, bullet.y }, tx);
        GdiObject brush(CreateSolidBrush(RGB(255, 230, 96)));
        GdiObject pen(CreatePen(PS_SOLID, 1, RGB(255, 255, 210)));
        HGDIOBJ old_brush = SelectObject(dc, brush.get());
        HGDIOBJ old_pen = SelectObject(dc, pen.get());
        Ellipse(dc, center.x - 4, center.y - 4, center.x + 5, center.y + 5);
        SelectObject(dc, old_pen);
        SelectObject(dc, old_brush);
    }

    void draw_crosshair(HDC dc) const {
        GdiObject pen(CreatePen(PS_SOLID, 1, RGB(230, 245, 255)));
        HGDIOBJ old_pen = SelectObject(dc, pen.get());
        MoveToEx(dc, _mouse.x - 10, _mouse.y, nullptr);
        LineTo(dc, _mouse.x - 3, _mouse.y);
        MoveToEx(dc, _mouse.x + 3, _mouse.y, nullptr);
        LineTo(dc, _mouse.x + 10, _mouse.y);
        MoveToEx(dc, _mouse.x, _mouse.y - 10, nullptr);
        LineTo(dc, _mouse.x, _mouse.y - 3);
        MoveToEx(dc, _mouse.x, _mouse.y + 3, nullptr);
        LineTo(dc, _mouse.x, _mouse.y + 10);
        SelectObject(dc, old_pen);
    }

    void draw_hud(HDC dc, const std::string& status, U32 local_id, const WireSnapshot& snapshot) const {
        draw_text(dc, 18, 16, RGB(230, 240, 255), "securecnet Win32 Shooter Demo");
        draw_text(dc, 18, 38, RGB(160, 178, 210), "WASD move | mouse aim | left click fire | Esc quit");

        std::string mode = (_options.mode == LaunchMode::Host) ? "mode: local host" : "mode: client";
        mode += " | ";
        mode += _options.host;
        mode += ':';
        mode += std::to_string(_options.port);
        draw_text(dc, 18, 60, RGB(160, 178, 210), mode);

        std::string state = "status: " + status;
        if (local_id != 0) {
            state += " | you are P" + std::to_string(local_id);
        }
        state += " | tick " + std::to_string(snapshot.server_tick);
        draw_text(dc, 18, 82, RGB(190, 210, 240), state);
    }

    LaunchOptions _options{};
    HWND _hwnd{ nullptr };
    scn::IoContext _io{};
    std::unique_ptr<scn::Server> _server{};
    std::unique_ptr<scn::Client> _client{};
    std::unique_ptr<ShooterServerGame> _server_game{};
    SharedClientState _shared{};
    POINT _mouse{ 450, 300 };
    std::atomic_bool _network_stopped{ false };
    U32 _client_tick{ 0 };
    bool _mouse_down{ false };
};

ShooterApp* get_app(HWND hwnd) {
    return reinterpret_cast<ShooterApp*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_NCCREATE: {
        auto* createstruct = reinterpret_cast<CREATESTRUCTW*>(lparam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(createstruct->lpCreateParams));
        return TRUE;
    }
    case WM_CREATE: {
        ShooterApp* app = get_app(hwnd);
        if (app != nullptr) {
            app->set_window(hwnd);
            SetTimer(hwnd, kTimerId, kFrameMs, nullptr);
        }
        return 0;
    }
    case WM_MOUSEMOVE: {
        ShooterApp* app = get_app(hwnd);
        if (app != nullptr) {
            app->update_mouse(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam));
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        ShooterApp* app = get_app(hwnd);
        if (app != nullptr) {
            app->set_mouse_down(true);
            SetCapture(hwnd);
        }
        return 0;
    }
    case WM_LBUTTONUP: {
        ShooterApp* app = get_app(hwnd);
        if (app != nullptr) {
            app->set_mouse_down(false);
            ReleaseCapture();
        }
        return 0;
    }
    case WM_TIMER: {
        ShooterApp* app = get_app(hwnd);
        if (app != nullptr && wparam == kTimerId) {
            app->frame();
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }
    case WM_KEYDOWN:
        if (wparam == VK_ESCAPE) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_PAINT: {
        ShooterApp* app = get_app(hwnd);
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);
        if (app != nullptr) {
            app->paint(dc);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY: {
        ShooterApp* app = get_app(hwnd);
        if (app != nullptr) {
            KillTimer(hwnd, kTimerId);
            app->stop_network();
        }
        PostQuitMessage(0);
        return 0;
    }
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

bool parse_port(const wchar_t* text, U16& out) {
    const int value = _wtoi(text);
    if (value <= 0 || value > 65535) {
        return false;
    }
    out = static_cast<U16>(value);
    return true;
}

LaunchOptions parse_options() {
    LaunchOptions options{};
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        return options;
    }

    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg(argv[i]);
        if (arg == L"--server") {
            options.mode = LaunchMode::DedicatedServer;
            if (i + 1 < argc) {
                U16 port = options.port;
                if (parse_port(argv[i + 1], port)) {
                    options.port = port;
                    ++i;
                }
            }
        } else if (arg == L"--client") {
            options.mode = LaunchMode::Client;
            if (i + 1 < argc) {
                options.host = narrow(argv[++i]);
            }
            if (i + 1 < argc) {
                U16 port = options.port;
                if (parse_port(argv[i + 1], port)) {
                    options.port = port;
                    ++i;
                }
            }
        } else if (arg == L"--host") {
            options.mode = LaunchMode::Host;
            options.host = "127.0.0.1";
            if (i + 1 < argc) {
                U16 port = options.port;
                if (parse_port(argv[i + 1], port)) {
                    options.port = port;
                    ++i;
                }
            }
        }
    }

    LocalFree(argv);
    return options;
}

void attach_console_streams() {
#if defined(_MSC_VER)
    FILE* stream = nullptr;
    (void)freopen_s(&stream, "CONOUT$", "w", stdout);
    (void)freopen_s(&stream, "CONOUT$", "w", stderr);
    (void)freopen_s(&stream, "CONIN$", "r", stdin);
#else
    (void)std::freopen("CONOUT$", "w", stdout);
    (void)std::freopen("CONOUT$", "w", stderr);
    (void)std::freopen("CONIN$", "r", stdin);
#endif
}

int run_dedicated_server(const LaunchOptions& options) {
    AllocConsole();
    attach_console_streams();

    scn::IoContext io;
    scn::Server server(io);
    ShooterServerGame game;

    server.on_peer_connected([&game](scn::Server::Peer peer) { game.add_peer(peer); });
    server.on_peer_disconnected([&game](scn::Server::Peer peer, scn::CloseReason) { game.remove_peer(peer); });
    server.on_message([&game](scn::Server::Peer peer, const scn::MsgView& msg) { game.handle_message(peer, msg); });

    auto rc = server.listen(options.port);
    if (!rc.ok()) {
        std::printf("server.listen failed: %.*s %.*s\n",
            static_cast<int>(rc.name().size()), view_chars(rc.name()),
            static_cast<int>(rc.msg.size()), view_chars(rc.msg));
        return 1;
    }

    rc = io.run_async();
    if (!rc.ok()) {
        std::printf("io.run_async failed: %.*s %.*s\n",
            static_cast<int>(rc.name().size()), view_chars(rc.name()),
            static_cast<int>(rc.msg.size()), view_chars(rc.msg));
        return 1;
    }

    std::atomic_bool running{ true };
    std::thread tick_thread([&] {
        while (running.load()) {
            io.post([&game] { game.update_and_broadcast(); });
            Sleep(kFrameMs);
        }
    });

    std::printf("securecnet Win32 shooter dedicated server listening on UDP %u\n", options.port);
    std::printf("Start clients with: securecnet_win32_shooter --client 127.0.0.1 %u\n", options.port);
    std::printf("Press Enter to stop.\n");
    char line[8]{};
    (void)std::fgets(line, sizeof(line), stdin);

    running.store(false);
    tick_thread.join();
    io.stop();
    (void)io.join();
    return 0;
}

int run_graphical_client(HINSTANCE instance, const LaunchOptions& options) {
    ShooterApp app(options);
    const scn::Result rc = app.start_network();
    if (!rc.ok()) {
        std::string message = "Failed to start network: ";
        message.append(rc.name());
        if (!rc.msg.empty()) {
            message.append(" - ");
            message.append(rc.msg.data(), rc.msg.size());
        }
        MessageBoxA(nullptr, message.c_str(), "securecnet shooter", MB_ICONERROR | MB_OK);
        return 1;
    }

    const wchar_t* class_name = L"securecnet_win32_shooter_window";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, static_cast<LPCWSTR>(MAKEINTRESOURCEW(32515)));
    wc.hIcon = LoadIconW(nullptr, static_cast<LPCWSTR>(MAKEINTRESOURCEW(32512)));
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = class_name;

    if (RegisterClassExW(&wc) == 0) {
        MessageBoxA(nullptr, "RegisterClassExW failed", "securecnet shooter", MB_ICONERROR | MB_OK);
        return 1;
    }

    HWND hwnd = CreateWindowExW(0, class_name, L"securecnet Win32 Shooter Demo",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 1100, 760,
        nullptr, nullptr, instance, &app);
    if (hwnd == nullptr) {
        MessageBoxA(nullptr, "CreateWindowExW failed", "securecnet shooter", MB_ICONERROR | MB_OK);
        return 1;
    }

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    const LaunchOptions options = parse_options();
    if (options.mode == LaunchMode::DedicatedServer) {
        return run_dedicated_server(options);
    }
    return run_graphical_client(instance, options);
}
