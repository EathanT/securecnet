#pragma once

#include "securecnet/async.hpp"
#include "securecnet/local_session.hpp"
#include "securecnet/router.hpp"
#include "securecnet/request_reply.hpp"

namespace scn {

    using EasyClient = AsyncClient;
    using EasyServer = AsyncServer;
    using EasyLocalSession = LocalSession;
    using EasyClientRouter = ClientRouter;
    using EasyServerRouter = ServerRouter;
    using EasyRequestTable = ClientRequestTable;

} // namespace scn
