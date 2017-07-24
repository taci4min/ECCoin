#ifndef BITCOIN_NOUI_H
#define BITCOIN_NOUI_H

#include <string>
#include "util/util.h"

extern void noui_connect();

static void noui_InitMessage(const std::string& message)
{
    LogPrintf("init message: %s\n", message);
}

#endif // BITCOIN_NOUI_H
