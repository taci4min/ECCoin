#ifndef HEADER_MESSAGES_H
#define HEADER_MESSAGES_H

#include "node.h"
#include "serialize.h"

bool processGetHeaders(CNode* pfrom, CDataStream& vRecv);
bool processHeaders(CNode* pfrom, CDataStream& vRecv);

#endif // HEADER_MESSAGES_H
