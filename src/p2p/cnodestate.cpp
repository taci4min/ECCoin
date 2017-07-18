#include "cnodestate.h"

/** Map maintaining per-node state. Requires cs_main. */
std::map<NodeId, CNodeState> mapNodeState;

// Requires cs_main.
CNodeState *State(NodeId pnode)
{
    std::map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end())
    {
        return NULL;
    }
    return &it->second;
}
