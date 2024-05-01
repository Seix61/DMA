
#ifndef LIB_TRUSTED_CONSENSUS_1_VOTE_STATE_H
#define LIB_TRUSTED_CONSENSUS_1_VOTE_STATE_H

struct VoteState {
    int term;
    int votedFor;
    int voteCount;

    VoteState() : term(-1), votedFor(-1), voteCount(0) {};
};

#endif //LIB_TRUSTED_CONSENSUS_1_VOTE_STATE_H
