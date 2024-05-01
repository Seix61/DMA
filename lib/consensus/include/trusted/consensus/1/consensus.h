
#ifndef LIB_TRUSTED_CONSENSUS_1_CONSENSUS_H
#define LIB_TRUSTED_CONSENSUS_1_CONSENSUS_H

#include <memory>
#include <mutex>
#include <consensus/1/vote_state.h>
#include <consensus/1/node_state.h>
#include <scheduler/async_task.h>

class Consensus1 {
protected:
    int id;
    size_t peerCount;

    std::shared_ptr<AsyncTask> followerToCandidateTask = nullptr;
    std::shared_ptr<AsyncTask> continueCandidateTask = nullptr;
    std::shared_ptr<AsyncTask> continueLeaderTask = nullptr;
private:
    size_t totalCount;
    size_t quorumCount;
    int electionMinTimeout;
    int electionMaxTimeout;
    int heartbeatMinTimeout;
    int heartbeatMaxTimeout;

    std::mutex stateLock;
    NodeState currentState = NotStart;
    int leaderId = -1;
    int term = 0;
    std::shared_ptr<VoteState> voteState;
    int followerCircle = 0;
    int candidateCircle = 0;
    int leaderCircle = 0;
private:
    NodeState getCurrentState();

    void setCurrentState(NodeState currentState);

    void becomeFollower();

    void becomeCandidate();

    void becomeLeader();

protected:
    explicit Consensus1(int id, size_t peerCount, int electionMinTimeout, int electionMaxTimeout,
                        int heartbeatMinTimeout, int heartbeatMaxTimeout);

    void start();

    void handleElectionMessage(int fromNodeId, int reqTerm);

    void handleElectionReplyMessage(int reqTerm);

    void handleLeaderNotificationMessage(int fromNodeId, int reqTerm);

    virtual void sendElectionMessage(int term) = 0;

    virtual void sendElectionReplyMessage(int toNodeId, int term) = 0;

    virtual void sendLeaderNotificationMessage(int term) = 0;
};

#endif //LIB_TRUSTED_CONSENSUS_1_CONSENSUS_H
