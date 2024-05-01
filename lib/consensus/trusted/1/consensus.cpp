
#include <consensus/1/consensus.h>
#include <scheduler/task_scheduler.h>
#include <util/sgx/random.h>
#include <util/log.h>

Consensus1::Consensus1(int id, size_t peerCount, int electionMinTimeout, int electionMaxTimeout,
                       int heartbeatMinTimeout, int heartbeatMaxTimeout) :
        id(id),
        peerCount(peerCount),
        totalCount(peerCount + 1),
        quorumCount((peerCount + 1) / 2),
        voteState(std::make_shared<VoteState>()),
        electionMinTimeout(electionMinTimeout),
        electionMaxTimeout(electionMaxTimeout),
        heartbeatMinTimeout(heartbeatMinTimeout),
        heartbeatMaxTimeout(heartbeatMaxTimeout) {}

NodeState Consensus1::getCurrentState() {
    std::lock_guard<std::mutex> lock(this->stateLock);
    return this->currentState;
}

void Consensus1::setCurrentState(NodeState state) {
    std::lock_guard<std::mutex> lock(this->stateLock);
    Consensus1::currentState = state;
}

void Consensus1::start() {
    if (this->getCurrentState() < Follower) {
        TaskScheduler::executeDetachedTask([this] {
            if (this->getCurrentState() < Follower) {
                this->becomeFollower();
            }
        });
    }
}

void Consensus1::becomeFollower() {
    this->setCurrentState(Follower);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Become Follower. Current circle = %d. Current term = %d.", this->followerCircle, this->term);
#else
    if (this->leaderId == -1) {
        LOG_INFO("Become Follower. Current circle = %d. Current term = %d.", this->followerCircle, this->term);
    }
#endif
    int circle = ++this->followerCircle;
    this->followerToCandidateTask = std::make_shared<AsyncTask>([this, circle] {
        if (this->getCurrentState() == Follower && this->followerCircle == circle) {
            this->candidateCircle = 0;
            this->becomeCandidate();
        }
    });
    TaskScheduler::executeDelayedTask(this->followerToCandidateTask,
                                      Random::nextInt(this->electionMinTimeout, this->electionMaxTimeout));
}

void Consensus1::becomeCandidate() {
    this->setCurrentState(Candidate);
    LOG_INFO("Become Candidate. Current circle = %d. Current term = %d.", this->candidateCircle, this->term);
    int circle = ++this->candidateCircle;
    this->term++;
    this->leaderId = -1;
    this->voteState = std::make_shared<VoteState>();
    int electionTerm = this->voteState->term = this->term;
    this->voteState->votedFor = this->id;
    this->voteState->voteCount++;
    TaskScheduler::executeDetachedTask([this, electionTerm] {
        this->sendElectionMessage(electionTerm);
    });
    this->continueCandidateTask = std::make_shared<AsyncTask>([this, circle] {
        if (this->getCurrentState() == Candidate && this->candidateCircle == circle) {
            this->becomeCandidate();
        }
    });
    TaskScheduler::executeDelayedTask(this->continueCandidateTask,
                                      Random::nextInt(this->electionMinTimeout, this->electionMaxTimeout));
}

void Consensus1::becomeLeader() {
    this->setCurrentState(Leader);
#ifdef LOG_VERBOSE
    LOG_DEBUG("Become Leader. Current circle = %d. Current term = %d.", this->leaderCircle, this->term);
#else
    if (this->leaderId != this->id) {
        LOG_INFO("Become Leader. Current circle = %d. Current term = %d.", this->leaderCircle, this->term);
    }
#endif
    int circle = ++this->leaderCircle;
    this->leaderId = this->id;
    TaskScheduler::executeDetachedTask([this] {
        this->sendLeaderNotificationMessage(this->term);
    });
    this->continueLeaderTask = std::make_shared<AsyncTask>([this, circle] {
        if (this->getCurrentState() == Leader && this->leaderCircle == circle) {
            this->becomeLeader();
        }
    });
    TaskScheduler::executeDelayedTask(this->continueLeaderTask,
                                      Random::nextInt(this->heartbeatMinTimeout, this->heartbeatMaxTimeout));
}

void Consensus1::handleElectionMessage(int fromNodeId, int reqTerm) {
#ifdef LOG_VERBOSE
    LOG_DEBUG("voteByPeer called. nodeId = %d, reqTerm = %d", nodeId, reqTerm);
#endif
    if (reqTerm < this->term) {
        return;
    }

    bool forceToBeFollower = false;
    if (reqTerm > this->term) {
        TaskScheduler::cancelDelayedTask(this->followerToCandidateTask);
        TaskScheduler::cancelDelayedTask(this->continueCandidateTask);
        TaskScheduler::cancelDelayedTask(this->continueLeaderTask);
        this->term = reqTerm;
        this->voteState = std::make_shared<VoteState>();
        this->voteState->term = reqTerm;
        this->followerCircle = 0;
        forceToBeFollower = true;
    }

    if (reqTerm == this->voteState->term && this->voteState->votedFor == -1) {
        this->voteState->votedFor = fromNodeId;
#ifdef LOG_VERBOSE
        LOG_DEBUG("Now voted for = %d.", id);
#endif
        TaskScheduler::executeDetachedTask([this, fromNodeId, reqTerm] {
            this->sendElectionReplyMessage(fromNodeId, reqTerm);
        });
    }

    if (this->getCurrentState() == Follower || forceToBeFollower) {
        this->becomeFollower();
    }
}

void Consensus1::handleElectionReplyMessage(int reqTerm) {
#ifdef LOG_VERBOSE
    LOG_DEBUG("votedFromPeer called.");
#endif
    if (reqTerm < this->term) {
        return;
    }

    if (this->getCurrentState() == Candidate && this->voteState->term == reqTerm) {
        this->voteState->voteCount++;
        if (this->voteState->voteCount > this->quorumCount) {
            this->leaderCircle = 0;
            this->becomeLeader();
        }
    }
}

void Consensus1::handleLeaderNotificationMessage(int fromNodeId, int reqTerm) {
#ifdef LOG_VERBOSE
    LOG_DEBUG("ledByPeer called. nodeId = %d, reqTerm = %d", nodeId, reqTerm);
#endif
    if (reqTerm < this->term) {
        return;
    }

    bool forceToBeFollower = false;
    if (reqTerm > this->term) {
        TaskScheduler::cancelDelayedTask(this->followerToCandidateTask);
        TaskScheduler::cancelDelayedTask(this->continueCandidateTask);
        TaskScheduler::cancelDelayedTask(this->continueLeaderTask);
        this->term = reqTerm;
        this->voteState = std::make_shared<VoteState>();
        this->voteState->term = reqTerm;
        this->voteState->votedFor = fromNodeId;
        this->followerCircle = 0;
        forceToBeFollower = true;
    }

    this->leaderId = fromNodeId;

    auto currState = this->getCurrentState();
    if (currState == Follower || currState == Candidate || forceToBeFollower) {
        if (currState == Candidate) {
            TaskScheduler::cancelDelayedTask(this->continueCandidateTask);
        }
        this->becomeFollower();
    }
}
