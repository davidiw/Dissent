#ifndef DISSENT_SESSION_SESSION_SHARED_STATE_H_GUARD
#define DISSENT_SESSION_SESSION_SHARED_STATE_H_GUARD

#include "Messaging/StateData.hpp"

namespace Dissent {
namespace Session {
  class SessionSharedState : public Messaging::StateData {
    public:
      virtual ~SessionSharedState() {}

      /**
       * Returns the current round
       */
      QSharedPointer<Anonymity::Round> GetRound() const { return m_round; }

      /**
       * Set the current round
       * @param round the current roudn
       */
      void SetRound(const QSharedPointer<Anonymity::Round> &round) { m_round = round; }

    private:
      QSharedPointer<Anonymity::Round> m_round;
  };
}
}

#endif
