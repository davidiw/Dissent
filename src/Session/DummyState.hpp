#ifndef DISSENT_SESSION_DUMMY_STATE_H_GUARD
#define DISSENT_SESSION_DUMMY_STATE_H_GUARD

#include <QDebug>

#include "Messaging/State.hpp"
#include "Messaging/StateData.hpp"

#include "SessionState.hpp"

namespace Dissent {
namespace Session {
  class DummyState : public SessionState {
    public:
      explicit DummyState(
          const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::ServerInit,
            SessionMessage::ServerInit)
      {
      }

      virtual Messaging::State::ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &)
      {
        return Messaging::State::NoChange;
      }

    private:
      virtual bool StorePacket(const QSharedPointer<Messaging::Message> &) const
      {
        return true;
      }
  };
}
}

#endif
