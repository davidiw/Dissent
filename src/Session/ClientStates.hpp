#ifndef DISSENT_SESSION_CLIENT_COMM_STATE_H_GUARD
#define DISSENT_SESSION_CLIENT_COMM_STATE_H_GUARD

#include "Messaging/ISender.hpp"
#include "Messaging/Message.hpp"
#include "Messaging/State.hpp"
#include "Messaging/StateData.hpp"
#include "Utils/QRunTimeError.hpp"

#include "ServerStates.hpp"
#include "SessionState.hpp"

namespace Dissent {
namespace Session {
      /*
  class ClientOfflineState : public SessionState {
    public:
      explicit ClientOfflineState(const QSharedPointer<SessionSharedState> &data) :
        SessionState(data, SessionStates::WaitingForServer,
            Messaging::Message::GetBadMessageType())
      {
      }

      virtual ProcessResult ProcessPacket(const QSharedPointer<ISender> &,
                    const QSharedPointer<Message> &)
      {
        return Messaging::State::NoChange;
      }


    private:
      virtual bool StorePacket(const QSharedPointer<Messaging::Message> &) const
      {
        return false;
      }
  };

  class ClientWaitingForServer : public SessionState {
    public:
      explicit ClientOfflineState(const QSharedPointer<SessionSharedState> &data) :
        SessionState(data, SessionStates::WaitingForServer,
            Messaging::Message::GetBadMessageType())
      {
      }

    private:
      virtual bool StorePacket(const QSharedPointer<Messaging::Message> &) const
      {
        return false;
      }
  };

  class ClientQueuing : public SessionState {
  };
  */

  class ClientCommState : public ServerCommState {
    public:
      explicit ClientCommState(
          const QSharedPointer<Messaging::StateData> &data) :
        ServerCommState(data)
      {
      }

    private:
      virtual bool StorePacket(const QSharedPointer<Messaging::Message> &) const
      {
        return false;
      }
  };
}
}

#endif
