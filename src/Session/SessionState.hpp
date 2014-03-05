#ifndef DISSENT_SESSION_SESSION_STATE_H_GUARD
#define DISSENT_SESSION_SESSION_STATE_H_GUARD

#include <QObject>

#include "Anonymity/Round.hpp"
#include "Messaging/State.hpp"
#include "Messaging/StateData.hpp"

#include "SessionSharedState.hpp"
#include "SessionMessage.hpp"

namespace Dissent {
namespace Session {
  class SessionStates : QObject {
    Q_OBJECT
    Q_ENUMS(States)

    public:
      enum Names {
        Offline = 0,
        ServerInit,
        WaitingForServer,
        Queuing,
        Communicating
      };

      /** 
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(int type)
      {
        int index = staticMetaObject.indexOfEnumerator("Names");
        return staticMetaObject.enumerator(index).valueToKey(type);
      }
  };

  class SessionState : public Messaging::State {
    public:
      explicit SessionState(const QSharedPointer<Messaging::StateData> &data,
          qint8 state, qint8 msg_type) :
        Messaging::State(data, state, msg_type)
      {
      }

    protected:
      QSharedPointer<SessionSharedState> GetSharedState() const
      {
        return GetStateData().dynamicCast<SessionSharedState>();
      }

    private:
      virtual bool RestartPacket(const QSharedPointer<Messaging::Message> &msg) const
      {
        // We could move all the verification logic here too
        return (msg->GetMessageType() == SessionMessage::ServerStop);
      }
  };
}
}

#endif
