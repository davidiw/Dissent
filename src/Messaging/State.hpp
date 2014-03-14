#ifndef DISSENT_MESSAGING_ABSTRACT_STATE_H_GUARD
#define DISSENT_MESSAGING_ABSTRACT_STATE_H_GUARD

#include <QSharedPointer>
#include "Utils/Callback.hpp"
#include "ISender.hpp"
#include "StateData.hpp"
#include "Message.hpp"

namespace Dissent {
namespace Messaging {
  class State {
    public:
      /**
       * Result of processing a packet
       */
      enum ProcessResult {
        Ignore,
        NoChange,
        NextState,
        Restart,
        ProcessMessage,
        StoreMessage
      };

      /**
       * Constructor
       * @param data State data
       * @param state Unique id
       * @param msg_type The states message type
       */
      explicit State(const QSharedPointer<StateData> &data, 
          qint8 state, qint8 msg_type) :
        m_data(data),
        m_state(state),
        m_msg_type(msg_type)
      {
      }

      virtual ~State() {}

      virtual ProcessResult Init()
      {
        return NoChange;
      }

      /**
       * Checks to see what to do with this message
       * @param msg The message to check
       */
      virtual ProcessResult CheckPacket(const QSharedPointer<Message> &msg)
      {
        if(m_msg_type == msg->GetMessageType()) {
          return ProcessMessage;
        } else if(StorePacket(msg)) {
          return StoreMessage;
        } else if(RestartPacket(msg)) {
          return Restart;
        } else {
          return Ignore;
        }
      }

      /**
       * Processes the messages intended for this state
       * @param msg The message to process
       */
      virtual ProcessResult ProcessPacket(const QSharedPointer<ISender> &from,
          const QSharedPointer<Message> &msg) = 0;

      /**
       * Returns the states message type
       */
      int GetMessageType() const { return m_msg_type; }

      /**
       * Returns the states unique id
       */
      int GetState() const { return m_state; }

      /**
       * Returns the state data
       */
      QSharedPointer<StateData> GetStateData() const { return m_data; }

      typedef QSharedPointer<Utils::BaseCallback<ProcessResult> > StateChangeHandler;
      void SetStateChangeHandler(const StateChangeHandler &handler) { m_state_change = handler; }
      void UnsetStateChangeHandler() { m_state_change.clear(); }

    protected:
      void StateChange(ProcessResult pr)
      {
        if(m_state_change) {
          m_state_change->Invoke(pr);
        }
      }

    private:
      /**
       * @param msg
       */
      virtual bool StorePacket(const QSharedPointer<Message> &msg) const = 0;

      /**
       * @param msg
       */
      virtual bool RestartPacket(const QSharedPointer<Message> &msg) const = 0;

      /**
       * @param msg
       */

      QSharedPointer<StateData> m_data;
      qint8 m_state;
      qint8 m_msg_type;
      StateChangeHandler m_state_change;
  };

  class AbstractStateFactory {
    public:
      explicit AbstractStateFactory(qint8 state, qint8 msg_type) :
        m_state(state),
        m_msg_type(msg_type)
      {
      }

      virtual ~AbstractStateFactory() {}

      virtual QSharedPointer<State> NewState(
          const QSharedPointer<StateData> &data) = 0;
      int GetMessageType() const { return m_msg_type; }
      int GetState() const { return m_state; }

    private:
      qint8 m_state;
      qint8 m_msg_type;
  };

  template<typename T> class StateFactory : public AbstractStateFactory {
    public:
      StateFactory(qint8 state, qint8 msg_type) :
        AbstractStateFactory(state, msg_type)
      {
      }

      virtual QSharedPointer<State> NewState(
          const QSharedPointer<StateData> &data)
      {
        return QSharedPointer<State>(new T(data));
      }
  };
}
}

#endif
