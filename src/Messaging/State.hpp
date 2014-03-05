#ifndef DISSENT_MESSAGING_ABSTRACT_STATE_H_GUARD
#define DISSENT_MESSAGING_ABSTRACT_STATE_H_GUARD

#include <QSharedPointer>
#include "ISender.hpp"
#include "StateData.hpp"
#include "Message.hpp"

namespace Dissent {
namespace Messaging {
  class State {
    public:
      /**
       * Result of checking a packet
       */
      enum PacketResult {
        Ignore,
        Process,
        Store,
        Restart
      };

      /**
       * Result of processing a packet
       */
      enum ProcessResult {
        NoChange,
        NextState,
        Finished,
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

      /**
       * Checks to see what to do with this message
       * @param msg The message to check
       */
      PacketResult CheckPacket(const QSharedPointer<Message> &msg)
      {
        if(m_msg_type == msg->GetMessageType()) {
          return Process;
        } else if(StorePacket(msg)) {
          return Store;
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

    private:
      /**
       * @param msg
       */
      virtual bool StorePacket(const QSharedPointer<Message> &msg) const = 0;

      /**
       * @param msg
       */
      virtual bool RestartPacket(const QSharedPointer<Message> &msg) const = 0;

      QSharedPointer<StateData> m_data;
      qint8 m_state;
      qint8 m_msg_type;
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
