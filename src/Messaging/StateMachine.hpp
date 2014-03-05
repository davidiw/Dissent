#ifndef DISSENT_MESSAGING_ABSTRACT_STATE_MACHINE_H_GUARD
#define DISSENT_MESSAGING_ABSTRACT_STATE_MACHINE_H_GUARD

#include <QSharedPointer>

#include "Utils/QRunTimeError.hpp"

#include "State.hpp"
#include "Message.hpp"
#include "StateData.hpp"

namespace Dissent {
namespace Messaging {
  class StateMachine {
    public:
      explicit StateMachine(const QSharedPointer<StateData> &data) :
        m_data(data)
      {
      }

      /**
       * Adds a state to the state machine
       * @param asf a state factory to produce new states
       */
      void AddState(const QSharedPointer<AbstractStateFactory> &asf)
      {
        m_states[asf->GetState()] = asf;
      }

      /**
       * Adds a state to the state machine
       * @param asf a state factory to produce new states
       */
      void AddState(AbstractStateFactory *asf)
      {
        m_states[asf->GetState()] = QSharedPointer<AbstractStateFactory>(asf);
      }

      /**
       * Transition from state "from" to state "to", when in state "from" and
       * StateComplete is called
       * @param from the "from" state
       * @param to the "to" state
       */
      void AddTransition(qint8 from, qint8 to)
      {
        m_transitions[from] = to;
      }

      void ProcessData(const QSharedPointer<ISender> &from,
          const QSharedPointer<Message> &msg)
      {
        State::PacketResult pr = m_cstate->CheckPacket(msg);
        if(pr == State::Ignore) {
          return;
        } else if(pr == State::Store) {
          m_storage.append(MsgPair(from, msg));
          return;
        }

        State::ProcessResult rr = State::NoChange;
        try {
          rr = m_cstate->ProcessPacket(from, msg);
        } catch (Utils::QRunTimeError &err) {
          // to indx id from indx id state exception
          qWarning() << err.What();
        }

        if(rr == State::NoChange) {
          return;
        } else if(rr == State::NextState) {
          StateComplete();
        } else if(rr == State::Finished) {
          m_cstate = m_states[m_finished]->NewState(m_data);
        }
      }

      void StateComplete()
      {
        int cstate = m_cstate->GetState();
        int nstate = m_transitions[cstate];
        m_cstate = m_states[nstate]->NewState(m_data);

        QList<MsgPair> msgs = m_storage;
        m_storage.clear();
        foreach(const MsgPair &mpair, msgs) {
          ProcessData(mpair.first, mpair.second);
        }
      }

      void SetState(qint8 state)
      {
        if(!m_states.contains(state)) {
          return;
        }
        m_cstate = m_states[state]->NewState(m_data);
      }

      void SetFinishedState(qint8 state)
      {
        m_finished = state;
      }

    private:
      QSharedPointer<StateData> m_data;
      QHash<qint8, QSharedPointer<AbstractStateFactory> > m_states;
      QHash<qint8, qint8> m_transitions;
      QSharedPointer<State> m_cstate;

      typedef QPair<QSharedPointer<ISender>, QSharedPointer<Message> > MsgPair;
      QList<MsgPair> m_storage;
      qint8 m_finished;
  };
}
}

#endif
