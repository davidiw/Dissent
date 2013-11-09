#ifndef DISSENT_SESSION_SERVER_SESSION_H_GUARD
#define DISSENT_SESSION_SERVER_SESSION_H_GUARD

#include <QMap>
#include <QMetaEnum>
#include <QSharedPointer>

#include "Anonymity/Round.hpp"
#include "ClientServer/Overlay.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/Response.hpp"
#include "Messaging/ResponseHandler.hpp"
#include "Utils/TimerEvent.hpp"

#include "ClientQueue.hpp"
#include "ClientRegister.hpp"
#include "ServerAgree.hpp"
#include "ServerEnlist.hpp"
#include "ServerInit.hpp"
#include "ServerQueued.hpp"
#include "Session.hpp"

namespace Dissent {
namespace Session {
  /**
   * The session code for a server process
   */
  class ServerSession : public Session {
    Q_OBJECT
    Q_ENUMS(States)

    public:
      /**
       * Constructor
       * @param overlay used to pass messages to other participants
       * @param my_key local nodes private key
       * @param keys public keys for all participants
       * @param create_round callback for creating rounds
       */
      explicit ServerSession(
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round);

      /**
       * Deconstructor
       */
      virtual ~ServerSession();

      enum States {
        OFFLINE = 0,
        WAITING_FOR_SERVERS_AND_INIT,
        WAITING_FOR_SERVERS,
        WAITING_FOR_INIT,
        ENLISTING,
        AGREEING,
        REGISTERING,
        ROSTERING,
        VERIFYING,
        COMMUNICATING,
      };

      /**
       * Converts a state to a string
       * @param state the state to convert
       */
      static QString StateToString(int state)
      {
        int index = staticMetaObject.indexOfEnumerator("States");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

    protected:
      /**
       * Called when the session is started
       */
      virtual void OnStart();

      /**
       * Called when the session is stopped
       */
      virtual void OnStop();

      /**
       * Returns if the server is the proposer
       */
      bool IsProposer() const
      {
        return GetOverlay()->GetId() == GetOverlay()->GetServerIds().first();
      }

      /**
       * Called to check the state of the servers
       */
      void CheckServers();

      /**
       * Sends the ServerInit message
       */
      void SendInit();

      /**
       * Processes the ServerInit message
       */
      bool ProcessInit(const QSharedPointer<ServerInit> &init);

      /**
       * Sends the ServerEnlist message
       */
      void SendEnlist();

      /**
       * Called after the timeout for the client registration phase has passed
       */
      void FinishClientRegister(const int &);

      /**
       * Verify the ClientRegister is properly formed
       * @param clr register message
       */
      bool CheckClientRegister(const QSharedPointer<ClientRegister> &clr);

      /**
       * Sends the List of clients taht registered with this server
       */
      void SendList();

    private:
      /**
       * Called when a round has been finished to prepare for the next round
       */
      virtual void HandleRoundFinished();

      /**
       * New incoming connection
       * @param con the connection
       */
      virtual void HandleConnection(
          const QSharedPointer<Connections::Connection> &con);

      /**
       * The disconnected connection
       * @param con the connection
       */
      virtual void HandleDisconnect(
          const QSharedPointer<Connections::Connection> &con);

      QSharedPointer<Messaging::ResponseHandler> m_started;

      int m_state;
      int m_connected_servers;
      QList<Messaging::Request> m_queue;
      QSharedPointer<ServerInit> m_init;
      QMap<Connections::Id, QSharedPointer<ServerEnlist> > m_enlist_msgs;
      QMap<Connections::Id, QSharedPointer<ServerAgree> > m_agree_msgs;
      QByteArray m_agree;
      QMap<Connections::Id, QSharedPointer<ClientQueue> > m_queued_msgs;
      QMap<Connections::Id, QSharedPointer<ClientRegister> > m_registered_msgs;
      QByteArray m_registered;
      QMap<Connections::Id, bool> m_list_received;
      QMap<Connections::Id, QByteArray> m_verify;

      int ROUND_TIMER = 30 * 1000;
      Utils::TimerEvent m_register_timer;

      typedef Messaging::Request Request;

    private slots:

      /**
       * Handles the ServerInit message
       * @param notification contains the ServerInit message
       */
      void HandleInit(const Request &notification);

      /**
       * Handles the ServerEnlist message
       * @param notification contains the ServerEnlist message
       */
      void HandleEnlist(const Request &notification);

      /**
       * Handles the ServerAgree message
       * @param notification contains the ServerAgree message
       */
      void HandleAgree(const Request &notification);

      /**
       * Handles the ClientQueue message
       * @param notification contains the ClientQueue message
       */
      void HandleQueue(const Request &request);

      /**
       * Handles the ClientRegister message
       * @param notification contains the ClientRegister message
       */
      void HandleRegister(const Request &request);

      /**
       * Handles the ServerList message
       * @param notification contains the ServerList message
       */
      void HandleList(const Request &notification);

      /**
       * Handles the ServerVerifyList message
       * @param notification contains the ServerVerifyList message
       */
      void HandleVerifyList(const Request &notification);
  };
}
}

#endif
