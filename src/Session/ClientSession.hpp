#ifndef DISSENT_SESSION_CLIENT_SESSION_H_GUARD
#define DISSENT_SESSION_CLIENT_SESSION_H_GUARD

#include <QHash>
#include <QSharedPointer>

#include "ClientRegister.hpp"
#include "Session.hpp"

#include "ClientServer/Overlay.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/Response.hpp"

namespace Dissent {
namespace Session {
  /**
   * Used to filter incoming messages across many sessions.
   */
  class ClientSession : public Session {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param overlay used to pass messages to other participants
       * @param my_key local nodes private key
       * @param keys public keys for all participants
       * @param create_round callback for creating rounds
       */
      explicit ClientSession(
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round);

      /**
       * Deconstructor
       */
      virtual ~ClientSession();

      enum States {
        OFFLINE = 0,
        WAITING_FOR_SERVER,
        QUEUING,
        REGISTERING,
        COMMUNICATING
      };

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
       * Called when a round has been finished to prepare for the next round
       */
      virtual void HandleRoundFinished();

      /**
       * New incoming connection
       * @param con the connection
       */
      virtual void HandleConnection(const QSharedPointer<Connections::Connection> &con);

      /**
       * The disconnected connection
       * @param con the connection
       */
      virtual void HandleDisconnect(const QSharedPointer<Connections::Connection> &con);

    private:
      /**
       * Checks to see if connected to a server and starts the client process if so
       */
      void CheckServer();

      /**
       * Sends the ClientQueue message to the upstream server
       */
      void SendQueue();

      /**
       * Sends the ClientRegister message to the upstream server
       */
      void SendRegister();

      QSharedPointer<Connections::Connection> m_server;
      QByteArray m_nonce;
      States m_state;

      typedef Messaging::Request Request;

    private slots:
      /**
       * Handles the ServerQueued message
       * @param notification contains the ServerQueued message
       */
      void HandleQueued(const Request &notification);

      /**
       * Handles the ServerStart message
       * @param notification contains the ServerStart message
       */
      void HandleStart(const Request &notification);
  };
}
}

#endif
