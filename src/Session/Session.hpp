#ifndef DISSENT_SESSION_SESSION_H_GUARD
#define DISSENT_SESSION_SESSION_H_GUARD

#include <QByteArray>
#include <QPair>
#include <QSharedPointer>

#include "Anonymity/Round.hpp"
#include "Connections/Connection.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/KeyShare.hpp"
#include "ClientServer/Overlay.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Messaging/FilterObject.hpp"
#include "Messaging/Request.hpp"

#include "ClientRegister.hpp"
#include "ServerAgree.hpp"

namespace Dissent {
namespace Session {

  /**
   * Used to handle participation in a anonymous protocol
   */
  class Session : public Messaging::FilterObject, public Utils::StartStop {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param overlay used to pass messages to other participants
       * @param my_key local nodes private key
       * @param keys public keys for all participants
       * @param create_round callback for creating rounds
       */
      explicit Session(const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round);

      /**
       * Deconstructor
       */
      virtual ~Session();

      /**
       * Send data across the session
       */
      virtual void Send(const QByteArray &data);

      /**
       * Returns the Session / Round information
       */
      inline virtual QString ToString() const
      {
        return "Session | " +
          (m_round.isNull() ? "No current round" : m_round->ToString());
      }

    signals:
      /**
       * Signals that a round is beginning.
       * @param round round returns the upcoming round
       */
      void RoundStarting(const QSharedPointer<Anonymity::Round> &round);

      /**
       * Signals that a round has completed.  The round will be deleted after
       * the signal has returned.
       * @param round round returns the completed round
       */
      void RoundFinished(const QSharedPointer<Anonymity::Round> &round);

      /**
       * Signfies that the session has been closed / stopped
       */
      void Stopping();

    protected:
      /**
       * Returns the local node's private key
       */
      QSharedPointer<Crypto::AsymmetricKey> GetPrivateKey() const { return m_my_key; }
      
      /**
       * Returns the set of public keys for all participants
       */
      QSharedPointer<Crypto::KeyShare> GetKeyShare() const { return m_keys; } 

      /**
       * Returns the overlay
       */
      QSharedPointer<ClientServer::Overlay> GetOverlay() { return m_overlay; }

      /**
       * Returns the overlay
       */
      QSharedPointer<ClientServer::Overlay> GetOverlay() const { return m_overlay; }

      /**
       * Returns the current round
       */
      QSharedPointer<Anonymity::Round> GetRound() const { return m_round; }

      /**
       * Builds the next round
       */
      void NextRound();
 
      /**
       * Returns the upcoming or current rounds Round Id
       */
      QByteArray GetRoundId() const { return m_round_id; }

      /**
       * Sets the upcoming rounds Round Id
       */
      void SetRoundId(const QByteArray &round_id) { m_round_id = round_id; }

      /**
       * Generates round data for the upcoming round, including ephemeral signing key
       * and in some cases a DiffieHellman key.
       */
      void GenerateRoundData();

      /**
       * Returns the ephemeral round key
       */
      QSharedPointer<Crypto::AsymmetricKey> GetEphemeralKey() const { return m_ephemeral_key; }

      /**
       * Returns the public component of the round's optional data
       */
      QVariant GetOptionalPublic() const { return m_optional_public; }

      /**
       * Returns the private component of the round's optional data
       */
      QVariant GetOptionalPrivate() const { return m_optional_private; }

      /**
       * Verifies that the ServerAgree is properly formed
       */
      bool CheckServerAgree(const ServerAgree &agree);

      /**
       * Returns the list of servers
       */
      QList<QSharedPointer<ServerAgree> > GetServers() { return m_server_list; }
      
      /**
       * Sets the list of servers
       */
      void SetServers(const QList<QSharedPointer<ServerAgree> > &servers) { m_server_list = servers; }

      /**
       * Returns the list of clients
       */
      QList<QSharedPointer<ClientRegister> > GetClients() { return m_client_list; }

      /**
       * Sets the list of clients
       */
      void SetClients(const QList<QSharedPointer<ClientRegister> > &clients) { m_client_list = clients; }

    private:
      /**
       * Called when a round has been finished to prepare for the next round
       */
      virtual void HandleRoundFinished() = 0;

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

      QSharedPointer<ClientServer::Overlay> m_overlay;
      QSharedPointer<Crypto::AsymmetricKey> m_my_key;
      QSharedPointer<Crypto::KeyShare> m_keys;
      Anonymity::CreateRound m_create_round;
      QSharedPointer<Anonymity::Round> m_round;

      QSharedPointer<Crypto::AsymmetricKey> m_ephemeral_key;
      QVariant m_optional_public;
      QVariant m_optional_private;
      QByteArray m_round_id;
      QList<Messaging::Request> m_round_queue;

      QList<QSharedPointer<ServerAgree> > m_server_list;
      QList<QSharedPointer<ClientRegister> > m_client_list;

      typedef Messaging::Request Request;

    private slots:

      /**
       * A remote peer is submitting data to this peer
       * @param notification a data message
       */
      void IncomingData(const Request &notification);

      /**
       * A server has issued a stop message
       * @param notification a data message
       */
      void HandleStop(const Request &notification);

      /**
       * Called when the round has been finished
       */
      void HandleRoundFinishedSlot();

      /**
       * A slot wrapper for HandleConnection
       * @param con the connection
       */
      void HandleConnectionSlot(const QSharedPointer<Connections::Connection> &con)
      {
        HandleConnection(con);
      }

      /**
       * A slot wrapper for HandleDisconnect
       */
      void HandleDisconnectSlot()
      {
        Connections::Connection *con =
          qobject_cast<Connections::Connection *>(sender());
        QSharedPointer<Connections::Connection> scon(con->GetSharedPointer());
        HandleDisconnect(scon);
      }

    private:
      /**
       * A light weight class for handling semi-reliable sends
       * across the anonymous communication channel
       */
      class DataQueue {
        public:
          DataQueue() : m_trim(0), m_get_data(this, &DataQueue::GetData) {}

          /**
           * Adds new data to the send queue
           * @param data the data to add
           */
          void AddData(const QByteArray &data)
          {
            m_queue.append(data);
          }

          /**
           * Retrieves data from the data waiting queue, returns the byte array
           * containing data and a bool which is true if there is more data
           * available.
           * @param max the maximum amount of data to retrieve
           */
          QPair<QByteArray, bool> GetData(int max);

          /**
           * Resets the current offset in the GetData queue
           */
          void UnGet()
          {
            m_trim = 0;
          }

          /** 
           * Returns a callback into this object,
           * which is valid so long as this object is
           */
          Messaging::GetDataCallback &GetCallback()
          {
            return m_get_data;
          }

        private:
          QList<QByteArray> m_queue;
          int m_trim;
          Messaging::GetDataMethod<DataQueue> m_get_data;
      };

      /**
       * Used to store messages to be transmitted in an upcoming round
       */
      DataQueue m_send_queue;

  };
}
}

#endif
