#include "Crypto/CryptoRandom.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/ISender.hpp"
#include "Messaging/Message.hpp"
#include "Messaging/State.hpp"
#include "Messaging/StateData.hpp"
#include "Utils/QRunTimeError.hpp"

#include "ClientSession.hpp"
#include "ServerQueued.hpp"
#include "ServerStart.hpp"
#include "ServerStop.hpp"
#include "SessionData.hpp"

#include "ServerStates.hpp"
#include "SessionState.hpp"

namespace Dissent {
namespace Session {
namespace Client {
  class ClientSessionSharedState : public SessionSharedState {
    public:
      explicit ClientSessionSharedState(const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round) :
        SessionSharedState(overlay, my_key, keys, create_round)
      {
      }

      virtual ~ClientSessionSharedState() {}

      void SetServer(const Connections::Id &server) { m_server = server; }
      Connections::Id GetServer() const { return m_server; }

    private:
      Connections::Id m_server;
  };

  class OfflineState : public SessionState {
    public:
      OfflineState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data,
            SessionStates::Offline,
            SessionMessage::None)
      {
      }

    private:
      virtual bool StorePacket(const QSharedPointer<Messaging::Message> &msg) const
      {
        return (msg->GetMessageType() == SessionMessage::ServerQueued);
      }
  };

  class WaitingForServerState : public SessionState {
    public:
      explicit WaitingForServerState(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data, SessionStates::WaitingForServer, SessionMessage::None)
      {
      }

      virtual ProcessResult Init()
      {
        if(CheckServer()) {
          return NextState;
        }
        return NoChange;
      }

      virtual ProcessResult HandleConnection(const Connections::Id &connector)
      {
        if(GetSharedState()->GetOverlay()->IsServer(connector)) {
          return NoChange;
        }

        return CheckServer() ? NextState : NoChange;
      }

    private:
      virtual bool StorePacket(const QSharedPointer<Messaging::Message> &msg) const
      {
        return (msg->GetMessageType() == SessionMessage::ServerQueued);
      }

      bool CheckServer()
      {
        QSharedPointer<Connections::Connection> server;

        Connections::ConnectionTable &ct = GetSharedState()->GetOverlay()->GetConnectionTable();
        foreach(const QSharedPointer<Connections::Connection> &con, ct.GetConnections()) {
          if(GetSharedState()->GetOverlay()->IsServer(con->GetRemoteId())) {
            server = con;
            break;
          }
        }

        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();
        state->SetServer(server->GetRemoteId());
        return !server.isNull();
      }
  };

  class Queuing : public SessionState {
    public:
      explicit Queuing(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data, SessionStates::Queuing, SessionMessage::ServerQueued)
      {
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();

        // @TODO Swap to another server and call Init again
        if(id == state->GetServer()) {
          return Restart;
        }
        return NoChange;
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();

        qDebug() << state->GetOverlay()->GetId() << this;
        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();

        QSharedPointer<ServerQueued> queued(msg.dynamicCast<ServerQueued>());
        QString server_id = state->GetServer().ToString();

        if(!state->GetKeyShare()->GetKey(server_id)->Verify(
              queued->GetPayload(), queued->GetSignature()))
        {
          throw Utils::QRunTimeError("Invalid signature");
        }

        QList<QSharedPointer<ServerAgree> > servers = queued->GetAgreeList();
        if(servers.size() != state->GetOverlay()->GetServerIds().size()) {
          throw Utils::QRunTimeError("Insufficient agree messages");
        }

        state->SetRoundId(servers[0]->GetRoundId());

        foreach(const QSharedPointer<ServerAgree> &agree, servers) {
          state->CheckServerAgree(*agree);
        }

        state->SetServers(servers);
        return NextState;
      }
  };

  class Registering : public SessionState {
    public:
      explicit Registering(const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data, SessionStates::Registering, SessionMessage::ServerStart)
      {
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();

        // @TODO Swap to another server and call Init again
        if(id == state->GetServer()) {
          return Restart;
        }
        return NoChange;
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();

        state->GenerateRoundData();
        ClientRegister reg(state->GetOverlay()->GetId(), state->GetRoundId(),
            state->GetEphemeralKey()->GetPublicKey(), state->GetOptionalPublic());
        reg.SetSignature(state->GetPrivateKey()->Sign(reg.GetPayload()));
        state->GetOverlay()->SendNotification(state->GetServer(),
            "SessionData", reg.GetPacket());

        qDebug() << state->GetOverlay()->GetId() << this;
        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();

        QSharedPointer<ServerStart> start(msg.dynamicCast<ServerStart>());
        if(start->GetSignatures().count() != state->GetOverlay()->GetServerIds().count()) {
          throw Utils::QRunTimeError("Incorrect number of signatures");
        }

        Crypto::Hash hash;
        QByteArray hash_data = hash.ComputeHash(start->GetRegisterBytes());
        int idx = 0;
        foreach(const Connections::Id &id, state->GetOverlay()->GetServerIds()) {
          QByteArray signature = start->GetSignatures()[idx++];
          if(!state->GetKeyShare()->GetKey(id.ToString())->Verify(hash_data, signature)) {
            throw Utils::QRunTimeError("Invalid signature: " + id.ToString());
          }
        }

        state->SetClients(start->GetRegisterList());
        state->NextRound();
        return NextState;
      }

    private:
      virtual bool StorePacket(const QSharedPointer<Messaging::Message> &msg) const
      {
        return (msg->GetMessageType() == SessionMessage::SessionData);
      }
  };

  class CommState : public SessionState {
    public:
      explicit CommState(
          const QSharedPointer<Messaging::StateData> &data) :
        SessionState(data, SessionStates::Communicating, SessionMessage::SessionData)
      {
      }

      virtual ProcessResult Init()
      {
        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();
        state->GetRound()->Start();
        return NoChange;
      }

      virtual ProcessResult ProcessPacket(
          const QSharedPointer<Messaging::ISender> &from,
          const QSharedPointer<Messaging::Message> &msg)
      {
        QSharedPointer<SessionData> rm(msg.dynamicCast<SessionData>());
        if(!rm) {
          throw Utils::QRunTimeError("Invalid message");
        }

        QSharedPointer<Connections::IOverlaySender> sender =
          from.dynamicCast<Connections::IOverlaySender>();

        if(!sender) {
          throw Utils::QRunTimeError("Received wayward message from: " +
              from->ToString());
        }

        GetSharedState()->GetRound()->ProcessPacket(
            sender->GetRemoteId(), rm->GetPacket());
        return NoChange;
      }

      virtual ProcessResult HandleDisconnection(const Connections::Id &id)
      {
        QSharedPointer<ClientSessionSharedState> state =
          GetSharedState().dynamicCast<ClientSessionSharedState>();

        // @TODO Swap to another server and call Init again
        if(id == state->GetServer()) {
          return Restart;
        }
        return NoChange;
      }
  };
}

using namespace Client;

  ClientSession::ClientSession(
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round) :
    Session(QSharedPointer<SessionSharedState>(
          new ClientSessionSharedState(overlay, my_key, keys, create_round)))
  {
    GetStateMachine().AddState(new Messaging::StateFactory<OfflineState>(
          SessionStates::Offline, SessionMessage::None));
    GetStateMachine().AddState(new Messaging::StateFactory<WaitingForServerState>(
          SessionStates::WaitingForServer, SessionMessage::None));
    GetStateMachine().AddState(new Messaging::StateFactory<Queuing>(
          SessionStates::Queuing, SessionMessage::ServerQueued));
    GetStateMachine().AddState(new Messaging::StateFactory<Registering>(
          SessionStates::Registering, SessionMessage::ServerStart));
    GetStateMachine().AddState(new Messaging::StateFactory<CommState>(
          SessionStates::Communicating, SessionMessage::SessionData));

    AddMessageParser(new Messaging::MessageParser<SessionData>(SessionMessage::SessionData));
    AddMessageParser(new Messaging::MessageParser<ServerQueued>(SessionMessage::ServerQueued));
    AddMessageParser(new Messaging::MessageParser<ServerStart>(SessionMessage::ServerStart));
    AddMessageParser(new Messaging::MessageParser<ServerStop>(SessionMessage::ServerStop));


    GetStateMachine().AddTransition(SessionStates::Offline, SessionStates::WaitingForServer);
    GetStateMachine().AddTransition(SessionStates::WaitingForServer, SessionStates::Queuing);
    GetStateMachine().AddTransition(SessionStates::Queuing, SessionStates::Registering);
    GetStateMachine().AddTransition(SessionStates::Registering, SessionStates::Communicating);
    GetStateMachine().AddTransition(SessionStates::Communicating, SessionStates::WaitingForServer);

    GetStateMachine().SetState(SessionStates::Offline);
  }

  ClientSession::~ClientSession()
  {
  }

  void ClientSession::HandleRoundFinished()
  {
    GetStateMachine().StateComplete();
  }

  void ClientSession::HandleConnection(
      const QSharedPointer<Connections::Connection> &con)
  {
    if(GetOverlay()->IsServer(con->GetRemoteId())) {
      return;
    }

    connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnectSlot()));
    GetStateMachine().HandleConnection(con->GetRemoteId());
  }
}
}
