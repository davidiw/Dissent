#include "ClientSession.hpp"
#include "ClientQueue.hpp"
#include "ServerQueued.hpp"
#include "ServerStart.hpp"
#include "SessionData.hpp"

#include "Crypto/CryptoRandom.hpp"
#include "Crypto/Hash.hpp"

#include "DummyState.hpp"
#include "ClientStates.hpp"

namespace Dissent {
namespace Session {
  ClientSession::ClientSession(
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round) :
    Session(overlay, my_key, keys, create_round),
    m_nonce(Crypto::CryptoRandom::OptimalSeedSize(), 0),
    m_state(OFFLINE)
  {
    GetStateMachine().AddState(new Messaging::StateFactory<DummyState>(
          SessionStates::ServerInit, SessionMessage::ServerInit));
    GetStateMachine().AddState(new Messaging::StateFactory<ClientCommState>(
          SessionStates::Communicating, SessionMessage::SessionData));
    AddMessageParser(new Messaging::MessageParser<SessionData>(SessionMessage::SessionData));
    GetStateMachine().SetState(SessionStates::ServerInit);
    GetStateMachine().AddTransition(SessionStates::ServerInit, SessionStates::Communicating);
    GetStateMachine().AddTransition(SessionStates::Communicating, SessionStates::ServerInit);

    GetOverlay()->GetRpcHandler()->Register("Queued", this, "HandleQueued");
    GetOverlay()->GetRpcHandler()->Register("Start", this, "HandleStart");
  }

  ClientSession::~ClientSession()
  {
    GetOverlay()->GetRpcHandler()->Unregister("HandleQueued");
    GetOverlay()->GetRpcHandler()->Unregister("HandleStart");
  }

  void ClientSession::OnStart()
  {
    m_state = WAITING_FOR_SERVER;
    CheckServer();
  }

  void ClientSession::OnStop()
  {
  }

  void ClientSession::HandleRoundFinished()
  {
    GetStateMachine().StateComplete();
    m_state = WAITING_FOR_SERVER;
    CheckServer();
  }

  void ClientSession::HandleConnection(
      const QSharedPointer<Connections::Connection> &con)
  {
    if(GetOverlay()->IsServer(con->GetRemoteId())) {
      return;
    }

    connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnectSlot()));
    CheckServer();
  }

  void ClientSession::HandleDisconnect(
      const QSharedPointer<Connections::Connection> &)
  {
  }

  void ClientSession::CheckServer()
  {
    if(m_state != WAITING_FOR_SERVER) {
      return;
    }

    m_server.clear();

    Connections::ConnectionTable &ct = GetOverlay()->GetConnectionTable();
    foreach(const QSharedPointer<Connections::Connection> &con, ct.GetConnections()) {
      if(GetOverlay()->IsServer(con->GetRemoteId())) {
        m_server = con;
        break;
      }
    }

    if(!m_server) {
      return;
    }

    SendQueue();
  }

  void ClientSession::SendQueue()
  {
    m_state = QUEUING;

    qDebug() << GetOverlay()->GetId() <<
      "ClientSession::SendQueue: sending Queue";

    Crypto::CryptoRandom rand;
    rand.GenerateBlock(m_nonce);
    ClientQueue queue(m_nonce);

    GetOverlay()->SendNotification(m_server->GetRemoteId(), "Queue", queue.GetPacket());
  }

  void ClientSession::HandleQueued(const Messaging::Request &notification)
  {
    if(m_state != QUEUING) {
      qWarning() << GetOverlay()->GetId() <<
        "ClientSession::Queued: message out of order" <<
        notification.GetFrom()->ToString() << "Current state:" << m_state;
      return;
    }

    ServerQueued queued(notification.GetData().toByteArray());
    if(m_nonce != queued.GetNonce()) {
      qWarning() << GetOverlay()->GetId() << "ClientSession::Queued: Invalid nonce.";
      return;
    } else if(!GetKeyShare()->GetKey(m_server->GetRemoteId().ToString())->Verify(
          queued.GetPayload(), queued.GetSignature()))
    {
      qWarning() << GetOverlay()->GetId() << "ClientSession::Queued: Invalid signature.";
      return;
    }

    SetServers(queued.GetAgreeList());
    if(GetServers().size() != GetOverlay()->GetServerIds().size()) {
      qWarning() << GetOverlay()->GetId() << "ClientSession::Queued: Insufficient agree messages.";
      return;
    }

    SetRoundId(GetServers()[0]->GetRoundId());

    foreach(const QSharedPointer<ServerAgree> &agree, GetServers()) {
      if(!CheckServerAgree(*agree)) {
        return;
      }
    }

    qDebug() << GetOverlay()->GetId() <<
      "ClientSession::Queued: sending Register";

    SendRegister();
  }

  void ClientSession::SendRegister()
  {
    m_state = REGISTERING;

    GenerateRoundData();
    ClientRegister reg(GetOverlay()->GetId(), GetRoundId(),
        GetEphemeralKey()->GetPublicKey(), GetOptionalPublic());
    reg.SetSignature(GetPrivateKey()->Sign(reg.GetPayload()));
    GetOverlay()->SendNotification(m_server->GetRemoteId(), "Register", reg.GetPacket());
  }

  void ClientSession::HandleStart(const Messaging::Request &notification)
  {
    if(m_state != REGISTERING) {
      qWarning() << GetOverlay()->GetId() <<
        "ClientSession::Start: message out of order" <<
        notification.GetFrom()->ToString() << "Current state:" << m_state;
      return;
    }

    ServerStart start(notification.GetData().toByteArray());
    if(start.GetSignatures().count() != GetOverlay()->GetServerIds().count()) {
      qWarning() << GetOverlay()->GetId() << "ClientSession::Start: Incorrect number of signatures.";
      return;
    }

    qDebug() << GetOverlay()->GetId() <<
      "ClientSession::Start: Starting";

    Crypto::Hash hash;
    QByteArray hash_data = hash.ComputeHash(start.GetRegisterBytes());
    int idx = 0;
    foreach(const Connections::Id &id, GetOverlay()->GetServerIds()) {
      QByteArray signature = start.GetSignatures()[idx++];
      if(!GetKeyShare()->GetKey(id.ToString())->Verify(hash_data, signature)) {
        qWarning() << GetOverlay()->GetId() << "ServerSession::VerifyList: invalid signature:" << id;
        return;
      }
    }

    SetClients(start.GetRegisterList());
    NextRound();
    GetStateMachine().StateComplete();
    GetRound()->Start();
    emit RoundStarting(GetRound());
  }
}
}
