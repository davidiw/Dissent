#include "ServerSession.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/Hash.hpp"
#include "Messaging/ISender.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"

#include "DummyState.hpp"
#include "ServerStates.hpp"

#include "SessionData.hpp"
#include "ServerList.hpp"
#include "ServerStart.hpp"
#include "ServerVerifyList.hpp"

namespace Dissent {
namespace Session {
  ServerSession::ServerSession(
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round) :
    Session(overlay, my_key, keys, create_round),
    m_state(OFFLINE)
  {
    GetStateMachine().AddState(new Messaging::StateFactory<DummyState>(
          SessionStates::ServerInit, SessionMessage::ServerInit));
    GetStateMachine().AddState(new Messaging::StateFactory<ServerCommState>(
          SessionStates::Communicating, SessionMessage::SessionData));
    AddMessageParser(new Messaging::MessageParser<SessionData>(SessionMessage::SessionData));
    GetStateMachine().SetState(SessionStates::ServerInit);
    GetStateMachine().AddTransition(SessionStates::ServerInit, SessionStates::Communicating);
    GetStateMachine().AddTransition(SessionStates::Communicating, SessionStates::ServerInit);

    GetOverlay()->GetRpcHandler()->Register("Init", this, "HandleInit");
    GetOverlay()->GetRpcHandler()->Register("Enlist", this, "HandleEnlist");
    GetOverlay()->GetRpcHandler()->Register("Agree", this, "HandleAgree");
    GetOverlay()->GetRpcHandler()->Register("Queue", this, "HandleQueue");
    GetOverlay()->GetRpcHandler()->Register("Register", this, "HandleRegister");
    GetOverlay()->GetRpcHandler()->Register("List", this, "HandleList");
    GetOverlay()->GetRpcHandler()->Register("VerifyList", this, "HandleVerifyList");
  }

  ServerSession::~ServerSession()
  {
    GetOverlay()->GetRpcHandler()->Unregister("HandleInit");
    GetOverlay()->GetRpcHandler()->Unregister("HandleEnlist");
    GetOverlay()->GetRpcHandler()->Unregister("HandleAgree");
    GetOverlay()->GetRpcHandler()->Unregister("HandleQueue");
    GetOverlay()->GetRpcHandler()->Unregister("HandleRegister");
    GetOverlay()->GetRpcHandler()->Unregister("HandleList");
    GetOverlay()->GetRpcHandler()->Unregister("HandleVerifyList");
  }

  void ServerSession::OnStart()
  {
    m_state = WAITING_FOR_SERVERS_AND_INIT;
    CheckServers();
  }

  void ServerSession::OnStop()
  {
  }

  void ServerSession::HandleRoundFinished()
  {
    GetStateMachine().StateComplete();
    m_state = WAITING_FOR_SERVERS_AND_INIT;

    m_init.clear();
    m_enlist_msgs.clear();
    m_agree_msgs.clear();
    m_agree = QByteArray();
    m_queued_msgs.clear();
    m_registered_msgs.clear();
    m_registered = QByteArray();
    m_list_received.clear();
    m_verify.clear();

    CheckServers();
  }

  void ServerSession::HandleConnection(
      const QSharedPointer<Connections::Connection> &con)
  {
    connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnectSlot()));

    if(!GetOverlay()->IsServer(con->GetRemoteId())) {
      return;
    }

    CheckServers();
  }

  void ServerSession::CheckServers()
  {
    m_connected_servers = 0;

    Connections::ConnectionTable &ct = GetOverlay()->GetConnectionTable();
    foreach(const QSharedPointer<Connections::Connection> &con, ct.GetConnections()) {
      if(GetOverlay()->IsServer(con->GetRemoteId())) {
        m_connected_servers++;
      }
    }

    if(m_connected_servers != GetOverlay()->GetServerIds().count()) {
      qDebug() << "Server" << GetOverlay()->GetId() << "connected to" <<
        m_connected_servers << "of" << GetOverlay()->GetServerIds().count() <<
        "servers.";
      return;
    }

    if(m_state == WAITING_FOR_SERVERS_AND_INIT) {
      m_state = WAITING_FOR_INIT;
      if(IsProposer()) {
        SendInit();
      }
    } else if(m_state == WAITING_FOR_SERVERS) {
      SendEnlist();
    }
  }

  void ServerSession::HandleDisconnect(
      const QSharedPointer<Connections::Connection> &con)
  {
    if(GetOverlay()->IsServer(con->GetRemoteId())) {
    }
  }

  void ServerSession::SendInit()
  {
    qDebug() << GetOverlay()->GetId() << "ServerSession::Init: sending Init";

    QByteArray nonce(16, 0);
    qint64 ctime = Utils::Time::GetInstance().MSecsSinceEpoch();
    ServerInit init(GetOverlay()->GetId(), nonce, ctime, QByteArray(16, 0));
    init.SetSignature(GetPrivateKey()->Sign(init.GetPayload()));

    foreach(const Connections::Id &remote_id, GetOverlay()->GetServerIds()) {
      GetOverlay()->SendNotification(remote_id, "Init", init.GetPacket());
    }
  }

  void ServerSession::HandleInit(const Messaging::Request &notification)
  {
    if(m_state == OFFLINE) {
      m_queue.append(notification);
      return;
    }

    QByteArray packet = notification.GetData().toByteArray();
    QSharedPointer<ServerInit> init(new ServerInit(packet));
    QSharedPointer<Connections::IOverlaySender> sender(
        notification.GetFrom().dynamicCast<Connections::IOverlaySender>());

    if(!sender) {
      qDebug() << "HandleInit - Invalid sender:" << notification.GetFrom();
      return;
    }

    if(GetOverlay()->GetServerIds().first() != sender->GetRemoteId()) {
      qDebug() << "HandleInit - wrong sender:" << notification.GetFrom();
      return;
    }

    ProcessInit(init);
  }

  bool ServerSession::ProcessInit(const QSharedPointer<ServerInit> &init)
  {
    if(m_init && (m_init->GetPacket() == init->GetPacket())) {
      return true;
    }

    QSharedPointer<Crypto::AsymmetricKey> key(GetKeyShare()->GetKey(
          GetOverlay()->GetServerIds().first().ToString()));
    if(!key->Verify(init->GetPayload(), init->GetSignature())) {
      qDebug() << "ProcessInit - invalid signature";
      return false;
    }

    if(m_init && m_init->GetTimestamp() >= init->GetTimestamp()) {
      qDebug() << "ProcessInit - older init" << m_init->GetTimestamp() <<
        init->GetTimestamp();
      return false;
    }

    m_init = init;

    if(m_state == WAITING_FOR_SERVERS_AND_INIT) {
      m_state = WAITING_FOR_SERVERS;
    } else if(m_state == WAITING_FOR_INIT) {
      SendEnlist();
    } else {
      qDebug() << "Think about it...";
    }

    return true;
  }

  void ServerSession::SendEnlist()
  {
    qDebug() << GetOverlay()->GetId() << "ServerSession::Enlist: sending Enlist";

    m_state = ENLISTING;

    m_enlist_msgs.clear();
    GenerateRoundData();

    ServerEnlist enlist(GetOverlay()->GetId(),
        m_init, GetEphemeralKey()->GetPublicKey(), GetOptionalPublic());
    enlist.SetSignature(GetPrivateKey()->Sign(enlist.GetPayload()));

    foreach(const Connections::Id &remote_id, GetOverlay()->GetServerIds()) {
      GetOverlay()->SendNotification(remote_id, "Enlist", enlist.GetPacket());
    }
  }

  void ServerSession::HandleEnlist(const Messaging::Request &notification)
  {
    if(m_state == OFFLINE) {
      m_queue.append(notification);
      return;
    }

    QByteArray packet = notification.GetData().toByteArray();
    QSharedPointer<ServerEnlist> enlist(new ServerEnlist(packet));
    QSharedPointer<Connections::IOverlaySender> sender(
        notification.GetFrom().dynamicCast<Connections::IOverlaySender>());

    if(!sender) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Enlist: Bad sender:"
        << notification.GetFrom()->ToString();
      return;
    }

    Connections::Id remote_id = sender->GetRemoteId();

    if(!GetOverlay()->IsServer(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Enlist: not a server:"
        << remote_id;
      return;
    }

    // If this is a new init message, we need to restart
    if(!ProcessInit(enlist->GetInit())) {
      return;
    }

    // This is just a repeat of the current init message with no new state
    if(m_enlist_msgs.contains(remote_id)) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Enlist: already have Enlist message" << remote_id;
      return;
    }

    if(m_state == WAITING_FOR_SERVERS) {
      m_queue.append(notification);
      return;
    }

    if(!GetKeyShare()->GetKey(remote_id.ToString())->Verify(enlist->GetPayload(),
          enlist->GetSignature()))
    {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Enlist: Invalid signature" << remote_id;
      return;
    }

    if(enlist->GetId() != remote_id) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Enlist: Remote peer's Id mismatch:" << remote_id << enlist->GetId();
      return;
    }

    if(!enlist->GetKey()->IsValid()) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Enlist: Invalid Ephemeral Key:" << remote_id;
      return;
    }

    m_enlist_msgs[remote_id] = enlist;
    if(m_enlist_msgs.count() != GetOverlay()->GetServerIds().size()) {
      qDebug() << GetOverlay()->GetId() <<
        "ServerSession::Enlist: have" << m_enlist_msgs.count() << "of" <<
        GetOverlay()->GetServerIds().size();
      return;
    }

    qDebug() << GetOverlay()->GetId() <<
      "ServerSession::Enlist: finished, sending Agree";

    Crypto::Hash hash;
    foreach(const QSharedPointer<ServerEnlist> &enlist, m_enlist_msgs) {
      hash.Update(enlist->GetPayload());
    }

    SetRoundId(hash.ComputeHash());
    ServerAgree agree(GetOverlay()->GetId(),
        GetRoundId(), GetEphemeralKey()->GetPublicKey(), GetOptionalPublic());
    agree.SetSignature(GetPrivateKey()->Sign(agree.GetPayload()));

    m_state = AGREEING;
    foreach(const Connections::Id &remote_id, GetOverlay()->GetServerIds()) {
      GetOverlay()->SendNotification(remote_id, "Agree", agree.GetPacket());
    }

    QList<Messaging::Request> queue = m_queue;
    m_queue.clear();
    foreach(const Messaging::Request &notification, queue) {
      if(notification.GetMethod() != "Agree") {
        continue;
      }
      HandleAgree(notification);
    }
  }

  void ServerSession::HandleAgree(const Messaging::Request &notification)
  {
    if(m_state == ENLISTING) {
      m_queue.append(notification);
      return;
    } else if(m_state != AGREEING) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Agree: message out of order" <<
        notification.GetFrom()->ToString() << "Current state:" << m_state;
      return;
    }

    QSharedPointer<Connections::Connection> sender =
      notification.GetFrom().dynamicCast<Connections::Connection>();

    if(!sender) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Agree: Bad sender:"
        << notification.GetFrom()->ToString();
      return;
    }

    Connections::Id remote_id = sender->GetRemoteId();
    if(!GetOverlay()->IsServer(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Agree: not a server:"
        << remote_id;
      return;
    }

    if(m_agree_msgs.contains(remote_id)) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Agree: already have Agree message" << remote_id;
      return;
    }

    QSharedPointer<ServerAgree> agree(new ServerAgree(
          notification.GetData().toByteArray()));

    if(agree->GetId() != remote_id) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Agree: Remote peer's Id mismatch:" << remote_id << agree->GetId();
      return;
    }

    if(!CheckServerAgree(*agree)) {
      return;
    }

    QSharedPointer<ServerEnlist> enlist = m_enlist_msgs[remote_id];
    if((enlist->GetId() != agree->GetId()) ||
        (enlist->GetKey() != agree->GetKey()) ||
        (enlist->GetOptional() != agree->GetOptional()))
    {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Agree: Agree message doesn't match Enlist:" << remote_id;
      return;
    }

    m_agree_msgs[remote_id] = agree;
    if(m_agree_msgs.count() != GetOverlay()->GetServerIds().size()) {
      qDebug() << GetOverlay()->GetId() <<
        "ServerSession::Agree: have" << m_agree_msgs.count() << "of" <<
        GetOverlay()->GetServerIds().size();
      return;
    }

    qDebug() << GetOverlay()->GetId() <<
      "ServerSession::Agree: finished, handling clients";

    SetServers(m_agree_msgs.values());
    m_agree = SerializeList<ServerAgree>(GetServers());

    m_state = REGISTERING;

    m_register_timer.Stop();
    Utils::TimerCallback *cb =
      new Utils::TimerMethod<ServerSession, int>(this,
          &ServerSession::FinishClientRegister, 0);

    m_register_timer = Utils::Timer::GetInstance().QueueCallback(cb, ROUND_TIMER);

    foreach(const Connections::Id &remote_id, m_queued_msgs.keys()) {
      ServerQueued queued(GetServers(), m_queued_msgs[remote_id]->GetNonce(), m_agree);
      queued.SetSignature(GetPrivateKey()->Sign(queued.GetPayload()));
      GetOverlay()->SendNotification(remote_id, "Queued", queued.GetPacket());
    }
  }

  void ServerSession::HandleQueue(const Messaging::Request &notification)
  {
    QSharedPointer<Connections::Connection> sender =
      notification.GetFrom().dynamicCast<Connections::Connection>();

    if(!sender) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Queue: Bad sender:"
        << notification.GetFrom()->ToString();
      return;
    }

    Connections::Id remote_id = sender->GetRemoteId();
    if(GetOverlay()->IsServer(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Queue: is a server:"
        << remote_id;
      return;
    }

    QSharedPointer<ClientQueue> clq(
        new ClientQueue(notification.GetData().toByteArray()));

    if(m_state == REGISTERING) {
      ServerQueued queued(GetServers(), clq->GetNonce(), m_agree);
      queued.SetSignature(GetPrivateKey()->Sign(queued.GetPayload()));
      GetOverlay()->SendNotification(remote_id, "Queued", queued.GetPacket());
      // Setup a timer
    } else {
      m_queued_msgs[remote_id] = clq;
    }
  }

  void ServerSession::HandleRegister(const Messaging::Request &notification)
  {
    if(m_state != REGISTERING) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::Register: message out of order" <<
        notification.GetFrom()->ToString() << "Current state:" << m_state;
      return;
    }

    QSharedPointer<Connections::Connection> sender =
      notification.GetFrom().dynamicCast<Connections::Connection>();

    if(!sender) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Register: Bad sender:"
        << notification.GetFrom()->ToString();
      return;
    }

    Connections::Id remote_id = sender->GetRemoteId();
    if(GetOverlay()->IsServer(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Register: is a server:"
        << remote_id;
      return;
    }

    QSharedPointer<ClientRegister> clr(
        new ClientRegister(notification.GetData().toByteArray()));
    if(m_registered_msgs.contains(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Register: already registered";
      return;
    } else if(clr->GetId() != remote_id) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::Register: sender mismatch";
      return;
    } else if(!CheckClientRegister(clr)) {
      return;
    }

    m_registered_msgs[remote_id] = clr;
    qDebug() << GetOverlay()->GetId() << "ServerSession::Register:" <<
      remote_id << "registered";
  }

  bool ServerSession::CheckClientRegister(const QSharedPointer<ClientRegister> &clr)
  {
    if(clr->GetRoundId() != GetRoundId()) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::CheckClientRegister" <<
        ": roundid mismatch";
      return false;
    } else if(!GetKeyShare()->GetKey(clr->GetId().ToString())->Verify(clr->GetPayload(),
          clr->GetSignature()))
    {
      qWarning() << GetOverlay()->GetId() << "ServerSession::CheckClientRegister" << 
        ": signature failure";
      return false;
    }
    return true;
  }

  void ServerSession::FinishClientRegister(const int &)
  {
    qDebug() << "ServerSession::FinishClientRegister:" <<
      "Finished waiting for clients.";
    SendList();
  }

  void ServerSession::SendList()
  {
    m_state = ROSTERING;
    SetClients(m_registered_msgs.values());
    ServerList list(GetClients());
    list.SetSignature(GetPrivateKey()->Sign(list.GetPayload()));

    foreach(const Connections::Id &remote_id, GetOverlay()->GetServerIds()) {
      GetOverlay()->SendNotification(remote_id, "List", list.GetPacket());
    }
  }

  void ServerSession::HandleList(const Messaging::Request &notification)
  {
    if(m_state != AGREEING && m_state != REGISTERING && m_state != ROSTERING) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::List: message out of order" <<
        notification.GetFrom()->ToString() << "Current state:" << m_state;
      return;
    }

    QSharedPointer<Connections::Connection> sender =
      notification.GetFrom().dynamicCast<Connections::Connection>();

    if(!sender) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::List: Bad sender:"
        << notification.GetFrom()->ToString();
      return;
    }

    Connections::Id remote_id = sender->GetRemoteId();
    if(!GetOverlay()->IsServer(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::List: isn't a server:"
        << remote_id;
      return;
    }

    if(m_list_received.contains(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::List: already have list:"
        << remote_id;
      return;
    }

    ServerList list(notification.GetData().toByteArray());
    foreach(const QSharedPointer<ClientRegister> &clr, list.GetRegisterList()) {
      if(!CheckClientRegister(clr)) {
        return;
      }
    }

    foreach(const QSharedPointer<ClientRegister> &clr, list.GetRegisterList()) {
      if(m_registered_msgs.contains(clr->GetId())) {
        // go with the lower server entry...
      }
      m_registered_msgs[clr->GetId()] = clr;
    }

    m_list_received[remote_id] = true;
    if(m_list_received.count() != GetOverlay()->GetServerIds().size()) {
      qDebug() << GetOverlay()->GetId() <<
        "ServerSession::List: have" << m_list_received.count() << "of" <<
        GetOverlay()->GetServerIds().size();
      return;
    }

    qDebug() << GetOverlay()->GetId() <<
      "ServerSession::List: finished, sending VerifyList";

    m_state = VERIFYING;
    SetClients(m_registered_msgs.values());
    QByteArray registered = SerializeList<ClientRegister>(GetClients());
    Crypto::Hash hash;
    m_registered = hash.ComputeHash(registered);
    ServerVerifyList verify(GetPrivateKey()->Sign(m_registered));
    foreach(const Connections::Id &remote_id, GetOverlay()->GetServerIds()) {
      GetOverlay()->SendNotification(remote_id, "VerifyList", verify.GetPacket());
    }

    QList<Messaging::Request> queue = m_queue;
    m_queue.clear();
    foreach(const Messaging::Request &notification, queue) {
      if(notification.GetMethod() != "VerifyList") {
        continue;
      }
      HandleVerifyList(notification);
    }
  }

  void ServerSession::HandleVerifyList(const Messaging::Request &notification)
  {
    if(m_state == ROSTERING) {
      m_queue.append(notification);
      return;
    } else if(m_state != VERIFYING) {
      qWarning() << GetOverlay()->GetId() <<
        "ServerSession::VerifyList: message out of order" <<
        notification.GetFrom()->ToString() << "Current state:" << m_state;
      return;
    }

    QSharedPointer<Connections::Connection> sender =
      notification.GetFrom().dynamicCast<Connections::Connection>();

    if(!sender) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::VerifyList: Bad sender:"
        << notification.GetFrom()->ToString();
      return;
    }

    Connections::Id remote_id = sender->GetRemoteId();
    if(!GetOverlay()->IsServer(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::VerifyList: isn't a server:"
        << remote_id;
      return;
    }

    if(m_verify.contains(remote_id)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::VerifyList: already have verification:"
        << remote_id;
      return;
    }

    ServerVerifyList verify(notification.GetData().toByteArray());
    QByteArray signature = verify.GetSignature();
    if(!GetKeyShare()->GetKey(remote_id.ToString())->Verify(m_registered, signature)) {
      qWarning() << GetOverlay()->GetId() << "ServerSession::VerifyList: invalid signature:"
        << remote_id;
      return;
    }

    m_verify[remote_id] = signature;
    if(m_verify.count() != GetOverlay()->GetServerIds().size()) {
      qDebug() << GetOverlay()->GetId() <<
        "ServerSession::VerifyList: have" << m_verify.count() << "of" <<
        GetOverlay()->GetServerIds().size();
      return;
    }
    
    qDebug() << GetOverlay()->GetId() <<
      "ServerSession::VerifyList: finished, sending Start";

    NextRound();
    GetStateMachine().StateComplete();
    m_state = COMMUNICATING;

    ServerStart start(GetClients(), m_verify.values());
    Connections::ConnectionTable &ct = GetOverlay()->GetConnectionTable();
    foreach(const QSharedPointer<Connections::Connection> &con, ct.GetConnections()) {
      if(m_registered_msgs.contains(con->GetRemoteId())) {
        GetOverlay()->SendNotification(con->GetRemoteId(), "Start", start.GetPacket());
      }
    }
    GetRound()->Start();
    emit RoundStarting(GetRound());
  }
}
}
