#include "Session.hpp"

#include "Crypto/DiffieHellman.hpp"
#include "Crypto/DsaPrivateKey.hpp"

namespace Dissent {
namespace Session {
  Session::Session(const QSharedPointer<SessionSharedState> &shared_state) :
    m_shared_state(shared_state),
    m_sm(shared_state)
  {
    GetOverlay()->GetRpcHandler()->Register("SessionData", this, "HandleData");
    QObject::connect(m_shared_state->GetRoundAnnouncer().data(),
        SIGNAL(Announce(const QSharedPointer<Anonymity::Round> &)),
        this,
        SLOT(HandleRoundStartedSlot(const QSharedPointer<Anonymity::Round> &)));
  }

  Session::~Session()
  {
    GetOverlay()->GetRpcHandler()->Unregister("SessionData");
  }

  void Session::OnStart()
  {
    GetStateMachine().StateComplete();
  }

  void Session::Send(const QByteArray &data)
  {
    GetSharedState()->AddData(data);
  }

  void Session::HandleRoundStartedSlot(const QSharedPointer<Anonymity::Round> &round)
  {
    round->SetSink(this);
    QObject::connect(round.data(), SIGNAL(Finished()),
        this, SLOT(HandleRoundFinishedSlot()));
    emit RoundStarting(round);
  }

  void Session::HandleRoundFinishedSlot()
  { 
    Anonymity::Round *round = qobject_cast<Anonymity::Round *>(sender());
    if(round != GetSharedState()->GetRound().data()) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }
  
    qDebug() << ToString() << "- round finished due to -" <<
      round->GetStoppedReason();
    
    GetSharedState()->RoundFinished(round->GetSharedPointer());

    emit RoundFinished(GetSharedState()->GetRound());
  
    if(Stopped()) {
      qDebug() << "Session stopped.";
      return;
    }

    HandleRoundFinished();
  }

  void Session::HandleData(const Messaging::Request &notification)
  {
    QByteArray packet = notification.GetData().toByteArray();
    QSharedPointer<Messaging::Message> msg = m_md.ParseMessage(packet);
    if(msg->GetMessageType() == Messaging::Message::GetBadMessageType()) {
      return;
    }

    m_sm.ProcessData(notification.GetFrom(), msg);
  }

  void Session::HandleStop(const Messaging::Request &)
  {
    // Is it a valid stop?
    OnStop();
  }

  void Session::HandleConnection(
      const QSharedPointer<Connections::Connection> &con)
  {
    GetStateMachine().HandleConnection(con->GetRemoteId());
  }

  void Session::HandleDisconnect(
      const QSharedPointer<Connections::Connection> &con)
  {
    GetStateMachine().HandleDisconnection(con->GetRemoteId());
  }
}
}
