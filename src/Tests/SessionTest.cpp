#include "DissentTest.hpp"
#include "OverlayTest.hpp"

namespace Dissent {
namespace Tests {
  typedef QSharedPointer<ServerSession> ServerPointer;
  typedef QSharedPointer<ClientSession> ClientPointer;
  typedef QPair<QList<ServerPointer>, QList<ClientPointer> > Sessions;
  typedef QList<QSharedPointer<BufferSink> > Sinks;

  Sessions BuildSessions(const OverlayNetwork &network)
  {
    DsaPrivateKey shared_key;
    QSharedPointer<KeyShare> keys(new KeyShare());

    QList<ServerPointer> servers;
    foreach(const OverlayPointer &server, network.first) {
      QSharedPointer<AsymmetricKey> key(new DsaPrivateKey(
            shared_key.GetModulus(), shared_key.GetSubgroupOrder(),
            shared_key.GetGenerator()));
      keys->AddKey(server->GetId().ToString(), key);

      ServerPointer ss = MakeSession<ServerSession>(
            server, key, keys, TCreateRound<NullRound>);
      servers.append(ss);
    }

    QList<ClientPointer> clients;
    foreach(const OverlayPointer &client, network.second) {
      QSharedPointer<AsymmetricKey> key(new DsaPrivateKey(
            shared_key.GetModulus(), shared_key.GetSubgroupOrder(),
            shared_key.GetGenerator()));
      keys->AddKey(client->GetId().ToString(), key);

      ClientPointer cs = MakeSession<ClientSession>(
            client, key, keys, TCreateRound<NullRound>);
      clients.append(cs);
    }
    
    return Sessions(servers, clients);
  }

  Sinks SetupSinks(const Sessions &sessions)
  {
    Sinks sinks;
    foreach(const ServerPointer &ss, sessions.first) {
      QSharedPointer<BufferSink> sink(new BufferSink());
      sinks.append(sink);
      ss->SetSink(sink.data());
    }

    foreach(const ClientPointer &cs, sessions.second) {
      QSharedPointer<BufferSink> sink(new BufferSink());
      sinks.append(sink);
      cs->SetSink(sink.data());
    }

    return sinks;
  }

  void StartSessions(const Sessions &sessions)
  {
    foreach(const ServerPointer &ss, sessions.first) {
      ss->Start();
    }

    foreach(const ClientPointer &cs, sessions.second) {
      cs->Start();
    }
  }

  void StartRound(const Sessions &sessions)
  {
    SignalCounter counter;
    foreach(const ServerPointer &ss, sessions.first) {
      QObject::connect(ss.data(),
          SIGNAL(RoundStarting(const QSharedPointer<Anonymity::Round> &)),
          &counter, SLOT(Counter()));
    }

    foreach(const ClientPointer &cs, sessions.second) {
      QObject::connect(cs.data(),
          SIGNAL(RoundStarting(const QSharedPointer<Anonymity::Round> &)),
          &counter, SLOT(Counter()));
    }

    RunUntil(counter, sessions.first.count() + sessions.second.count());
  }

  void CompleteRound(const Sessions &sessions)
  {
    SignalCounter counter;
    foreach(const ServerPointer &ss, sessions.first) {
      QObject::connect(ss.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Anonymity::Round> &)),
          &counter, SLOT(Counter()));
    }

    foreach(const ClientPointer &cs, sessions.second) {
      QObject::connect(cs.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Anonymity::Round> &)),
          &counter, SLOT(Counter()));
    }

    RunUntil(counter, sessions.first.count() + sessions.second.count());
  }

  void StopSessions(const Sessions &sessions)
  {
    foreach(const ServerPointer &ss, sessions.first) {
      ss->Stop("Finished");
    }

    foreach(const ClientPointer &cs, sessions.second) {
      cs->Stop("Finished");
    }
  }
  
  void SendTest(const Sessions &sessions, const Sinks &sinks)
  {
    QList<QByteArray> messages;
    CryptoRandom rand;

    foreach(const QSharedPointer<BufferSink> &sink, sinks) {
      sink->Clear();
    }

    foreach(const ClientPointer &cs, sessions.second) {
      QByteArray msg(128, 0);
      rand.GenerateBlock(msg);
      messages.append(msg);
      cs->Send(msg);
    }

    StartRound(sessions);
    CompleteRound(sessions);

    foreach(const QSharedPointer<BufferSink> &sink, sinks) {
      EXPECT_EQ(messages.size(), sink->Count());
      for(int idx = 0; idx < messages.count(); idx++) {
        EXPECT_EQ(messages[idx], sink->At(idx).second);
      }
    }
  }

  TEST(Session, Servers)
  {
    Timer::GetInstance().UseVirtualTime();
    ConnectionManager::UseTimer = false;
    OverlayNetwork net = ConstructOverlay(10, 0);
    VerifyStoppedNetwork(net);
    StartNetwork(net);
    VerifyNetwork(net);

    Sessions sessions = BuildSessions(net);
    Sinks sinks = SetupSinks(sessions);
    qDebug() << "Starting sessions...";
    StartSessions(sessions);
    SendTest(sessions, sinks);
    StopSessions(sessions);

    StopNetwork(net);
    VerifyStoppedNetwork(net);
    ConnectionManager::UseTimer = true;
  }

  TEST(Session, ClientsServer)
  {
    Timer::GetInstance().UseVirtualTime();
    ConnectionManager::UseTimer = false;
    OverlayNetwork net = ConstructOverlay(1, 10);
    VerifyStoppedNetwork(net);
    StartNetwork(net);
    VerifyNetwork(net);

    Sessions sessions = BuildSessions(net);
    Sinks sinks = SetupSinks(sessions);
    qDebug() << "Starting sessions...";
    StartSessions(sessions);
    SendTest(sessions, sinks);
    StopSessions(sessions);

    StopNetwork(net);
    VerifyStoppedNetwork(net);
    ConnectionManager::UseTimer = true;
  }

  TEST(Session, ClientsServers)
  {
    Timer::GetInstance().UseVirtualTime();
    ConnectionManager::UseTimer = false;
    OverlayNetwork net = ConstructOverlay(10, 100);
    VerifyStoppedNetwork(net);
    StartNetwork(net);
    VerifyNetwork(net);

    Sessions sessions = BuildSessions(net);
    Sinks sinks = SetupSinks(sessions);
    qDebug() << "Starting sessions...";
    StartSessions(sessions);
    SendTest(sessions, sinks);
    StopSessions(sessions);

    StopNetwork(net);
    VerifyStoppedNetwork(net);
    ConnectionManager::UseTimer = true;
  }
}
}
