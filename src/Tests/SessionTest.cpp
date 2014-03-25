#include "DissentTest.hpp"
#include "OverlayTest.hpp"
#include "SessionTest.hpp"

namespace Dissent {
namespace Tests {
  Sessions BuildSessions(const OverlayNetwork &network, CreateRound create_round)
  {
    DsaPrivateKey shared_key;
    QSharedPointer<KeyShare> keys(new KeyShare());

    Sessions sessions;
    sessions.network = network;
    sessions.keys = keys;

    foreach(const OverlayPointer &server, network.first) {
      QSharedPointer<AsymmetricKey> key(new DsaPrivateKey(
            shared_key.GetModulus(), shared_key.GetSubgroupOrder(),
            shared_key.GetGenerator()));
      keys->AddKey(server->GetId().ToString(), key->GetPublicKey());

      ServerPointer ss = MakeSession<ServerSession>(
            server, key, keys, create_round);
      sessions.servers.append(ss);
      sessions.private_keys[server->GetId().ToString()] = key;

      QSharedPointer<BufferSink> sink(new BufferSink());
      sessions.sinks.append(sink);
      ss->SetSink(sink.data());
    }

    QList<ClientPointer> clients;
    foreach(const OverlayPointer &client, network.second) {
      QSharedPointer<AsymmetricKey> key(new DsaPrivateKey(
            shared_key.GetModulus(), shared_key.GetSubgroupOrder(),
            shared_key.GetGenerator()));
      keys->AddKey(client->GetId().ToString(), key->GetPublicKey());

      ClientPointer cs = MakeSession<ClientSession>(
            client, key, keys, create_round);
      sessions.clients.append(cs);
      sessions.private_keys[client->GetId().ToString()] = key;

      QSharedPointer<BufferSink> sink(new BufferSink());
      sessions.sinks.append(sink);
      cs->SetSink(sink.data());
    }
    
    return sessions;
  }

  Sessions BuildSessions(const OverlayNetwork &network)
  {
    return BuildSessions(network, TCreateRound<NullRound>);
  }

  void StartSessions(const Sessions &sessions)
  {
    foreach(const ServerPointer &ss, sessions.servers) {
      ss->Start();
    }

    foreach(const ClientPointer &cs, sessions.clients) {
      cs->Start();
    }
  }

  void StartRound(const Sessions &sessions)
  {
    SignalCounter counter;
    foreach(const ServerPointer &ss, sessions.servers) {
      QObject::connect(ss.data(),
          SIGNAL(RoundStarting(const QSharedPointer<Anonymity::Round> &)),
          &counter, SLOT(Counter()));
    }

    foreach(const ClientPointer &cs, sessions.clients) {
      QObject::connect(cs.data(),
          SIGNAL(RoundStarting(const QSharedPointer<Anonymity::Round> &)),
          &counter, SLOT(Counter()));
    }

    RunUntil(counter, sessions.servers.count() + sessions.clients.count());
  }

  void CompleteRound(const Sessions &sessions)
  {
    SignalCounter counter;
    foreach(const ServerPointer &ss, sessions.servers) {
      QObject::connect(ss.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Anonymity::Round> &)),
          &counter, SLOT(Counter()));
    }

    foreach(const ClientPointer &cs, sessions.clients) {
      QObject::connect(cs.data(),
          SIGNAL(RoundFinished(const QSharedPointer<Anonymity::Round> &)),
          &counter, SLOT(Counter()));
    }

    RunUntil(counter, sessions.servers.count() + sessions.clients.count());
  }

  void StopSessions(const Sessions &sessions)
  {
    foreach(const ServerPointer &ss, sessions.servers) {
      ss->Stop("Finished");
    }

    foreach(const ClientPointer &cs, sessions.clients) {
      cs->Stop("Finished");
    }
  }
  
  void SendTest(const Sessions &sessions)
  {
    qDebug() << "Starting SendTest";
    QList<QByteArray> messages;
    CryptoRandom rand;

    foreach(const QSharedPointer<BufferSink> &sink, sessions.sinks) {
      sink->Clear();
    }

    foreach(const ClientPointer &cs, sessions.clients) {
      QByteArray msg(64, 0);
      rand.GenerateBlock(msg);
      messages.append(msg);
      cs->Send(msg);
    }

    StartRound(sessions);
    CompleteRound(sessions);

    foreach(const QSharedPointer<BufferSink> &sink, sessions.sinks) {
      EXPECT_EQ(messages.size(), sink->Count());
      for(int idx = 0; idx < sink->Count(); idx++) {
        EXPECT_TRUE(messages.contains(sink->At(idx).second));
      }
    }
    qDebug() << "Finished SendTest";
  }

  void DisconnectServer(Sessions &sessions, bool hard)
  {
    qDebug() << "Disconnecting server" << hard;

    int server_count = sessions.servers.count();
    CryptoRandom rand;
    int idx = rand.GetInt(0, server_count);
    OverlayPointer op_disc = sessions.network.first[idx];

    if(hard) {
      op_disc->Stop();
      sessions.servers[idx]->Stop();
      // This will need to be adjusted if we support offline servers
      Time::GetInstance().IncrementVirtualClock(60000);
      Timer::GetInstance().VirtualRun();

      OverlayPointer op(new Overlay(op_disc->GetId(),
            op_disc->GetLocalEndpoints(),
            op_disc->GetRemoteEndpoints(),
            op_disc->GetServerIds()));
      op->SetSharedPointer(op);
      sessions.network.first[idx] = op;
      ServerPointer ss = MakeSession<ServerSession>(
            op, sessions.private_keys[op->GetId().ToString()],
            sessions.keys, TCreateRound<NullRound>);
      sessions.servers[idx] = ss;

      QSharedPointer<BufferSink> sink(new BufferSink());
      sessions.sinks[idx] = sink;
      ss->SetSink(sink.data());

      op->Start();
      ss->Start();
    } else {
      int disc_count = rand.GetInt(0, server_count - 1);
      QHash<int, bool> disced;
      disced[idx] = true;
      while(disced.size() < disc_count) {
        int to_disc = rand.GetInt(0, server_count);
        if(disced.contains(to_disc)) {
          continue;
        }
        disced[to_disc] = true;
        Id remote = sessions.network.first[to_disc]->GetId();
        op_disc->GetConnectionTable().GetConnection(remote)->Disconnect();
      }
    }
    StartRound(sessions);
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
    qDebug() << "Starting sessions...";
    StartSessions(sessions);
    SendTest(sessions);
    SendTest(sessions);
    DisconnectServer(sessions, true);
    SendTest(sessions);
    DisconnectServer(sessions, false);
    SendTest(sessions);
    SendTest(sessions);
    StopSessions(sessions);

    StopNetwork(sessions.network);
    VerifyStoppedNetwork(sessions.network);
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
    qDebug() << "Starting sessions...";
    StartSessions(sessions);
    SendTest(sessions);
    SendTest(sessions);
    DisconnectServer(sessions, true);
    SendTest(sessions);
    SendTest(sessions);
    StopSessions(sessions);

    StopNetwork(sessions.network);
    VerifyStoppedNetwork(sessions.network);
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
    qDebug() << "Starting sessions...";
    StartSessions(sessions);
    SendTest(sessions);
    SendTest(sessions);
    DisconnectServer(sessions, true);
    SendTest(sessions);
    DisconnectServer(sessions, false);
    SendTest(sessions);
    SendTest(sessions);
    StopSessions(sessions);

    StopNetwork(sessions.network);
    VerifyStoppedNetwork(sessions.network);
    ConnectionManager::UseTimer = true;
  }
}
}
