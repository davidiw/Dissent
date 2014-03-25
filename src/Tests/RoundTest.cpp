#include "DissentTest.hpp"
#include "OverlayTest.hpp"
#include "SessionTest.hpp"

namespace Dissent {
namespace Tests {
  template <typename T> void TestRoundBasic()
  {
    Timer::GetInstance().UseVirtualTime();
    ConnectionManager::UseTimer = false;
    OverlayNetwork net = ConstructOverlay(2, 10);
    VerifyStoppedNetwork(net);
    StartNetwork(net);
    VerifyNetwork(net);

    Sessions sessions = BuildSessions<T>(net);
    qDebug() << "Starting sessions...";
    StartSessions(sessions);
    SendTest(sessions);
    /*
    SendTest(sessions);
    DisconnectServer(sessions, true);
    SendTest(sessions);
    DisconnectServer(sessions, false);
    SendTest(sessions);
    SendTest(sessions);
    StopSessions(sessions);

    StopNetwork(sessions.network);
    VerifyStoppedNetwork(sessions.network);
    */
    ConnectionManager::UseTimer = true;
  }

  TEST(NeffShuffleRound, Basic)
  {
    TestRoundBasic<NeffShuffleRound>();
  }
}
}
