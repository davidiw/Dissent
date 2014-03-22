#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  typedef QSharedPointer<Overlay> OverlayPointer;
  typedef QPair<QList<OverlayPointer>, QList<OverlayPointer> > OverlayNetwork;

  OverlayNetwork ConstructOverlay(int servers, int clients);
  void StartNetwork(const OverlayNetwork &network);
  void VerifyNetwork(const OverlayNetwork &network);
  void StopNetwork(const OverlayNetwork &network);
  void VerifyStoppedNetwork(const OverlayNetwork &network);
}
}
