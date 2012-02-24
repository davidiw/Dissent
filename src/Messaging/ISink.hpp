#ifndef DISSENT_ISINK_H_GUARD
#define DISSENT_ISINK_H_GUARD

#include <QByteArray>
#include <QObject>
#include <QSharedPointer>

namespace Dissent {
namespace Messaging {
  class ISender;

  /**
   * Handle asynchronous data input
   */
  class ISink : public QObject {
    Q_OBJECT

    public:
      /**
       * Handle incoming data from a source
       * @param data message from the remote peer
       * @param from a path way back to the remote sender
       */
      virtual void HandleData(const QSharedPointer<ISender> &from,
          const QByteArray &data) = 0;

      /**
       * Virtual destructor...
       */
      virtual ~ISink() {}

    public slots:
      /**
       * Handle incoming data from a source
       * @param data message from the remote peer
       * @param from a path way back to the remote sender
       */
      virtual void HandleDataSlot(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        HandleData(from, data);
      }
  };
}
}

#endif
