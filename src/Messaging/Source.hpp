#ifndef DISSENT_SOURCE_H_GUARD
#define DISSENT_SOURCE_H_GUARD

#include <QDebug>
#include <QSharedPointer>

#include "ISink.hpp"

namespace Dissent {
namespace Messaging {
  class ISender;

  /**
   * Produces data to be received by a sink
   */
  class Source : public QObject {
    Q_OBJECT

    public:
      /**
       * Push data from this source into a sink, this hides some of the
       * nastiness associated w/ Qt slots and signals
       * @param sink the sink to push data into
       */
      void SetSink(const ISink &sink)
      {
        QObject::connect(this,
            SIGNAL(PushDataSignal(const QSharedPointer<ISender> &,
                const QByteArray &)),
            &sink,
            SLOT(HandleDataSlot(const QSharedPointer<ISender> &,
                const QByteArray &)));
      }

      virtual ~Source() {}

    signals:
      /**
       * Pushes data into the sink
       * @param from the remote sending party
       * @param data the message
       */
      void PushDataSignal(const QSharedPointer<ISender> &from,
          const QByteArray &data);

    protected:
      /**
       * Pushes data into the sink
       * @param from the remote sending party
       * @param data the message
       */
      void PushData(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        emit PushDataSignal(from, data);
      }
  };
}
}

#endif
