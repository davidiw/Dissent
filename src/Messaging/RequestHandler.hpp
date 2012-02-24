#ifndef DISSENT_MESSAGING_REQUEST_HANDLER_H_GUARD
#define DISSENT_MESSAGING_REQUEST_HANDLER_H_GUARD

#include <QObject>

#include "Request.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Used to create a request callback
   */
  class RequestHandler : public QObject {
    Q_OBJECT

    public:
      RequestHandler(const QObject *obj, const char *func)
      {
        QString slot = QString::number(QSLOT_CODE) + func +
          "(const Request &)" + QLOCATION;

        QObject::connect(this,
            SIGNAL(MakeRequestSignal(const Request &)),
            obj,
            slot.toUtf8().data());
      }

      /**
       * Destructor
       */
      virtual ~RequestHandler() {}

      inline void MakeRequest(const Request &request) const
      {
        emit MakeRequestSignal(request);
      }

    signals:
      void MakeRequestSignal(const Request &request) const;
  };
}
}

#endif
