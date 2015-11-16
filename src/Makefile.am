ACLOCAL_AMFLAGS = -I m4
lib_LIBRARIES = libsmppcxx.a
libsmppcxx_a_SOURCES =  \
alert_notification.cpp     broadcast_sm.cpp              data_sm_resp.cpp       outbind.cpp                  submit_multi_resp.cpp \
aux_types.cpp              broadcast_sm_resp.cpp         deliver_sm.cpp         query_broadcast_sm.cpp       submit_sm.cpp \
bind_receiver.cpp          buffer.cpp                    deliver_sm_resp.cpp    query_broadcast_sm_resp.cpp  submit_sm_resp.cpp \
bind_receiver_resp.cpp     cancel_broadcast_sm.cpp       enquire_link.cpp       query_sm.cpp                 unbind.cpp \
bind_transceiver.cpp       cancel_broadcast_sm_resp.cpp  enquire_link_resp.cpp  query_sm_resp.cpp            unbind_resp.cpp \
bind_transceiver_resp.cpp  cancel_sm.cpp                 error.cpp              replace_sm.cpp \
bind_transmitter.cpp       cancel_sm_resp.cpp            generic_nack.cpp       replace_sm_resp.cpp \
bind_transmitter_resp.cpp  data_sm.cpp                   header.cpp             submit_multi.cpp
libsmppcxx_a_CPPFLAGS = -I ${top_srcdir}/include

lib_LTLIBRARIES = libsmppcxx.la
libsmppcxx_la_SOURCES =	\
alert_notification.cpp     broadcast_sm.cpp              data_sm_resp.cpp       outbind.cpp                  submit_multi_resp.cpp \
aux_types.cpp              broadcast_sm_resp.cpp         deliver_sm.cpp         query_broadcast_sm.cpp       submit_sm.cpp \
bind_receiver.cpp          buffer.cpp                    deliver_sm_resp.cpp    query_broadcast_sm_resp.cpp  submit_sm_resp.cpp \
bind_receiver_resp.cpp     cancel_broadcast_sm.cpp       enquire_link.cpp       query_sm.cpp                 unbind.cpp \
bind_transceiver.cpp       cancel_broadcast_sm_resp.cpp  enquire_link_resp.cpp  query_sm_resp.cpp            unbind_resp.cpp \
bind_transceiver_resp.cpp  cancel_sm.cpp                 error.cpp              replace_sm.cpp \
bind_transmitter.cpp       cancel_sm_resp.cpp            generic_nack.cpp       replace_sm_resp.cpp \
bind_transmitter_resp.cpp  data_sm.cpp                   header.cpp             submit_multi.cpp 
libsmppcxx_la_CPPFLAGS=-fPIC -I ${top_srcdir}/include
libsmppcxx_la_LDFLAGS= -shared -fPIC
