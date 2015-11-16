/*
 * SMPP Encoder/Decoder
 * Copyright (C) 2006 redtaza@users.sourceforge.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

// This program shows basic usage of the SMPP C++ API. 
// To compile and link using vc++ (Windows)
// cl -D__WINDOWS__ -nologo -EHsc -wd4996 -I..\src sample_app.cpp -link -LIBPATH:..\src "WS2_32.lib" smpp.lib
// To compile and static link using g++ (some platforms may require extra libraries)
// g++ -static -I../src -o prog sample_app.cpp -L../src -lsmpp

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <iostream>
#include <sstream>
#include <iterator>
#include <cerrno>
#ifdef __WINDOWS__
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "smpp.hpp"

namespace {
    // modifiy these to change connection/bind settings etc.
    const std::string ipaddr = "127.0.0.1";
    const Smpp::Uint16 port = 2775;

    const Smpp::SystemId sysid("sysid");
    const Smpp::Password pass("pass");
    const Smpp::SystemType systype("systype");
    const Smpp::Uint8 infver = 0x34;
    const Smpp::ServiceType servtype("SERV");
    const Smpp::Address srcaddr("234567");
    const Smpp::Address dstaddr("787878787878");
    const std::string msgtext = "Hello smsc";
}

// A socket class portable between unix and windows.
class Socket {
    public:
#ifdef __WINDOWS__
        typedef SOCKET type;
#else
        typedef int type;
#endif

    private:
        type s_;

        void system_error(const char* func) const {
            std::stringstream s;
            int err;
#ifdef __WINDOWS__
            err = WSAGetLastError();
            WSACleanup();
#else
            err = errno;
#endif
            s << func << " failed: " << strerror(err);
            throw Exception(s.str());
        }
        
    public:
        Socket() {
#ifdef __WINDOWS__
            WSADATA wsaData;
            int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
            if(iResult != NO_ERROR)
                printf("Error at WSAStartup()\n");
#endif
            s_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef __WINDOWS__
            if (s_ == INVALID_SOCKET) system_error("socket()");
#else
            if(s_ < 0) system_error("socket()");
#endif
        }

        ~Socket() throw() {
#ifdef __WINDOWS__
            closesocket(s_);
#else
            close(s_);
#endif
        }
        
        void connect(const char* addr, u_short port) const {
            sockaddr_in peer;

            peer.sin_family = AF_INET;
            peer.sin_addr.s_addr = inet_addr(addr);
            peer.sin_port = htons(port);

            int ret = ::connect(s_, (struct sockaddr*)&peer, sizeof(peer));
#ifdef __WINDOWS__
            if(ret == SOCKET_ERROR) system_error("connect()");
#else
            if(ret < 0) system_error("connect()");
#endif
        }

        int send(const Smpp::Uint8* buf, int len, int flags) const {
            int n = 0;
            while(n < len) {
                int ret = ::send(s_, (const char*)buf+n, len-n, flags);
                if(ret < 0)
                    return ret;
                n += ret;
            }
            return n;
        }
        
        int recv(Smpp::Uint8* buf, int len, int flags) const {
            int n = 0; // number of bytes read
            while(n < len) {
                int ret = ::recv(s_, (char*)buf+n, len-n, flags);
                if(ret == 0) // other side closed socket
                    return 0;
                else if(ret < 0) // error
                    return -1;
                n += ret;
            }
            return n;
        }
        
        struct Exception : public std::runtime_error {
            Exception(const std::string& s) : std::runtime_error(s) {}
        };
};

// local functions declarations that send and receive the SMPP PDUs.
namespace {
    // make a buffer - just a standard vector of chars
    typedef std::vector<Smpp::Uint8> Buffer;

    Buffer& read_smpp_pdu(const Socket&, Buffer&);

    void send_bind(const Socket&);
    void read_bind_resp(const Socket&);

    void send_enquire_link(const Socket& sd);
    void read_enquire_link_resp(const Socket& sd);

    void send_submit_sm(const Socket& sd);
    void read_submit_sm_resp(const Socket& sd);

    void send_data_sm(const Socket& sd);
    void read_data_sm_resp(const Socket& sd);

    Smpp::Uint32 read_deliver_sm(const Socket& sd);
    void send_deliver_sm_resp(const Socket& sd, Smpp::Uint32 seqnum);

    void send_unbind(const Socket&);
    void read_unbind_resp(const Socket&);
}

int
main(int argc, char** argv)
{
    try {

        Socket sd;
        sd.connect(ipaddr.c_str(), port);

        send_bind(sd);
        read_bind_resp(sd);

        send_enquire_link(sd);
        read_enquire_link_resp(sd);

        send_submit_sm(sd);
        read_submit_sm_resp(sd);

        Smpp::Uint32 seqnum = read_deliver_sm(sd);
        send_deliver_sm_resp(sd, seqnum);

        send_data_sm(sd);
        read_data_sm_resp(sd);

        seqnum = read_deliver_sm(sd);
        send_deliver_sm_resp(sd, seqnum);

        send_unbind(sd);
        read_unbind_resp(sd);

    } catch(Smpp::Error& e) {
        std::cerr << "SMPP error: " << e.what() << std::endl;
    } catch(Socket::Exception& e) {
        std::cerr << "Socket error: " << e.what() << std::endl;
    } catch(std::exception& e) {
        std::cerr << "std::exception error: " << e.what() << std::endl;
    } catch(...) {
        std::cerr << "Unknown exception" << std::endl;
    }
   
    exit(EXIT_SUCCESS); 
}

namespace {
    // function that reads an SMPP PDU from a socket.
    // The contents are placed in a std::vector which is returned
    Buffer& read_smpp_pdu(const Socket& s, Buffer& v) {
        // read the header
        v.resize(16);
        int n = s.recv(&v[0], 16, 0);
   
        // extract the length from the header
        // Smpp::get_command_length() is an auxiliary function defined in
        // aux_types.hpp used for extracting the command_length from an
        // encoded PDU.
        // There are similar functions for the other header parameters.
        Smpp::Uint32 len = Smpp::get_command_length((Smpp::Uint8*)&v[0]);
  
        // read the remainder of the PDU.
        // Some PDUs (e.g. enquire_link) only contain a header (16 octets)
        // hence the condition.
        if(len > 16) {
            v.resize(len); // resize to the number of octets.
            n = s.recv(&v[16], len-16, 0);
        }

        return v;
    }

    // send an SMPP bind command.
    void send_bind(const Socket& sd) {
        // build an SMPP bind_transceiver PDU.
        Smpp::BindTransceiver pdu;
        pdu.system_id(sysid);
        pdu.password(pass);
        pdu.system_type(systype);
        pdu.interface_version(infver);

        std::cout << "\nSending a bind transceiver\n";

        Smpp::Uint8* d = (Smpp::Uint8*)pdu.encode();
        Smpp::hex_dump(d , pdu.command_length(), std::cout);

        int bytesSent;
        bytesSent = sd.send(pdu.encode(), pdu.command_length(), 0);
    }
   
    // receive the bind response
    void read_bind_resp(const Socket& sd) {
        Buffer buf;
        buf = read_smpp_pdu(sd, buf);
    
        std::cout << "\nRead a bind response\n";
        Smpp::chex_dump(&buf[0], buf.size(), stdout);

        Smpp::BindTransceiverResp pdu;
        pdu.decode(&buf[0]);

        std::string sid = pdu.system_id();
        printf("response system_id: \"%s\"\n", sid.c_str());
    }
    
    // send an enquire link
    void send_enquire_link(const Socket& sd) {
        Smpp::EnquireLink pdu(0x02); // set the sequence number
        std::cout << "\nSending an enquire link\n";
        Smpp::Uint8* buff = (Smpp::Uint8*)pdu.encode();
        Smpp::hex_dump(buff , pdu.command_length(), std::cout);
        int bytesSent;
        bytesSent = sd.send(pdu.encode(), pdu.command_length(), 0);
    }
    
    // receive the enquire link response
    void read_enquire_link_resp(const Socket& sd) {
        Buffer buf;
        buf = read_smpp_pdu(sd, buf);
    
        std::cout << "\nRead an enquire link repsonse\n";
        Smpp::chex_dump(&buf[0], buf.size(), stdout);

        Smpp::EnquireLinkResp pdu;
        pdu.decode(&buf[0]);
    }

    // send an SMPP submit_sm
    void send_submit_sm(const Socket& sd) {
        // build an SMPP submit_sm PDU.
        Smpp::SubmitSm pdu;
        pdu.service_type(servtype);
        pdu.source_addr(Smpp::Address(srcaddr));
        pdu.destination_addr(
                Smpp::SmeAddress(Smpp::Ton(Smpp::Ton::International),
                                  Smpp::Npi(Smpp::Npi::E164),
                                  Smpp::Address(dstaddr)));
        pdu.registered_delivery(0x01);
        pdu.short_message(
                reinterpret_cast<const Smpp::Uint8*>(msgtext.data()),
                msgtext.length());

        std::cout << "\nSending a submit sm\n";
        Smpp::Uint8* d = (Smpp::Uint8*)pdu.encode();
        Smpp::chex_dump(d , pdu.command_length(), stdout);

        int bytesSent;
        bytesSent = sd.send(pdu.encode(), pdu.command_length(), 0);
    }
   
    // receive the submit sm response
    void read_submit_sm_resp(const Socket& sd) {
        Buffer buf;
        buf = read_smpp_pdu(sd, buf);
        std::cout << "\nRead a submit sm resp\n";
        Smpp::hex_dump(&buf[0], buf.size(), std::cout);
        Smpp::SubmitSmResp pdu;
        pdu.decode(&buf[0]);
        std::string sid = pdu.message_id();
        printf("response message_id: \"%s\"\n", sid.c_str());
    }
    
    // send a data sm
    void send_data_sm(const Socket& sd) {
        // build an SMPP data_sm PDU directly from the constructor.
        Smpp::DataSm pdu(0x00000020,
                          servtype,
                          Smpp::SmeAddress(srcaddr),
                          Smpp::SmeAddress(
                              Smpp::Ton(Smpp::Ton::International),
                              Smpp::Npi(Smpp::Npi::E164),
                              dstaddr),
                          Smpp::EsmClass(0x00),
                          Smpp::RegisteredDelivery(0x01),
                          Smpp::DataCoding(0x00));

        pdu.insert_array_tlv(
            Smpp::Tlv::message_payload,
            msgtext.length(),
            reinterpret_cast<const Smpp::Uint8*>(msgtext.data()));

        std::cout << "\nSending a data sm\n";
        Smpp::Uint8* d = (Smpp::Uint8*)pdu.encode();
        Smpp::chex_dump(d , pdu.command_length(), stdout);

        int bytesSent;
        bytesSent = sd.send(pdu.encode(), pdu.command_length(), 0);
    }
   
    // receive the data sm response 
    void read_data_sm_resp(const Socket& sd) {
        Buffer buf;
        buf = read_smpp_pdu(sd, buf);
        std::cout << "\nRead a data sm response\n";
        Smpp::hex_dump(&buf[0], buf.size(), std::cout);
        Smpp::DataSmResp pdu;
        pdu.decode(&buf[0]);
        std::string sid = pdu.message_id();
        printf("response message_id: \"%s\"\n", sid.c_str());
    }

    // receive a deliver sm
    Smpp::Uint32 read_deliver_sm(const Socket& sd) {
        Buffer buf;
        buf = read_smpp_pdu(sd, buf);
        std::cout << "\nRead a deliver sm\n";
        Smpp::hex_dump(&buf[0], buf.size(), std::cout);
        Smpp::DeliverSm pdu(&buf[0]);
   
        if(pdu.sm_length())
            std::copy(pdu.short_message().begin(), pdu.short_message().end(),
                       std::ostream_iterator<char>(std::cout));
        else {
            const Smpp::Tlv* tlv = pdu.find_tlv(Smpp::Tlv::message_payload);
            if(tlv)
                std::copy(tlv->value(), tlv->value() + tlv->length(),
                           std::ostream_iterator<char>(std::cout));
            else
                printf("No short message in delivey receipt");
        }
        std::cout << '\n';

        const Smpp::Tlv* msgstate = pdu.find_tlv(Smpp::Tlv::message_state);
        if(msgstate)
            printf("Message state: 0x%02x\n", *msgstate->value());
        
        const Smpp::Tlv* necode = pdu.find_tlv(Smpp::Tlv::network_error_code);
        if(necode) {
            printf("Network Type:   0x%02x\n", *necode->value());
            printf("Error code:   0x%04x\n", Smpp::ntoh16(necode->value()+1));
        }

        return pdu.sequence_number();
    }

    // send a deliver sm response
    void send_deliver_sm_resp(const Socket& sd, Smpp::Uint32 seqnum) {
        Smpp::DeliverSmResp pdu(Smpp::CommandStatus::ESME_ROK, seqnum);
        std::cout << "\nSending a deliver sm response\n";
        Smpp::Uint8* buff = (Smpp::Uint8*)pdu.encode();
        Smpp::hex_dump(buff , pdu.command_length(), std::cout);
        int bytesSent;
        bytesSent = sd.send(pdu.encode(), pdu.command_length(), 0);
    }

    // send an unbind
    void send_unbind(const Socket& sd) {
        Smpp::Unbind pdu(0x7fffffff); // set the sequence number
        std::cout << "\nSending an unbind\n";
        Smpp::Uint8* buff = (Smpp::Uint8*)pdu.encode();
        Smpp::hex_dump(buff , pdu.command_length(), std::cout);
        int bytesSent;
        bytesSent = sd.send(pdu.encode(), pdu.command_length(), 0);
    }
   
    // receive the unbind response
    void read_unbind_resp(const Socket& sd) {
        Buffer buf;
        buf = read_smpp_pdu(sd, buf);
    
        std::cout << "\nRead an unbind response\n";
        Smpp::chex_dump(&buf[0], buf.size(), stdout);

        Smpp::UnbindResp pdu;
        pdu.decode(&buf[0]);
    }
}
 
