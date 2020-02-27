/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_RoutingInfo.hpp>
#include <E/E_System.hpp>
#include "TCPAssignment.hpp"
#include <unistd.h>
#include <stdlib.h>
#include <cmath>

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
    NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
    SystemCallInterface(AF_INET, IPPROTO_TCP, host),
    NetworkLog(host->getNetworkSystem()),
    TimerModule(host->getSystem())
{
  
}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
  this->clientSeq = 10;  // sequence number for client side

  TCPreadBuffer = (uint8_t *)malloc(51200); // Buffer to store data if there's no pending reads
  readBufferReceiveStart = 0; // index of TCPreadBuffer to mark where to receive data from network
  readBufferSentLast = 0;     // index of TCPreadBuffer to mark where to send to the app
  
  unACKedbytes = 0; // Count the number of unACKed bytes
  isDup = 0;  // Variable to check 3 dup ACK for fast retransmit
  
  // Variables for congestion control
  cwnd = MSS;
  rwnd = 51200;
  ssthresh = 64 * 1024;
  dupACKcount = 0;
  congState = SS;  // congestion state = slow start

  // Variables to calculate RTO
  RTT = DEFAULT_RTT;
  SRTT = RTT;
  RTTVAR = RTT/2;
  RTO = SRTT + (K*RTTVAR);
}

void TCPAssignment::finalize()
{
	serverMap.clear();
	clientMap.clear();
  fdToAddr.clear();
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
  switch(param.syscallNumber)
  {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
    break;
  case CONNECT:
    this->syscall_connect(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr*>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr *>(param.param2_ptr),
        (socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr *>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr *>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
  // src is dst of new packet, dst is src of new packet
  uint32_t src_ip, dst_ip, big_src_ip, big_dst_ip, receivedSeq, receivedAck;
  uint16_t src_port, dst_port, big_src_port, big_dst_port, rcvRwnd;
  uint8_t flags, newFlags;
  packet->readData(14+12, &big_src_ip, 4); 
  packet->readData(14+16, &big_dst_ip, 4);
  packet->readData(34, &big_src_port, 2);
  packet->readData(36, &big_dst_port, 2);
  packet->readData(47, &flags, 1);
  packet->readData(38, &receivedSeq, 4);
  packet->readData(42, &receivedAck, 4);
  packet->readData(48, &rcvRwnd, 2);
  src_ip = ntohl(big_src_ip);
  dst_ip = ntohl(big_dst_ip);
  src_port = ntohs(big_src_port);
  dst_port = ntohs(big_dst_port);
  receivedSeq = ntohl(receivedSeq);
  receivedAck = ntohl(receivedAck);
  rwnd = ntohs(rcvRwnd);

  /** Check checksum **/
  uint16_t rcvCksum;
  uint16_t zeroCksum = 0;
  size_t cksumRange = packet->getSize() - 34;
  packet->readData(50, &rcvCksum, 2);
  rcvCksum = ntohs(rcvCksum);
  packet->writeData(50, &zeroCksum, 2);
  uint8_t bufForCksum[532];
  memset(bufForCksum, 0, 532);
  packet->readData(34, bufForCksum, cksumRange);
  uint16_t calcCksum = ~NetworkUtil::tcp_sum(htonl(src_ip), htonl(dst_ip), bufForCksum, cksumRange);
  if (rcvCksum != calcCksum)
    return;
  /*******************/

  int sockfd;
  uint64_t sockKey1;

  /*** Find socket with src and dst address of packet ***/
  auto iterAddr = this->fdToAddr.begin();
  // IF flag is not SYN, find sockfd with TCP context
  if (flags != SYN) {
    while (iterAddr != this->fdToAddr.end()) {
      if ((std::get<1>(iterAddr->second) == dst_port) 
          && (std::get<2>(iterAddr->second) == dst_ip || std::get<2>(iterAddr->second) == 0)
          && (std::get<3>(iterAddr->second) == src_port)
          && (std::get<4>(iterAddr->second) == src_ip)) {
        sockfd = (int)((iterAddr->first)&0xFFFFFFFF);
        sockKey1 = iterAddr->first;
        break;
      }
      iterAddr++;
    }
  }
  else {  // IF flag is SYN, find listening socket
    while (iterAddr != this->fdToAddr.end()) {
      if ((std::get<1>(iterAddr->second) == dst_port) 
          && (std::get<2>(iterAddr->second) == dst_ip || std::get<2>(iterAddr->second) == 0)
          && (std::get<3>(iterAddr->second) == 0)) {
        sockfd = (int)((iterAddr->first)&0xFFFFFFFF);
        sockKey1 = iterAddr->first;
        break;
      }
      iterAddr++;
    }
    // if statement is for TestConnect_SimultanouesConnect
    if (iterAddr == this->fdToAddr.end()) {
      iterAddr = this->fdToAddr.begin();
      while (iterAddr != this->fdToAddr.end()) {
        if ((std::get<1>(iterAddr->second) == dst_port) 
            && (std::get<2>(iterAddr->second) == dst_ip || std::get<2>(iterAddr->second) == 0)) {
          sockfd = (int)((iterAddr->first)&0xFFFFFFFF);
          sockKey1 = iterAddr->first;
          break;
        }
        iterAddr++;
      }
    }
  }
  
  /* Find socket information with sockfd and pid */
  bool isServer;
  auto iterMapS = this->serverMap.begin();
  auto iterMapC = this->clientMap.begin();
  serverSocketEntry * serverSocket;
  clientSocketEntry * clientSocket;
  if ((iterMapS = this->serverMap.find(sockKey1)) == this->serverMap.end()) {
    iterMapC = this->clientMap.find(sockfd);
    clientSocket = iterMapC->second;
    isServer = false;
  }
  else {
    serverSocket = iterMapS->second;
    isServer = true;
  }

  /***** FINITE STATE MACHINE *****/
  switch (isServer? (serverSocket->sState) : (clientSocket->cState) ) {
    case SOC_LISTEN: // when server socket gets SYN
    { 
      // If the pending queue is full, just return
      if (serverSocket->pendingCount >= serverSocket->Backlog)
        break;
      else {
        newFlags = SYNACK;
        int pid = serverSocket->pid;
        this->receivedSeq = receivedSeq+1;

        // create new fd for accept socket and insert it into fdToAddr&serverMap
        int newfd = this->createFileDescriptor(pid);
        uint64_t sockKey = getPidSocketKey(pid, newfd);
        this->fdToAddr.insert(std::pair<uint64_t, Namespace>(sockKey, Namespace(AF_INET, dst_port, dst_ip, src_port, src_ip, pid, receivedSeq+1)));
        std::vector <struct sockaddr *> pendingQueue;
        serverSocketEntry * newServerSocket;
        newServerSocket = (serverSocketEntry *)malloc(sizeof(serverSocketEntry));
          newServerSocket -> Pendings = pendingQueue;
          newServerSocket -> Backlog = 0;
          newServerSocket -> sState = SYN_RCVD;
          newServerSocket -> syscallUUID = serverSocket -> syscallUUID;
          newServerSocket -> pid = pid;
          newServerSocket -> parentFd = sockfd;
          newServerSocket -> acceptAddr = NULL;
          newServerSocket -> pendingCount = 0;
          newServerSocket -> seqNum = (serverSocket -> seqNum) +1;
          newServerSocket -> closeCalled = false;
        this->serverMap.insert(std::pair<uint64_t, serverSocketEntry *>(sockKey, newServerSocket));

        serverSocket -> pendingCount = (serverSocket -> pendingCount) +1;

        // Send SYNACK to client
        sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(serverSocket->seqNum), receivedSeq, 0, 0, 1, true, sockfd);
      }
      break;
    }
    case SYN_SENT:  // when client socket gets SYNACK
    { 
      // if received flag is RST, return -1
      if (flags == RST) {
        this->returnSystemCall(clientSocket->syscallUUID, -1);
        break;
      }
      if (flags == ACK)
        break;

      // Remove timer of SYN packet
      UUID timerUUID;
      auto iterTimer = timerMap.begin();
      for (; iterTimer != timerMap.end(); iterTimer++) {
        if (iterTimer->first == receivedAck-1) {
          timerUUID = std::get<0>(iterTimer->second);
          this->cancelTimer(timerUUID);
          timerMap.erase(receivedAck-1);
          break;
        }
      }
      sndIntBuf.erase(receivedAck-1);

      this->receivedSeq = receivedSeq+1;

      if (flags != SYN)
        clientSocket->cState = ESTAB;
      else
        this->clientSeq = this->clientSeq -1;
      
      newFlags = (flags!=SYN) ? ACK : SYNACK;
      // send ACK to server
      sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 0, 1, true, sockfd);
      std::get<6>(iterAddr->second) = receivedSeq+1;

      if (flags == SYN)
        this->clientSeq = this->clientSeq+1;
      else {
        clientSocket->handshaking = true;
        this->returnSystemCall(clientSocket->syscallUUID, 0);
      }
      break;
    }
    case SYN_RCVD:  // when server socket gets ACK
    {
      // Remove timer of SYNACK packet
      UUID timerUUID;
      auto iterTimer = timerMap.begin();
      for (; iterTimer != timerMap.end(); iterTimer++) {
        if (iterTimer->first == receivedAck-1) {
          timerUUID = std::get<0>(iterTimer->second);
          this->cancelTimer(timerUUID);
          timerMap.erase(receivedAck-1);
          break;
        }
      }
      sndIntBuf.erase(receivedAck-1);

      // change state to ESTAB
      serverSocket->sState = ESTAB;
      // find the information about parent
      int parentFd = serverSocket->parentFd;
      int parentPid = serverSocket->pid;
      uint64_t parentKey = getPidSocketKey(parentPid, parentFd);
      auto iterParent = this->serverMap.begin();
      iterParent = this->serverMap.find(parentKey);
      serverSocketEntry * parentSocket;
      parentSocket = iterParent->second;

      // if accept() is not called yet, push address to pending queue
      if (parentSocket->acceptAddr == NULL) {  
        struct sockaddr_in* pendingAddr;
        pendingAddr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
        pendingAddr->sin_family = AF_INET;
        pendingAddr->sin_port = src_port;
        pendingAddr->sin_addr.s_addr = src_ip;
        memset(pendingAddr->sin_zero, 0, 8);
        (parentSocket->Pendings).push_back((struct sockaddr *)pendingAddr);
        parentSocket->pendingCount = (parentSocket->pendingCount)-1;
      }
      else {  // if accept() is already called, finish what should be done at accept() function
        ((struct sockaddr_in*)parentSocket->acceptAddr)->sin_family = AF_INET;
        ((struct sockaddr_in*)parentSocket->acceptAddr)->sin_port = src_port;
        ((struct sockaddr_in*)parentSocket->acceptAddr)->sin_addr.s_addr = src_ip;
        
        parentSocket->acceptAddr = NULL;
        parentSocket->pendingCount = (parentSocket->pendingCount)-1;
        this->returnSystemCall(parentSocket->syscallUUID, sockfd); // wake blocking system call(accept)
      }
      break;
    }
    case ESTAB: 
    {
      if (flags == FIN  && rcvIntBuf.size() == 0) {  // Start of teardown
        // To deal with EOF cases
        while (pendingReads.size() > 0)  {
            pendingRead pend = pendingReads.front();
            this->returnSystemCall(std::get<0>(pend), -1);
            pendingReads.pop();
        }
  
        newFlags = ACK; 
        if (isServer) {  // if server, change state to CLOSE_WAIT
          serverSocket->sState = CLOSE_WAIT;
          sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(serverSocket->seqNum), receivedSeq, 0, 0, 1, false, sockfd);
        }
        else { // if client, change state to TIMED_WAIT and then start a new timer
          clientSocket->cState = TIMED_WAIT;
          fdSeq * fdSeqPtr;
          fdSeqPtr = (fdSeq *)malloc(sizeof(fdSeq));
          fdSeqPtr->seqNum = this->clientSeq;
          fdSeqPtr->sockfd = sockfd;
          UUID timerID = addTimer(fdSeqPtr, 500);
          Time sentTime = this->getHost()->getSystem()->getCurrentTime();
          timerMap[this->clientSeq] = timerNamespace(timerID, sockfd, sentTime);
          clientSocket->TimerID = timerID;

          sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 0, 1, false, sockfd);
        }
      }
      else if (flags == ACK) { // Data transfer
        newFlags = ACK;
        size_t payloadLen = (packet->getSize()) - 54;

        if (!payloadLen) // Data sender
        {
          auto iterSndBuf = sndIntBuf.begin();

          if ((iterSndBuf = sndIntBuf.find(receivedAck-512)) != sndIntBuf.end())
          {
            isDup = 0;

            /** CONGESTION CONTROL : when getting new ACK **/
            if (congState == SS)
				      cwnd = cwnd+MSS > 51200 ? 51200 : cwnd+MSS;
            else if (congState == CA)
              cwnd += round(MSS * ((double)MSS/cwnd));
            else {
              cwnd = ssthresh;
              congState = CA;
            }
            dupACKcount = 0;
            /***********************************************/

            if (congState == SS && cwnd >= ssthresh)
              congState = CA;

            // When TCP Window Update packet is arrived
            if (rwnd < 51200 || rwnd < sndIntBuf.size()*512)
              cwnd = MSS;

            while(sndIntBuf.begin()->first != iterSndBuf->first) {
              auto iterTimer = timerMap.begin();
              iterTimer = timerMap.find(sndIntBuf.begin()->first);
              cancelTimer(std::get<0>(iterTimer->second));
              timerMap.erase(sndIntBuf.begin()->first);
              sndIntBuf.erase(sndIntBuf.begin()->first);
              unACKedbytes -= 512;
            }
            
            auto iterTimer = timerMap.begin();
            iterTimer = timerMap.find(sndIntBuf.begin()->first);

            Time sentTime = std::get<2>(iterTimer->second);
            Time rcvTime = this->getHost()->getSystem()->getCurrentTime();
            this->RTT = rcvTime - sentTime;
            calcRTO(this->RTT, this->SRTT, this->RTTVAR);

            cancelTimer(std::get<0>(iterTimer->second));
            timerMap.erase(sndIntBuf.begin()->first);
            sndIntBuf.erase(sndIntBuf.begin()->first);
            unACKedbytes -= 512;

            if (pendingWrites.size() > 0) {
              pendingWrite pend = pendingWrites.front();
              UUID syscallUUID = std::get<0>(pend);
              int pid = (int)((sockKey1 >> 32) & 0xFFFFFFFF);
              void * buf = std::get<1>(pend);
              size_t count = std::get<2>(pend);

              this->syscall_write(syscallUUID, pid, sockfd, buf, count);
              free(std::get<1>(pend));
              pendingWrites.pop();
            }
          }
          else
          {
            /** CONGESTION CONTROL : when getting duplicate ACK **/
            if (congState == FR)
              cwnd = cwnd+MSS > 51200 ? 51200 : cwnd+MSS;
            else
              dupACKcount += 1;
            /** CONGESTION CONTROL : when duplicate ACK == 3 **/
            if (dupACKcount == 3 && congState != FR) {
              ssthresh = cwnd/2;
              if (ssthresh < MSS)
                ssthresh = MSS;
              cwnd = ssthresh + (3*MSS);
              congState = FR;
            }
            /******************************************************/

            if (congState == SS && cwnd >= ssthresh)
              congState = CA;

            // When TCP Window Update packet is arrived
            if (rwnd < 51200 || rwnd < sndIntBuf.size()*512)
            {
              cwnd = MSS;
              break;
            }

            if (isDup == 0)  // 2 dup ACK
              isDup = receivedAck - 512;
            else {
              if (isDup == receivedAck - 512){ // 3 dup ACK
                cwnd /= 2;
                if (cwnd < MSS)
                  cwnd = MSS;
                
                /**** FAST RETRANSMIT: SEND ONLY THAT *******/
                auto iterSndBuf2 = sndIntBuf.begin();
                iterSndBuf2 = sndIntBuf.find(receivedAck);
                Packet * clonedPkt = this->clonePacket(iterSndBuf2->second);
                this->sendPacket("IPv4", clonedPkt);

                auto iterTimer = timerMap.begin();
                iterTimer = timerMap.find(receivedAck);
                cancelTimer(std::get<0>(iterTimer->second));
                fdSeq * fdSeqPtr = (fdSeq *)malloc(sizeof(fdSeq));
                fdSeqPtr->seqNum = iterTimer->first;
                fdSeqPtr->sockfd = sockfd;
                UUID timerID = addTimer(fdSeqPtr, 100000000);
                Time sentTime = this->getHost()->getSystem()->getCurrentTime();
                timerMap[iterTimer->first] = timerNamespace(timerID, sockfd, sentTime);
                /**********************************************/
              }
              else
                isDup = receivedAck - 512;
            }
          }

          // if close() is called and sndIntBuf is empty -> call syscall_close
          if (sndIntBuf.size() == 0) {
            if (isServer) {
              if (serverSocket->closeCalled == true)
                this->syscall_close(serverSocket->syscallUUID, serverSocket->pid, sockfd);
            }
            else {
              if (clientSocket->closeCalled == true)
                this->syscall_close(clientSocket->syscallUUID, clientSocket->pid, sockfd);
            }
          }
        }
        else { // Data receiver
          if (std::get<6>(iterAddr->second) == receivedSeq) /* Packet with expected sequence number */
          {           
            uint32_t consecMax = receivedSeq; // variable to get maximum consecutive sequence number
            uint32_t prevPayloadLen = payloadLen;
            if (rcvIntBuf.size() > 0) // reorder happens before -> send ACK with max consecutive seq
            {
              auto iterRcvBuf = rcvIntBuf.begin();
              while (consecMax+prevPayloadLen == iterRcvBuf->first) {
                consecMax = iterRcvBuf->first;
                prevPayloadLen = iterRcvBuf->second->getSize() - 54;
                iterRcvBuf++;
              }

              if (!isServer)
                sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), consecMax, 0, 0, prevPayloadLen, false, sockfd);
              else
                sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(serverSocket->seqNum), consecMax, 0, 0, prevPayloadLen, false, sockfd);

              std::get<6>(iterAddr->second) = consecMax+prevPayloadLen;
            }
            else // No reorder before -> just send ACK corresponding to current data packet
            {
              if (!isServer)
                sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 0, payloadLen, false, sockfd);
              else
                sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(serverSocket->seqNum), receivedSeq, 0, 0, payloadLen, false, sockfd);
              
              std::get<6>(iterAddr->second) = receivedSeq + payloadLen;
            }
            
            Packet * clonedPacket = this->clonePacket(packet);
            rcvIntBuf[receivedSeq] = clonedPacket;

            uint8_t tempBuf1[512];
            auto iterRcvBuf = rcvIntBuf.begin();
            auto iterRcvBufPrev = rcvIntBuf.begin();
            /* move rcvIntBuf data to TCPreadBuffer
             * until max consecutive sequence number packet */
            while (iterRcvBuf->first <= consecMax && iterRcvBuf != rcvIntBuf.end()) 
            {
              memset(tempBuf1, 0, 512);
              payloadLen = iterRcvBuf->second->getSize() - 54;
              (iterRcvBuf->second)->readData(54, tempBuf1, payloadLen);
              if (51200 - (readBufferReceiveStart%51200) < payloadLen) {
                // Fragmentation at end of TCPreadBuffer
                memcpy(TCPreadBuffer+(readBufferReceiveStart%51200), tempBuf1, 51200-(readBufferReceiveStart%51200));
                memcpy(TCPreadBuffer, tempBuf1+51200-(readBufferReceiveStart%51200), payloadLen+(readBufferReceiveStart%51200)-51200);
              }
              else {
                memcpy(TCPreadBuffer+(readBufferReceiveStart%51200), tempBuf1, payloadLen);
              } 
              readBufferReceiveStart += payloadLen;
              iterRcvBufPrev = iterRcvBuf;
              iterRcvBuf++;
              rcvIntBuf.erase(iterRcvBufPrev->first);
            }

            /*** If there is read() pending, deal one ***/
            if (pendingReads.size() > 0)
            {
              pendingRead *pend = &(pendingReads.front());
              size_t count, readBytes, minRead;
              UUID syscallUUID = std::get<0>(*pend);
              count = std::get<2>(*pend);
              readBytes = std::get<3>(*pend);

              minRead = count > 512 ? 512 : count;
              if (readBufferReceiveStart - readBufferSentLast < minRead)
                minRead = readBufferReceiveStart - readBufferSentLast;

              if (51200 - (readBufferSentLast%51200) < minRead){
                // Fragmentation at end of TCPreadBuffer
                memcpy(((uint8_t*)std::get<1>(*pend))+readBytes, TCPreadBuffer+(readBufferSentLast%51200) , 51200-(readBufferSentLast%51200));
                memcpy(((uint8_t*)std::get<1>(*pend))+readBytes+51200-(readBufferSentLast%51200), TCPreadBuffer, minRead+(readBufferSentLast%51200)-51200);
              }
              else {
                memcpy(((uint8_t*)std::get<1>(*pend))+readBytes, TCPreadBuffer+(readBufferSentLast%51200) , minRead);
              }

              readBufferSentLast += minRead;

              pendingReads.pop();
              this->returnSystemCall(syscallUUID, minRead);
            }
          }
          else if (std::get<6>(iterAddr->second) < receivedSeq) /* Packet with larger sequence number => send ACK and save the packet rcvIntBuf */
          {
            if (!isServer)
              sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), std::get<6>(iterAddr->second), 0, 0, 0, false, sockfd);
            else
              sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(serverSocket->seqNum), std::get<6>(iterAddr->second), 0, 0, 0, false, sockfd);

            Packet * clonedPacket = this->clonePacket(packet);
            rcvIntBuf[receivedSeq] = clonedPacket;
          }
          else {  /* Packet with smaller sequence number => just send recent ACK */
            if (!isServer)
              sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 0, payloadLen, false, sockfd);
            else
              sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(serverSocket->seqNum), receivedSeq, 0, 0, payloadLen, false, sockfd);
          }
        } // End of receiver      
      }
      else if (flags == SYNACK) { // If SYNACK is arrived again -> send ACK like SYN_SENT state
        newFlags = ACK;
        
        UUID timerUUID;
        auto iterTimer = timerMap.begin();
        for (; iterTimer != timerMap.end(); iterTimer++) {
          if (iterTimer->first == receivedAck) {
            timerUUID = std::get<0>(iterTimer->second);
            this->cancelTimer(timerUUID);
            timerMap.erase(receivedAck);
            sndIntBuf.erase(receivedAck);
            break;
          }
        }
        clientSocket->handshaking = true;
        sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 0, 1, true, sockfd);
      }
      break;
    }
    case CLOSE_WAIT:
    {
      if (flags == ACK) {
        // remove timer of my FIN
        UUID timerUUID;
        auto iterTimer = timerMap.begin();
        for (; iterTimer != timerMap.end(); iterTimer++) {
          if (iterTimer->first == receivedAck-1) {
            timerUUID = std::get<0>(iterTimer->second);
            this->cancelTimer(timerUUID);
            timerMap.erase(receivedAck-1);
            break;
          }
        }
        sndIntBuf.erase(receivedAck-1);
      }
      break;
    }
    case LAST_ACK:
    {
      // change state to CLOSED
      serverSocket->sState = CLOSED;
      newFlags = ACK;
      if (flags == FIN) {
        sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(serverSocket->seqNum), receivedSeq, 1, 0, 1, false, sockfd);
      }
      else if (flags == ACK) {
        // remove timer of my FIN
        UUID timerUUID;
        auto iterTimer = timerMap.begin();
        for (; iterTimer != timerMap.end(); iterTimer++) {
          if (iterTimer->first == receivedAck-1) {
            timerUUID = std::get<0>(iterTimer->second);
            this->cancelTimer(timerUUID);
            timerMap.erase(receivedAck-1);
            break;
          }
        }
        sndIntBuf.erase(receivedAck-1);
      }
      break;
    }
    case FIN_WAIT_1:
    {
      if (flags == ACK) {
        // remove timer of my FIN
        UUID timerUUID;
        auto iterTimer = timerMap.begin();
        for (; iterTimer != timerMap.end(); iterTimer++) {
          if (iterTimer->first == receivedAck-1) {
            timerUUID = std::get<0>(iterTimer->second);
            this->cancelTimer(timerUUID);
            timerMap.erase(receivedAck-1);
            break;
          }
        }
        sndIntBuf.erase(receivedAck-1);

        clientSocket->cState = FIN_WAIT_2; /// change state to FIN_WAIT_2
        break;
      }

      /****** Fall through!!!! *******/
      /****** Don't write anything *****/
    }
    case FIN_WAIT_2:
    {
      if (flags == ACK) {
        // remove timer of my FIN
        UUID timerUUID;
        auto iterTimer = timerMap.begin();
        for (; iterTimer != timerMap.end(); iterTimer++) {
          if (iterTimer->first == receivedAck-1) {
            timerUUID = std::get<0>(iterTimer->second);
            this->cancelTimer(timerUUID);
            timerMap.erase(receivedAck-1);
            break;
          }
        }
        sndIntBuf.erase(receivedAck-1);
        break;
      }
      if (flags == SYNACK) { // If SYNACK is arrived, send ACK like SYN_SENT state
        newFlags = ACK;
        this->clientSeq -= 1;
        sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 1, 1, false, sockfd);
        break;
      }

      // change state to TIMED_WAIT
      clientSocket->cState = TIMED_WAIT;
      newFlags = ACK;
      // set Timer for ACK packet to wait for FIN to be retransmitted
      fdSeq * fdSeqPtr;
      fdSeqPtr = (fdSeq *)malloc(sizeof(fdSeq));
      fdSeqPtr->seqNum = this->clientSeq;
      fdSeqPtr->sockfd = sockfd;
      UUID timerID = addTimer(fdSeqPtr, 500);
      Time sentTime = this->getHost()->getSystem()->getCurrentTime();
      timerMap[this->clientSeq] = timerNamespace(timerID, sockfd, sentTime);
      clientSocket->TimerID = timerID;
      sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 1, 1, false, sockfd);
      break; 
    }
    case TIMED_WAIT:
    {
      // If FIN packet is arrived, retransmit the ACK packet
      if (flags == FIN) {
        newFlags = ACK;
        sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 1, 1, false, sockfd);
      }
      else if (flags == ACK){
        // remove timer for FIN
        UUID timerUUID;
        auto iterTimer = timerMap.begin();
        for (; iterTimer != timerMap.end(); iterTimer++) {
          if (iterTimer->first == receivedAck-1) {
            timerUUID = std::get<0>(iterTimer->second);
            this->cancelTimer(timerUUID);
            sndIntBuf.erase(receivedAck-1);
            timerMap.erase(receivedAck-1);
            break;
          }
        }
      }
      break;
    }
    case CLOSED:
    {
      if (flags == FIN) {
        newFlags = ACK;
        if (isServer)
          sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(serverSocket->seqNum), receivedSeq, 1, 0, 1, false, sockfd);
        else
          sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 1, 0, 1, false, sockfd);
      }
      else if (flags == ACK) {
        // remove timer for FIN
        UUID timerUUID;
        auto iterTimer = timerMap.begin();
        for (; iterTimer != timerMap.end(); iterTimer++) {
          if (iterTimer->first == receivedAck-1) {
            timerUUID = std::get<0>(iterTimer->second);
            this->cancelTimer(timerUUID);
            sndIntBuf.erase(receivedAck-1);
            timerMap.erase(receivedAck-1);
            break;
          }
        }
      }
      break;
    }
  }

  // given packet is my responsibility
  this->freePacket(packet);
}

void TCPAssignment::timerCallback(void* payload)
{
  fdSeq * fdSeqPtr = (fdSeq *)payload;

  auto iterMapC = this->clientMap.begin();
  clientSocketEntry * clientSocket;
  if ((iterMapC = this->clientMap.find(fdSeqPtr->sockfd)) != this->clientMap.end()) {
    clientSocket = iterMapC->second;
    // If timeouted timer is timer for ACK to wait for FIN to be retransmitted
    if (clientSocket->cState == FIN_WAIT_2 || clientSocket->cState == TIMED_WAIT) {
      auto iterTimer = timerMap.begin();
      iterTimer = timerMap.find(fdSeqPtr->seqNum);
      UUID timerID = std::get<0>(iterTimer->second);
      cancelTimer(timerID);
      timerMap.erase(fdSeqPtr->seqNum);
      clientSocket->cState = CLOSED;
      free(payload);
      return;
    }
    // If timeouted timer is timer for ACK which is last state of handshake
    else if (clientSocket->handshaking) {
      auto iterTimer = timerMap.begin();
      iterTimer = timerMap.find(fdSeqPtr->seqNum);
      UUID timerID = std::get<0>(iterTimer->second);
      cancelTimer(timerID);
      timerMap.erase(fdSeqPtr->seqNum);
      sndIntBuf.erase(fdSeqPtr->seqNum);
      clientSocket->handshaking = false;

      if (clientSocket->closeCalled) {
        this->syscall_close(clientSocket->syscallUUID, clientSocket->pid, fdSeqPtr->sockfd);
      }
      free(payload);
      return;
    }
  }

  /** CONGESTION CONTROL : when timeout **/
  ssthresh = cwnd/2;
  if (ssthresh < MSS)
    ssthresh = MSS;
  cwnd = MSS;
  dupACKcount = 0;
  congState = SS;
  /**************************************/

  /* Double RTO when there's timeout */
  this->RTO = this->RTO * 2;

  /** Retransmit all unACKed packets and reset all timers */
  auto iterSndBuf = sndIntBuf.begin();
  for (; iterSndBuf != sndIntBuf.end(); iterSndBuf++) {
    this->sendPacket("IPv4", iterSndBuf->second);
    Packet * newClone = this->clonePacket(iterSndBuf->second);
    sndIntBuf[iterSndBuf->first] = newClone;
  }
  
  auto iterTimer = timerMap.begin();
  auto iterTimerNext = timerMap.begin();
  while (iterTimer != timerMap.end()) {
    iterTimerNext = std::next(iterTimer, 1);
    fdSeq * fdSeqPtr2 = (fdSeq *)malloc(sizeof(fdSeq));
    fdSeqPtr2->seqNum = iterTimer->first;
    fdSeqPtr2->sockfd = std::get<1>(iterTimer->second);
    cancelTimer(std::get<0>(iterTimer->second));
    timerMap.erase(iterTimer->first);
    UUID timerID = addTimer(fdSeqPtr2, 100000000);
    Time sentTime = this->getHost()->getSystem()->getCurrentTime();
    timerMap[fdSeqPtr2->seqNum] = timerNamespace(timerID, std::get<1>(iterTimer->second), sentTime);
    iterTimer = iterTimerNext;
  }
  /*******************************************************/

  free(payload);
  return;
}

/* socket() system call */
void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
  // create file descriptor and return the result
  int sockfd = this->createFileDescriptor(pid);
  this->returnSystemCall(syscallUUID, sockfd);
}

/* close() system call */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{ 
  bool isServer;
  uint64_t sockKey = getPidSocketKey(pid, sockfd);
  auto iter = this->fdToAddr.begin();
  iter = this->fdToAddr.find(sockKey);
  auto iterMapS = this->serverMap.begin();
  auto iterMapC = this->clientMap.begin();
  serverSocketEntry * serverSocket;
  clientSocketEntry * clientSocket;
  if ((iterMapS = this->serverMap.find(sockKey)) == this->serverMap.end()) {
    iterMapC = this->clientMap.find(sockfd);
    isServer = false;
    // If neither server nor client
    if (iterMapC == this->clientMap.end()) {  
      // if the sockfd is bound, remove it from fdToAddr
      if (iter != this->fdToAddr.end()) {
        this->fdToAddr.erase(sockKey);
      }
      this->removeFileDescriptor(pid, sockfd);
      this->returnSystemCall(syscallUUID, 0); 
      return;
    }
		else {
			clientSocket = iterMapC->second;
		}
  }
  else {
    serverSocket = iterMapS->second;
    isServer = true;
  }

  // If there are unACKed packets, pending read(), or pending write()
  // -> blocking close() system call
  if (sndIntBuf.size() > 0 || pendingReads.size() > 0 || pendingWrites.size() > 0) {
    if (isServer) {
      serverSocket->syscallUUID = syscallUUID;
      serverSocket->pid = pid;
      serverSocket->closeCalled = true;
    }
    else {
      clientSocket->syscallUUID = syscallUUID;
      clientSocket->pid = pid;
      clientSocket->closeCalled = true;
    }
    return;
  }
  // If the socket is in the middle of handshaking -> block close() system call
  if (!isServer && clientSocket->handshaking) {
    clientSocket->syscallUUID = syscallUUID;
    clientSocket->pid = pid;
    clientSocket->closeCalled = true;
    return;
  }
  // If some packets are left in rcvIntBuf, move all to TCPreadBuffer
  if (rcvIntBuf.size() > 0) {
    uint8_t tempBuf1[512];
    auto iterRcvBuf = rcvIntBuf.begin();
    auto iterRcvBufPrev = rcvIntBuf.begin();
    while (iterRcvBuf != rcvIntBuf.end()) 
    {
      memset(tempBuf1, 0, 512);
      size_t payloadLen = iterRcvBuf->second->getSize() - 54;
      (iterRcvBuf->second)->readData(54, tempBuf1, payloadLen);
      if (51200 - (readBufferReceiveStart%51200) < payloadLen) {
        // Fragmentation at end of TCPreadBuffer
        memcpy(TCPreadBuffer+(readBufferReceiveStart%51200), tempBuf1, 51200-(readBufferReceiveStart%51200));
        memcpy(TCPreadBuffer, tempBuf1+51200-(readBufferReceiveStart%51200), payloadLen+(readBufferReceiveStart%51200)-51200);
      }
      else {
        memcpy(TCPreadBuffer+(readBufferReceiveStart%51200), tempBuf1, payloadLen);
      } 
      readBufferReceiveStart += payloadLen;
      iterRcvBufPrev = iterRcvBuf;
      iterRcvBuf++;
      rcvIntBuf.erase(iterRcvBufPrev->first);
    }
  }

  // If the socket is listening socket, just remove the socket
  if (isServer && std::get<3>(iter->second) == 0) {
    this->removeFileDescriptor(pid, sockfd);
    this->returnSystemCall(syscallUUID, 0);
    return;
  }

  uint32_t src_ip = htonl(std::get<2>(iter->second));
  uint32_t dst_ip = htonl(std::get<4>(iter->second));
  uint16_t src_port = htons(std::get<1>(iter->second));
  uint16_t dst_port = htons(std::get<3>(iter->second));
  uint8_t newFlags = FIN;

  if (!isServer) {
    /**** syscall_close for client socket : Change state to FIN_WAIT_1 ****/
    clientSocket->cState = FIN_WAIT_1;

    sendPacketHeader(src_ip, dst_ip, src_port, dst_port, newFlags, &(this->clientSeq), -1, 0, 1, 1, true, sockfd);
  }
  else {
    /**** syscall_close for server socket : Change state to LAST_ACK ****/
    serverSocket->sState = LAST_ACK;

    sendPacketHeader(src_ip, dst_ip, src_port, dst_port, newFlags, &(serverSocket->seqNum), -1, 0, 0, 1, true, sockfd);
  }
 
  // remove file descriptor
  this->removeFileDescriptor(pid, sockfd);
  this->returnSystemCall(syscallUUID, 0);
}

/* bind() system call */
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd,
        struct sockaddr *my_addr, socklen_t addrlen)
{
  uint8_t family;
  uint16_t port;
  uint32_t ipAddr;
  uint16_t portBigEndian;
  uint32_t ipBigEndian;

  uint64_t sockKey = getPidSocketKey(pid, sockfd);
  // if the socket is already bound, return -1
  if (this->fdToAddr.find(sockKey) != this->fdToAddr.end())
    this->returnSystemCall(syscallUUID, -1);

  // copy and change the endian of address
  memcpy(&portBigEndian, my_addr->sa_data, 2);
  port = ntohs(portBigEndian);
  memcpy(&ipBigEndian, my_addr->sa_data+2, 4);
  ipAddr = ntohl(ipBigEndian);
  family = my_addr->sa_family;

  // check whether the overlapped address is already bound or not
  for (auto iter = this->fdToAddr.begin(); iter != this->fdToAddr.end(); iter++) {
    if (std::get<1>(iter->second) == port) {
      if ((std::get<2>(iter->second) == ipAddr) || (std::get<2>(iter->second) == INADDR_ANY) || (ipAddr == INADDR_ANY))
        this->returnSystemCall(syscallUUID, -1);
    }
  }

  // insert the address into fdToAddr and return 0
  this->fdToAddr.insert(std::pair<uint64_t, Namespace>(sockKey, Namespace(family, port, ipAddr, NULL, NULL, pid, 0)));
  this->returnSystemCall(syscallUUID, 0);
}

/* getsockname() system call */
void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
        struct sockaddr *addr, socklen_t *addrlen)
{
  struct sockaddr_in * addr2 = (struct sockaddr_in*)malloc(*addrlen);
  uint64_t sockKey = getPidSocketKey(pid, sockfd);
  // Find the address matched to sockfd in the fdToAddr
  // If the socket is not bound, just return 0
  auto iter = this->fdToAddr.begin();
  if ((iter = this->fdToAddr.find(sockKey)) == this->fdToAddr.end()) {
    this->returnSystemCall(syscallUUID, 0);
    return;
  }

  // Copy the address to * addr
  memset(addr2, 0, *addrlen);
  addr2->sin_family = std::get<0>(iter->second);
  addr2->sin_port = htons(std::get<1>(iter->second));
  addr2->sin_addr.s_addr = htonl(std::get<2>(iter->second));
  memcpy(addr, addr2, *addrlen);

  free(addr2);
  this->returnSystemCall(syscallUUID, 0);
}

/* connect() system call */
void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, 
        struct sockaddr* serv_addr, socklen_t addrlen) 
{
  uint32_t big_src_ip, big_dst_ip;
  uint16_t big_src_port, big_dst_port;
  uint64_t sockKey = getPidSocketKey(pid, sockfd);

  // Find the address matched to sockfd in the fdToAddr
  auto iter = this->fdToAddr.begin();
  if ((iter = this->fdToAddr.find(sockKey)) == this->fdToAddr.end()) {
    // bind implicitly
    uint16_t port = (uint16_t)rand();
    uint8_t ip_addr[4];
    memset(ip_addr, 0, 4);
    uint32_t ipAddr;
    this->getHost()->getIPAddr(ip_addr,
        this->getHost()->getRoutingTable(ip_addr));
    memcpy(&ipAddr, ip_addr, 4);
    ipAddr = ntohl(ipAddr);
    this->fdToAddr.insert(std::pair<uint64_t, Namespace>(sockKey, Namespace(AF_INET, port, ipAddr, NULL, NULL, pid, 0)));
    iter = this->fdToAddr.find(sockKey);
  }
    
  big_src_port = htons(std::get<1>(iter->second));
  big_src_ip = htonl(std::get<2>(iter->second));
  struct sockaddr_in* serv_addr_in = (struct sockaddr_in*)(serv_addr);
  big_dst_port = serv_addr_in->sin_port;
  big_dst_ip = serv_addr_in->sin_addr.s_addr;

  std::get<3>(iter->second) = ntohs(big_dst_port);
  std::get<4>(iter->second) = ntohl(big_dst_ip);

  // Make new client socket
  clientSocketEntry * newClientSocket;
  newClientSocket = (clientSocketEntry *)malloc(sizeof(clientSocketEntry));
    newClientSocket->cState = SOC_LISTEN;
    newClientSocket->cSeq = this->clientSeq;
    newClientSocket->syscallUUID = syscallUUID;
    newClientSocket->TimerID = -1;
    newClientSocket->closeCalled = false;
    newClientSocket->pid = pid;
    newClientSocket->handshaking = false;
  this->clientMap.insert(std::pair<int, clientSocketEntry *>(sockfd, newClientSocket));
  uint8_t newFlags = SYN;
  sendPacketHeader(big_src_ip, big_dst_ip, big_src_port, big_dst_port, newFlags, &(this->clientSeq), -1, 0, 1, 1, true, sockfd);
  
  /*** Change State ***/
  newClientSocket -> cState = SYN_SENT;
}

/* listen() system call */
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
  // Insert the information to serverMap
  std::vector <struct sockaddr *> pendingQueue;
  uint64_t sockKey = getPidSocketKey(pid, sockfd);
  
  // Make new listening socket
  serverSocketEntry * newServerSocket;
  newServerSocket = (serverSocketEntry *)malloc(sizeof(serverSocketEntry));
    newServerSocket -> Pendings = pendingQueue;
    newServerSocket -> Backlog = backlog;
    newServerSocket -> sState = SOC_LISTEN;
    newServerSocket -> syscallUUID = syscallUUID;
    newServerSocket -> pid = pid;
    newServerSocket -> parentFd = 0;
    newServerSocket -> acceptAddr = NULL;
    newServerSocket -> pendingCount = 0;
    newServerSocket -> seqNum = (uint32_t)rand();
    newServerSocket -> closeCalled = false;
  this->serverMap.insert(std::pair<uint64_t, serverSocketEntry *>(sockKey, newServerSocket));
  this->returnSystemCall(syscallUUID, 0);
}

/* accept() system call */
void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, 
        struct sockaddr* addr, socklen_t* addrlen)
{
  socklen_t clientLen;
  memcpy(&clientLen, addrlen, sizeof(socklen_t));
  uint64_t sockKey = getPidSocketKey(pid, sockfd);

  auto iter = this->serverMap.begin();
  serverSocketEntry * serverSocket;
  if ((iter = this->serverMap.find(sockKey)) == this->serverMap.end()) {
    this->returnSystemCall(syscallUUID, -1);
    return;
  }
  serverSocket = iter->second;

  auto iterAddr = this->fdToAddr.begin();
  if ((iterAddr = this->fdToAddr.find(sockKey)) == this->fdToAddr.end())
    this->returnSystemCall(syscallUUID, -1);

  // If queue is not empty, pop one element in the queue
  if ((serverSocket->Pendings).size() > 0) {
    struct sockaddr* clientAddr = serverSocket->Pendings[0];
    memcpy(addr, clientAddr, 16);
    serverSocket->Pendings.erase(serverSocket->Pendings.begin());

    int newfd;
    auto iterSock = this->fdToAddr.begin();
    while (iterSock != this->fdToAddr.end()) {
      if ((std::get<1>(iterSock->second) == std::get<1>(iterAddr->second)) 
          && (std::get<2>(iterSock->second) == std::get<2>(iterAddr->second) || std::get<2>(iterSock->second) == 0 || std::get<2>(iterAddr->second) == 0)
          && (std::get<3>(iterSock->second) == ((sockaddr_in*)clientAddr)->sin_port)
          && (std::get<4>(iterSock->second) == ((sockaddr_in*)clientAddr)->sin_addr.s_addr)) {
        newfd = (int)((iterSock->first)&0xFFFFFFFF);

        break;
      }
      iterSock++;
    }

    free(clientAddr);
    this->returnSystemCall(syscallUUID, newfd);
  }
  else {  // if queue is empty, store UUID and addr to copy
    serverSocket->syscallUUID = syscallUUID;
    serverSocket->acceptAddr = addr;
  }

  return;
}

/* getpeername() system call */
void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
        struct sockaddr *addr, socklen_t *addrlen)
{
  struct sockaddr_in * addr2 = (struct sockaddr_in*)malloc(*addrlen);
  uint64_t sockKey = getPidSocketKey(pid, sockfd);

  // Find the address matched to sockfd in the fdToAddr
  // If the socket is not bound, just return 0
  auto iter = this->fdToAddr.begin();
  if ((iter = this->fdToAddr.find(sockKey)) == this->fdToAddr.end())
    this->returnSystemCall(syscallUUID, 0);

  // Copy the address to * addr
  memset(addr2, 0, *addrlen);
  addr2->sin_family = std::get<0>(iter->second);
  addr2->sin_port = htons(std::get<3>(iter->second));
  addr2->sin_addr.s_addr = htonl(std::get<4>(iter->second));
  memcpy(addr, addr2, *addrlen);

  free(addr2);
  this->returnSystemCall(syscallUUID, 0);
}

/* read() system call */
void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd,
        void *buf, size_t count)
{
  // If there is no data to read -> pend read()
  if (readBufferReceiveStart == readBufferSentLast)
  {
    pendingRead pend = pendingRead(syscallUUID, buf, count, 0);
    pendingReads.push(pend);
  }
  // If there is data to read in TCPreadBuffer -> read the data(amount: minRead)
  else
  {
    size_t readBytes = 0;
    while (count > 0) {

      /** minRead = min(512, count, 51200 - (readBufferSentLast%51200), (readBufferReceiveStart-readBufferSentLast)) **/
      size_t minRead = count > 512 ? 512 : count;

      if (51200 - (readBufferSentLast%51200) < minRead)
        minRead = 51200 - (readBufferSentLast%51200);
      if ((readBufferReceiveStart-readBufferSentLast) <  minRead)
        minRead = readBufferReceiveStart-readBufferSentLast;
      if (minRead == 0)
        break;
      /*************************************************************/

      memcpy(((uint8_t*)buf)+readBytes, TCPreadBuffer+(readBufferSentLast%51200), minRead);

      readBufferSentLast += minRead;
      count -= minRead;
      readBytes += minRead;
    }
    this->returnSystemCall(syscallUUID, readBytes);
  }
}

/* write() system call */
void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd,
        const void *buf, size_t count)
{
  uint32_t src_ip, dst_ip, bigSeqNum;
  uint16_t src_port, dst_port;
  bool isServer = true;
  uint32_t *seqNum;
  int flag = ACK;
  uint16_t zero16 = 0;
  uint8_t copyPacket[532];
  size_t writtenByte = 0;
  uint64_t sockKey = getPidSocketKey(pid, sockfd);
  auto iter = fdToAddr.begin();
  if ((iter = fdToAddr.find(sockKey)) == fdToAddr.end())
    this->returnSystemCall(syscallUUID, -1);

  auto iterServer = serverMap.begin();
  auto iterClient = clientMap.begin();
  serverSocketEntry * serverSocket;
  clientSocketEntry * clientSocket;
  // Find socket information with sockfd and pid
  if ((iterServer = serverMap.find(sockKey)) == serverMap.end()) {
    isServer = false;
    iterClient = clientMap.find(sockfd);
    clientSocket = iterClient->second;
  }
  else {
    serverSocket = iterServer->second;
  }
  if (isServer)
    seqNum = &(serverSocket->seqNum);
  else
    seqNum = &(this->clientSeq);

  /** FLOW CONTROL & CONGESTION CONTROL **/
  size_t minCwnd = 51200 > cwnd ? cwnd : 51200;
  minCwnd = rwnd > minCwnd ? minCwnd : rwnd;

  if (unACKedbytes + 512 <= minCwnd) {
    src_port = htons(std::get<1>(iter->second));
    src_ip = htonl(std::get<2>(iter->second));
    dst_port = htons(std::get<3>(iter->second));
    dst_ip = htonl(std::get<4>(iter->second));

    Packet* initialPacket = this->allocatePacket(566);
    initialPacket->writeData(14+12, &src_ip, 4);
    initialPacket->writeData(14+16, &dst_ip, 4);
    initialPacket->writeData(34, &src_port, 2);
    initialPacket->writeData(36, &dst_port, 2);

    // length and unused field
    uint8_t lengthAndUnused = (5 << 4) & 0xF0;
    initialPacket->writeData(46, &lengthAndUnused, 1);

    // window size
    uint16_t windowSize = htons(51200);
    initialPacket->writeData(48, &windowSize, 2);

    Packet* myPacket = this->clonePacket(initialPacket);

    bigSeqNum = htonl(*seqNum);
    myPacket->writeData(38, &bigSeqNum, 4);

    // write acknowledge number
    uint32_t rcvNum = htonl(this->receivedSeq);
    myPacket->writeData(42, &rcvNum, 4);

    // write flag
    myPacket->writeData(47, &flag, 1);

    // write payload
    myPacket->writeData(54, ((uint8_t*)buf)+writtenByte, 512);

    // zero cksum field, calculate cksum, and set cksum
    myPacket->writeData(50, &zero16, 2);
    memset(copyPacket, 0, 532);
    myPacket->readData(34, copyPacket, 532);
    uint16_t sendChecksum = ~NetworkUtil::tcp_sum(src_ip, dst_ip, copyPacket, 532);
    sendChecksum = htons(sendChecksum);
    myPacket->writeData(50, &sendChecksum, 2);

    this->sendPacket("IPv4", myPacket);
    count -= 512;
    writtenByte += 512;
    unACKedbytes += 512;

    /** FOR UNRELIABLE DATA TRANSMISSION **/
    Packet * cloned = this->clonePacket(myPacket);
    sndIntBuf[*seqNum] = cloned;
    fdSeq * fdSeqPtr = (fdSeq *)malloc(sizeof(fdSeq));
    fdSeqPtr->seqNum = *seqNum;
    fdSeqPtr->sockfd = sockfd;
    UUID timerID = addTimer(fdSeqPtr, 100000000);
    Time sentTime = this->getHost()->getSystem()->getCurrentTime();
    timerMap[*seqNum] = timerNamespace(timerID, sockfd, sentTime);
    /*************************************/

    *seqNum += 512;

    this->freePacket(initialPacket);
    this->returnSystemCall(syscallUUID, writtenByte);
  }
  else  // FLOW CONTROL => pend write()
  {
    uint8_t * bufCopy = (uint8_t *)malloc(count);
    memcpy(bufCopy, buf+writtenByte, count);
    pendingWrite pend = pendingWrite(syscallUUID, bufCopy, count);
    pendingWrites.push(pend);
  }
}

// Function to make Key which is concatenation of pid and sockfd
uint64_t TCPAssignment::getPidSocketKey(int pid, int sockfd) 
{
  return ((((uint64_t)pid)<<32) & 0xFFFFFFFF00000000) + sockfd;
}

// Function to make packet header
void TCPAssignment::sendPacketHeader(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t flag,
        uint32_t* seqNum, uint32_t rcvNum, uint32_t seqNumBeforeIncr, uint32_t seqNumAfterIncr, uint32_t rcvNumIncr, bool makeTimer, int sockfd)
{
  if (flag == FIN)
    flag = FIN;
  
  uint32_t seqNumCopy = *seqNum;
  Packet* myPacket = this->allocatePacket(54);

  myPacket->writeData(14+12, &src_ip, 4);
  myPacket->writeData(14+16, &dst_ip, 4);
  myPacket->writeData(34, &src_port, 2);
  myPacket->writeData(36, &dst_port, 2);
          
  // write sequence number
  *seqNum += seqNumBeforeIncr;
  uint32_t bigSeqNum = htonl(*seqNum);
  myPacket->writeData(38, &bigSeqNum, 4);
  *seqNum += seqNumAfterIncr;

  // write flag
  myPacket->writeData(47, &flag, 1);

  // write acknowledge number
  rcvNum += rcvNumIncr;
  rcvNum = htonl(rcvNum);
  myPacket->writeData(42, &rcvNum, 4);
  
  // length and unused field
  uint8_t lengthAndUnused = (5 << 4) & 0xF0;
  myPacket->writeData(46, &lengthAndUnused, 1);

  // window size
  uint16_t windowSize = htons(51200);
  myPacket->writeData(48, &windowSize, 2);

  // zero cksum field, calculate cksum, and set cksum
  uint16_t zero16 = 0;
  myPacket->writeData(50, &zero16, 2);
  uint8_t packetHeader[20];
  myPacket->readData(34, packetHeader, 20);
  uint16_t sendChecksum = ~NetworkUtil::tcp_sum(src_ip, dst_ip, packetHeader, 20);
  sendChecksum = htons(sendChecksum);
  myPacket->writeData(50, &sendChecksum, 2);

  // IP module will fill rest of IP header, send it to correct network interface 
  this->sendPacket("IPv4", myPacket);

  /**** FOR UNRELIABLE DATA TRANSMISSION ****/
  if (makeTimer) {
    fdSeq * fdSeqPtr = (fdSeq *)malloc(sizeof(fdSeq));
    fdSeqPtr->seqNum = seqNumCopy;
    fdSeqPtr->sockfd = sockfd;
    UUID timerID = addTimer(fdSeqPtr, 100000000);
    Time sentTime = this->getHost()->getSystem()->getCurrentTime();
    timerMap[seqNumCopy] = timerNamespace(timerID, sockfd, sentTime);

    Packet * clonedPacket = this->clonePacket(myPacket);
    sndIntBuf[seqNumCopy] = clonedPacket;
  }
  /****************************************/
}

// Function to calculate RTO with RTT, SRTT, RTTVAR
uint64_t TCPAssignment::calcRTO(uint64_t RTT, uint64_t SRTT, uint64_t RTTVAR) {
  SRTT = (1-ALPHA)*SRTT + ALPHA*RTT;
  RTTVAR = (1-BETA)* RTTVAR + BETA*abs((long long)(SRTT-RTT));
  uint64_t RTO = SRTT + K*RTTVAR;

  this->SRTT = SRTT;
  this->RTTVAR = RTTVAR;
  this->RTO = RTO;

  return RTO;
}

}

