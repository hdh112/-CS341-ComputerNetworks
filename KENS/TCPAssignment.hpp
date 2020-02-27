/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/E_Common.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <queue>


#include <E/E_TimerModule.hpp>

#define MSS 512
#define DEFAULT_RECV_BUFFER 51200
#define DEFAULT_RTT 100000000
#define K 4
#define ALPHA 0.125
#define BETA 0.25

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
public:
  enum socketState { SOC_LISTEN, SYN_RCVD, ESTAB, CLOSE_WAIT, LAST_ACK, CLOSED, SYN_SENT, FIN_WAIT_1, FIN_WAIT_2, TIMED_WAIT };
  enum packetFlag { FIN=1, SYN=2, RST=4, ACK=16, SYNACK=18 };
  enum congestionState { SS, CA, FR }; // Slow start, Congestion avoidance, Fast recovery

  uint32_t clientSeq;
  uint32_t receivedSeq;
  uint8_t * TCPreadBuffer;
  int readBufferReceiveStart;
  int readBufferSentLast;
  uint32_t isDup;
  size_t unACKedbytes;
  uint32_t cwnd;
  uint32_t rwnd;
  uint32_t ssthresh;
  uint64_t RTT;
  uint64_t SRTT;
  uint64_t RTTVAR;
  uint64_t RTO;
  int dupACKcount;
  congestionState congState;

  typedef uint8_t Family;
  typedef uint16_t Port;
  typedef uint32_t IPAddr;
  typedef int PID;
  typedef uint32_t recentAck;    // 6
  typedef std::tuple<Family, Port, IPAddr, Port, IPAddr, PID, recentAck> Namespace;
  std::unordered_map<uint64_t, Namespace> fdToAddr;

  /* serverSocketEntry: struct to store information of server socket */
  typedef struct serverSocketEntry {
    std::vector <struct sockaddr*> Pendings;
    int Backlog;
    socketState sState;
    UUID syscallUUID;
    int pid;
    int parentFd;
    struct sockaddr * acceptAddr; 
    int pendingCount;
    uint32_t seqNum;
    bool closeCalled; 
  } serverSocketEntry;

  std::unordered_map<uint64_t, serverSocketEntry *> serverMap;

  
  /* clientSocketEntry: struct to store information of client socket */
  typedef struct clientSocketEntry {
    socketState cState;
    uint32_t cSeq;
    UUID syscallUUID;
    UUID TimerID;
    bool closeCalled;
    int pid;
    bool handshaking; 
  } clientSocketEntry;
  
  std::unordered_map<int, clientSocketEntry *> clientMap;

  typedef std::tuple<UUID, void *, size_t, size_t> pendingRead; // 2: count, 3: readBytes
  std::queue<pendingRead> pendingReads;
  typedef std::tuple<UUID, void *, size_t> pendingWrite;
  std::queue<pendingWrite> pendingWrites;

  std::map<uint32_t, Packet *> sndIntBuf;
  std::map<uint32_t, Packet *> rcvIntBuf;
  typedef std::tuple<UUID, int, uint64_t> timerNamespace;  // TimerID and sockfd and sentTime
  std::map<uint32_t, timerNamespace> timerMap;

  typedef struct fdSeq {
    int sockfd;
    uint32_t seqNum;
  } fdSeq;

private:

private:
  virtual void timerCallback(void* payload) final;

  /***** KENS#1: Requirement2 *****/
  void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
  void syscall_close(UUID syscallUUID, int pid, int sockfd);
  void syscall_bind(UUID syscallUUID, int pid, int sockfd,  struct sockaddr *my_addr, socklen_t addrlen);
  void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  /********************************/

  /***** KENS#2: Requirements *****/
  void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr* serv_addr, socklen_t addrlen);
  void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen);
  void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  /********************************/

  /***** KENS#3: Requirements *****/
  void syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count);
  void syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count);
  /********************************/
  
  /***** Helper functions *****/
  uint64_t getPidSocketKey(int pid, int sockfd);
  void sendPacketHeader(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t flag, uint32_t* seqNum, uint32_t rcvNum, uint32_t seqNumBeforeIncr, uint32_t seqNumAfterIncr, uint32_t rcvNumIncr, bool makeTimer, int sockfd);
  uint64_t calcRTO(uint64_t RTT, uint64_t SRTT, uint64_t RTTVAR);

public:
  TCPAssignment(Host* host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();
protected:
  virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
  virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}
public:
  static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
