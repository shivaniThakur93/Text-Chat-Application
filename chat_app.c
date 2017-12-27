/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>

#include <ifaddrs.h>


#define MAXDATASIZE 400 // max number of bytes we can get at once 
#define BACKLOG 4
#define BUFFERSIZE 1024
#define MAXBUFFERMSGSIZE 25600
#define COPYINPUTSIZE 450
#define INET_ADDRSTRLEN 16
#define INPUTBUFSIZE 5
#define DATASIZE 128 //for ip addresses,hostnames,status info, 
#define LOGGEDINSTATUS "logged-in" //for ip addresses,hostnames,status info, 
#define LOGGEDOUTSTATUS "logged-out" //for ip addresses,hostnames,status info, 
#define STDIN 0
#define LISTMESSAGE "L"
#define MESSAGE "M"
#define UBITNAME "sthakur3"
//defining shell commands
  //defining a master structure for all the client info to be kept on server side
  struct bufferedMessages{
    char bufMsg[MAXDATASIZE];
    char senderIP[DATASIZE];
  };
  //this master structure will be kept updated and then further used to provide info to the logging in clients and statistics of the system
  struct clientMasterInfo
  {
    char buffMsgs[100][MAXDATASIZE];//buffered messages for the client
    char hostName[DATASIZE];
    char status[DATASIZE];
    char ipAddress[DATASIZE];
    int listeningPortNumber;
    int messagesSent;
    int messagesReceived;
    int clientSocket;
    char blockedClientsIP[3][DATASIZE]; // at max a client can block 3 clients and IPs data size will not exceed 128 bytes
  };
  //defining global structure for list of logged in clients to be maintained on the server
  struct listForClients{
    char hostName[DATASIZE];
    char ipAddress[DATASIZE];
    char portNo[DATASIZE];

  };
  //defining global structure for client info to be maintained on the server
  struct clientMasterInfo clientsInfo[5]; // as the max number of clients is 4
  //defining global structure for list for clients to be used for later use
  struct listForClients listForClients[4]; // as the max number of clients other than the client itself is 3
  //defining global variables
  int listenerServerSocket,newserversockfd;
  socklen_t client_len;
  int numbytes,i;  
  const char *plogin="LOGIN";
  const char *pexit="EXIT";
  const char *pauthor="AUTHOR";
  const char *psend="SEND";
  const char *pip="IP";
  const char *pport="PORT";
  int yes=1;
  int fdmax;
  //defining functions for the application
  //print Author commans
  void authorFunction() {
    printf("I, %s, have read and understood the course academic integrity policy.\n",UBITNAME);  
    return;
    }
  void ipFunction(char *externalIP) {
    if(externalIP!=NULL){
    printf("IP:%s\n",externalIP);  
    }
    else{
      printf("External IP is null \n");
    }
    return;
    }
  void portFunction(int portNo) {
    printf("PORT:%d\n",portNo);  
    return;
    }
  int sendall(int socket, char *buf, int *len)
  { 
      int total = 0;        // how many bytes we've sent
      int bytesleft = *len; // how many we have left to send
      int n=0;
      while(total < *len) {
          n = send(socket, buf+total, bytesleft, 0);
          if (n == -1) { break; }
          total += n;
          bytesleft -= n;
  }
      return n==-1?-1:0; // return -1 on failure, 0 on success
  }

// receive all function

  int receiveall(int socket, char *buf)
  {
      int maxBuf = recv(socket,buf,INPUTBUFSIZE,0); // number of bytes received ,use first 5 bytes to get the message length
      int total=0; //buf contains the length of the read string
      int inputLength;
      int n;
      int x=0; // return variable
      if(maxBuf==0){
      printf("client hung up on the server \n");
      x=-1;
      }
      else if(maxBuf==5){
      inputLength=atoi(buf);
      while(total<inputLength){
      n= recv(socket,buf+total,inputLength+1,0);
      if(n == -1 || n==0){
      x=-1;
      break;}//remote has hung up the connection
      if (buf[0] == ' ') {
      memmove(buf, buf+1, strlen(buf));
      }
      total += n; 
      inputLength -= n;
      }
      }//add code for reading if maxBuf<5
      return x;// return -1 on failure, 0 on success
  }


  int isValidIpAddress(char *ipAddress)
  {
      struct sockaddr_in sa;
      int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
      return result;
  }

  //check for white spaces in inputted string
  char* containsWhiteSpace(char *str){
    char key[] = { ' '};
      return strpbrk (str, key);
  }

  //function to send entire data to the connected server
    int sendData(char *buf,int socket){
        //connect client to server (struct sockaddr *) 
            int len2;
            int msgLen2;
            char msgBuf2[BUFFERSIZE];
            int n=0;
            //send the whole input command message to the server
            len2=strlen(buf);
            sprintf(msgBuf2,"%5d %s",len2,buf);
            msgLen2=strlen(msgBuf2);
            if (sendall(socket,msgBuf2,&msgLen2) == -1) 
                {
                 printf("We only sent %d bytes because of the error! \n", len2);
                 n=-1;
                }
            return n; // -1 on failure /0 on success
    }
    //defining compare function to keep the master buffer structure on server sorted. This buffer will be used for other clients as well
  //Reference : https://stackoverflow.com/questions/13372688/sorting-members-of-structure-array
    int compare(const void *s1, const void *s2)
    {
      struct clientMasterInfo *e1 = (struct clientMasterInfo *)s1;
      struct clientMasterInfo *e2 = (struct clientMasterInfo *)s2;
        return e1->listeningPortNumber - e2->listeningPortNumber;
    }
    //create message to be sent for the client
    char * createMessageString(char *senderIP, char *msg){
      char *msgSendString=malloc(sizeof(char) * 400);
      strcpy(msgSendString,MESSAGE);
      strcat(msgSendString,senderIP);
      strcat(msgSendString,"@");
      strcat(msgSendString,msg);
      return msgSendString;    
    }
    //store the received list
    void storeClientsList(char *listString){
        char *ptr= malloc(sizeof(char) * 1024); 
        ptr=strtok(listString,"@"); //this will give the hostname in the list 
            int count=0;
            int k=0;
            int j=0;
            if(ptr!=NULL){
              while(ptr!=NULL && k<=3){
              if(j!=0)
              ptr=strtok(NULL,"@"); //this will give the hostname in the list 
              if(count==0 && ptr!=NULL){
              strcpy(listForClients[k].hostName,ptr);
              count++;
              j++;
              continue;
              }
              else if(count==1){
              strcpy(listForClients[k].ipAddress,ptr);
              count++;
              continue;
              }
              else if(count==2){
              strcpy(listForClients[k].portNo,ptr);
              count=0;
              k++;
              continue;
              }
            }
            }
            free(ptr);
    }
  // get IP address from the given socket by iterating the master struct for server code
  char * getIPfromSocket(int socket){
      int i;
      char *ipAddr=(char *) malloc(sizeof(char) * 20);
      for(i=0;i<=3;i++){
        if(strlen(clientsInfo[i].ipAddress)==0){ //no ip at this address, break
          break;
        }
        else if(clientsInfo[i].clientSocket==socket){
          ipAddr=clientsInfo[i].ipAddress;
        }
        else{
        continue;
        }
      }
      return ipAddr;
    }
    // get socket from IP by iterating the master struct for server code
  int getSocketFromIP(char *clientIP){
      int i;
      int socket;
      for(i=0;i<=3;i++){
        if(strlen(clientsInfo[i].ipAddress)==0){ //no ip at this address, break
          break;
        }
        else if(strcmp(clientsInfo[i].ipAddress,clientIP)==0){
          socket=clientsInfo[i].clientSocket;
        }
        else{
        continue;
        }
      }
      return socket;
    }
  //check whether the sender is blocked by the receiver
  int isSenderBlocked(char *senderIP,char *receiverIP){
    int i;
    int result=-1;
    for(i=0;i<=3;i++){
       if(strlen(clientsInfo[i].ipAddress)==0){ //no ip at this address, break
          break;
        }
        else if(clientsInfo[i].ipAddress==receiverIP){//this gives the receivers record in the master struct of server
        for(int j=0;j<=2;j++){// can block max 3 clients
          if(strlen(clientsInfo[i].blockedClientsIP[j])==0){ //no blocked client ip at this address, break
          break;
        }
        else if(strcmp(clientsInfo[i].blockedClientsIP[j],senderIP)==0){
          result=0;//sender is blcoked
        }
        else{
          continue;
        }
        }
        }
        else{
        continue;
        }
    }
    return result;
  }
  //is a client with the given IP logged in or not
  int isClientLoggedIn(char *clientIP){
    int loggedin=-1;
    for(i=0;i<=3;i++){
       if(strlen(clientsInfo[i].ipAddress)==0){ //no ip at this address, break
          break;
        }
        else if(strcmp(clientsInfo[i].ipAddress,clientIP)==0){//this gives the receivers record in the master struct of server
        if(strcmp(clientsInfo[i].status,LOGGEDINSTATUS)==0){
          loggedin=0;
          break;
        }
        else if(strcmp(clientsInfo[i].status,LOGGEDOUTSTATUS)==0){
          loggedin=1;
          break;
        }
        }
        else{
        continue;
        }
    }
    return loggedin;
  }
  //buffer messages for the client with given ip address
  //is a client with the given IP logged in or not
  void bufferMessageForClient(char *clientIP,char *message){
    for(i=0;i<=3;i++){
       if(strlen(clientsInfo[i].ipAddress)==0){ //no ip at this address, break
          break;
        }
        else if(clientsInfo[i].ipAddress==clientIP){//this gives the receivers record in the master struct of server
        for(int j=0;j<100;j++){
          if(strlen(clientsInfo[i].buffMsgs[j])==0){//buff msg is empty at this position fill the message here
            strcpy(clientsInfo[i].buffMsgs[j],message);
            break;
          }
          else{
            continue;
          }
        }
        }
    }
  }
  //end buffer messages

  //display the received message from server
  void displayReceivedMessage(char *recvMsg){
    char *ptr= malloc(sizeof(char) * 256); 
    ptr=strtok(recvMsg,"@");
    if(ptr!=NULL){
    ptr=strtok(NULL,"\0");
    }

  }
  //end display the received message from server
  //start of main function
  int main(int argc, char *argv[])
  {
  int yes=1;
  fd_set master;    // master file descriptor list
  fd_set read_fds;  // temp file descriptor list for select()
  fd_set client_master;    // master file descriptor list
  fd_set client_read_fds;  // temp file descriptor list for select()
  struct sockaddr_in serv_addr,my_addr,client_addr;
  int len,msgLen;
  int hostNameResult;
  FD_ZERO(&read_fds);
  FD_ZERO(&master);
  //server code to be exceuted
  char buf[BUFFERSIZE];
  char copybuf[BUFFERSIZE];
  char msgBuf[BUFFERSIZE];
  int sockfd;
  //common for server and client
  //reference : https://stackoverflow.com/questions/4139405/how-can-i-get-to-know-the-ip-address-for-interfaces-in-c
  //this code gets to get the external ip address of the system, i have taken the ip address when the interface is ethernet
  struct ifaddrs *ifapifaddrs,*ifap, *ifa;
  struct sockaddr_in *sa;
  char *addr;
  char *externalIP;
  if(argc < 2){
      fprintf(stderr,"Error, no port provided \n");
      exit(1);
    }
        int externalIPResult=getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            if(strcmp(ifa->ifa_name,"en0")==0){
              strcpy(externalIP,addr);
            }
        }
    }
   freeifaddrs(ifap);
  char *startType=argv[1];
  int portNo=atoi(argv[2]);

//if app is run as server
if(*startType == 's'){
  //struct and variables to fill up requesting client data
  int i;
  struct sockaddr_in client_msg_addr;
  int reqClientPort;
  char ipstr[DATASIZE];
  char clientHostName[DATASIZE]; //hostname of a particular client
  char clientService[DATASIZE];
  //create a struct server for relaying messages need to look into this later
  struct sockaddr_in relay_msg_addr;
  char * ptr= malloc(sizeof(char) * 800);
  int numbytes;  // listen on sock_fd, new connection on new_fd
  if(argc < 2){
    fprintf(stderr,"Error, no port provided \n");
    exit(1);
  }

  //opening socket on server
  listenerServerSocket=socket(PF_INET,SOCK_STREAM,0);
  if(listenerServerSocket < 0){
    printf("Error Opening socket Listener Socket \n");
  }
  // add the listener to the master set
  //fill up serv_addr socket with server information from command line  
  memset(&serv_addr.sin_zero, '\0', sizeof serv_addr.sin_zero);
  serv_addr.sin_family=AF_INET;
  serv_addr.sin_port=htons(portNo);
  serv_addr.sin_addr.s_addr=inet_addr(externalIP);
  //setting struct linger to end client connection immediately on socket close
  struct linger linger;
  memset(&linger, 0, sizeof linger);
    linger.l_onoff = 1;
    linger.l_linger = 0;
  setsockopt(listenerServerSocket, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger));
  if(setsockopt(listenerServerSocket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
                    perror("setsockopt");
                    exit(1);
  }
  if(setsockopt(listenerServerSocket, SOL_SOCKET, SO_REUSEPORT, (const char*)&yes, sizeof(yes)) < 0) {
                      perror("setsockopt(SO_REUSEPORT) failed");
  }
  //bind the port with the socket
  if(bind(listenerServerSocket, (struct sockaddr *) &serv_addr,sizeof(serv_addr))<0){
    printf("Error on binding \n");
  }
  listen(listenerServerSocket,BACKLOG);
  
  FD_SET(listenerServerSocket, &master);
  FD_SET(STDIN, &master);
  // keep track of the biggest file descriptor
  fdmax = listenerServerSocket; // so far, it's this one
  //code for select call
  for(;;){ 
    read_fds = master; // copy of master fds into read-fds
    //select call to check for open connections
    if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
        perror("select \n");
    exit(4); }
    //loop through the existing conenctions looking for data to read
    for(i=0;i<=fdmax;i++){
    if (FD_ISSET(i, &read_fds)) { // we got one!!
        if(i==STDIN){//this means that we have got the standard input from user
        char inputCommand[MAXDATASIZE]="0"; // input like LOGIN SEND
        char copyInput[MAXDATASIZE]="0"; // copy of input like LOGIN SEND
        fgets(inputCommand,MAXDATASIZE,stdin);
        inputCommand[strlen(inputCommand) -1] = '\0';//add null terminator 
        strcpy(copyInput,inputCommand);
          //check for spaces in the input command
                      char *p=containsWhiteSpace(copyInput);
                      if(p==NULL){
                        p=strtok(copyInput, "\n");
                        if(strcmp(p,pauthor) == 0){
                        authorFunction();
                        } 
                        else if(strcmp(p,pip) == 0){
                        ipFunction(externalIP);                        
                        }
                        else if(strcmp(p,pport) == 0){
                        portFunction(portNo);
                        }
                      }
  }
        else if(i==listenerServerSocket){
            //this is a new connection accept this connection
            //accept client connection
            newserversockfd=accept(listenerServerSocket,(struct sockaddr *) &client_addr,&client_len);
            if(newserversockfd == -1){
              printf("Error on accept \n");
              }
            else{
                FD_SET(newserversockfd, &master); // add to master set
                if (newserversockfd > fdmax) {    // keep track of the max
                            fdmax = newserversockfd;
                        }
            }
        }
        else {
            //handle data from client
            memset(buf, '\0', sizeof buf);
            //reading data sent from client : loop the data to receive all data use receive all function
            if ((numbytes = receiveall(i, buf)) == 0) { // data received fully
            strcpy(copybuf,buf);
            //extract the ip address and port number of the client corresponding to this socket
            socklen_t len = sizeof client_msg_addr;
            if(getpeername(i,(struct sockaddr*)&client_msg_addr,&len)==0){// peer info received corerctly
            //extracting client ip and port no of the client who sent the request from client_msg_addr field

            struct sockaddr_in *s = (struct sockaddr_in *)&client_msg_addr;
              reqClientPort = ntohs(s->sin_port);
              inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
              //get hostname of this ip address
              if(getnameinfo((struct sockaddr*)s, sizeof s, clientHostName, sizeof clientHostName, clientService, sizeof clientService, 0)==0){
              //host name of requesting client received successfully
              }
            }
            else if(getpeername(i,(struct sockaddr*)&client_msg_addr,&len)==-1){
            //error in getting peer info
            printf("Could not receive peer infor : error \n");
            }
            char *p=containsWhiteSpace(copybuf);
            //if received message does not contain white spaces
                if(p==NULL){

                }
                else{
            //if received message contains white spaces

                  char *ptr= malloc(sizeof(char) * 1024); 
                  int count=0;
                  char *ip4=malloc(sizeof(char) * 1024);
                        char *msg=malloc(sizeof(char) * 1024);
                  ptr=strtok(copybuf," "); // extract command name
                  if(ptr!=NULL){
                    //fill up the master struct with the connecting client info
                    if(strcmp(ptr,plogin) == 0){ // LOGIN user request. we just need the first param
                      //now we want to fill up master struct to keep track of this client
                      //iterate the master struct to check if it already contains this ip address in its info panel
                      int j;
                      for(j=0;j<=3;j++){
                        if(!(strlen(clientsInfo[j].ipAddress)==0)){ //means the ip address is filled up at ith position 
                          if(reqClientPort==clientsInfo[j].listeningPortNumber){ //on local port nos used, in actual we will compare ip addresses
                            strcpy(clientsInfo[j].status,LOGGEDINSTATUS);
                            //if the client has ever logged in it will be found in the master struct
                            // now use the master struct to get its buff msgs if any
                            for(int k=0;k<100;k++){
                              if(strlen(clientsInfo[j].buffMsgs[k])>0){ 
                                  //client has some buff msgs
                                  int result=sendData(clientsInfo[j].buffMsgs[k],i); // i is the current socket used to send data to the client
                                              if(result==-1){
                                                  printf("error in transfer \n");
                                              }
                                              else if (result==0){
                                                  printf("transferred complete data \n");
                                              }
                                  }
                                  }
                                  break;
                          }
                          else{
                            continue;
                          }
                        }
                        else{// the ip address was not found, hence fill it at the empty ith position
                          strcpy(clientsInfo[j].status,LOGGEDINSTATUS);
                          strcpy(clientsInfo[j].ipAddress,ipstr);                         
                          //start new code for host name
                          struct sockaddr_in sa; // IPv4
                          char host[1024];
                          char service[20];
                          memset(&sa, 0, sizeof sa);
                          int nameInfoResult;
                          //filling up sa struct
                          sa.sin_family=AF_INET;
                          sa.sin_port = htons(reqClientPort); //portNo is the listening port number
                          sa.sin_addr.s_addr= inet_addr(ipstr);
                          //end filling up sa struct
                          // pretend sa is full of good information about the host and port...
                          if((nameInfoResult=getnameinfo(&sa, sizeof sa, host, sizeof host, service, sizeof service, 0))==0){
                          strcpy(clientsInfo[j].hostName,host);
                          }
                          else{
                            printf("There was an error retreiving host name\n");
                          } 
                          clientsInfo[j].listeningPortNumber=reqClientPort;
                          clientsInfo[j].clientSocket=i;
                          break;
                        }
                      }
                      //call qsort function to sort the master struct 
                      qsort(clientsInfo, j, sizeof(struct clientMasterInfo), compare);
                      //construct list of logged in clients from master struct and pass it to the logged in user
                      char listMsgSendString[MAXDATASIZE];
                      strcpy(listMsgSendString,LISTMESSAGE);
                      for(int n=0;n<=3;n++){
                        if(strlen(clientsInfo[n].ipAddress)==0){//master struct does not have any valid entry at nth position
                                break;  
                        }
                        else if(strcmp(clientsInfo[n].status,LOGGEDINSTATUS)==0){ //this means strings match
                                  strcat(listMsgSendString, clientsInfo[n].hostName);
                                  strcat(listMsgSendString,"@");
                                  strcat(listMsgSendString, clientsInfo[n].ipAddress);
                                  strcat(listMsgSendString,"@");
                                  int listeningPortNumber = clientsInfo[n].listeningPortNumber;
                                  char sPortNo[MAXDATASIZE];
                                  // convert 123 to string [buf]
                                  snprintf(sPortNo, MAXDATASIZE, "%d", listeningPortNumber);
                                  strcat(listMsgSendString, sPortNo);
                                  strcat(listMsgSendString,"@");

                        }
                      }
                      if(strlen(listMsgSendString)>1){//means there was at least one logged in user info that can be sent
                        if (sendData(listMsgSendString,i) == -1) 
                              {
                                printf("We only sent %d bytes because of the error! \n", len);
                              }
                        else{
                          printf("server sent all the data of logged in clients to the client::%s\n",listMsgSendString);
                        }
                      }
                    }
                    else if(strcmp(ptr,psend) == 0){ // SEND user request
                      char *ipAddr=(char *) malloc(sizeof(char) * 20);
                                int count=0;
                                ptr=strtok(NULL," ");
                      if(ptr!=NULL){ // this gives us client IP
                        count += 1;
                        strcpy(ip4, ptr);
                      }
                      //ptr points to the message now
                      ptr=strtok(NULL,"\0");
                      if(ptr!=NULL){
                        count += 1;
                        strcpy(msg, ptr);
                      }
                      //means we received the client message with full arguments
                      if(count==2){
                      //iterate master struct to find ip corresponding to i socket
                      ipAddr=getIPfromSocket(i);
                      int blocked=isSenderBlocked(ipAddr,ipstr);
                      if(blocked==0){
                        //sender is blocked do nothing
                      }
                      else{
                        //sender is not blocked, check the logged in status of the receiver
                        //if logged in send the data , else buffer the data
                        int loggedin=isClientLoggedIn(ipstr);
                        char *messageSendString=malloc(sizeof(char) * 400); ;
                        messageSendString=createMessageString(ipAddr,msg);
                        if(loggedin==0){     //client is logged in, send the received message
                        int receiverSocket=getSocketFromIP(ipstr); //get the client socket from its IP
                        if(receiverSocket>0){
                          if(sendData(messageSendString,receiverSocket)==-1){
                          }
                        }
                        }else if(loggedin==1){//client is logged out , buffer messages for him
                        bufferMessageForClient(ipstr,messageSendString);
                        }
                        else if(loggedin==-1){//client does not exist in the server's records-> client has exited the system
                          printf("Client record not found in server's clients list\n");
                        }
                      }
                      free(ip4);
                      free(msg);
                      }
                      
                      
                    }
                  }// if condtion for send ends here
                  //now do further processing here : if client is logged in or logged out ??
                }
          } 
          else if((numbytes = receiveall(i, buf)) == -1){
          FD_CLR(i,&master);          
        }
         }
      }
    }
  }
  return 0;
  
}
//if app is run as client
  else if(*startType == 'c'){
    int serverPortNo;
    //client code to be exceuted
    if(argc < 2){
      fprintf(stderr,"usage %s hostname port \n",argv[0]);
      exit(0);
    }

    //write the code here for shell commands for the client . this will be generic code.
    FD_SET(STDIN, &master);
    fdmax = STDIN; // keep track of biggest file descriptor so far, it's this one
    while(1){
    read_fds=master;
    //select use
    //select call to check for open connections
    if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
         exit(4); }
    for(int i=0;i<=fdmax;i++){
      if(FD_ISSET(i, &read_fds)){
      if(i==STDIN){
        //input from user
        char inputCommand[MAXDATASIZE]="0"; // input like LOGIN SEND
        char copyInput[MAXDATASIZE]="0"; // copy of input like LOGIN SEND
        fgets(inputCommand,MAXDATASIZE,stdin);
        inputCommand[strlen(inputCommand) -1] = '\0';//add null terminator 
        strcpy(copyInput,inputCommand);
          //check for spaces in the input command
                      char *p=containsWhiteSpace(copyInput);
                      //if input string does not contain white spaces
                      if(p==NULL){ 
                        p=strtok(copyInput, "\n");
                        if(strcmp(p,pexit) == 0){
                          printf("deleting client state on the server and exiting the application \n"); // delete client state on the server
                          exit(0);
                        } 
                        else if(strcmp(p,pauthor) == 0){
                          authorFunction();
                        }
                        else if(strcmp(p,pip) == 0){
                        ipFunction(externalIP);                        
                        }
                        else if(strcmp(p,pport) == 0){
                        portFunction(portNo);
                        }
                      }
                      //if input string contains white spaces,then split the string to get sub strings
                      else{
                        char * ptr= malloc(sizeof(char) * 800); 
                        ptr=strtok(copyInput," "); // extract command name
                        if(ptr!=NULL){
                          //LOGIN SHELL COMMAND CASE
                          if(strcmp(ptr,plogin) == 0){
                            int count=0;
                            char *ip4=malloc(sizeof(char) * 800);
                            while(ptr!=NULL){
                                ptr=strtok(NULL," ");
                                if(ptr!=NULL){
                                count=count+1;
                                if(count==1){
                                strcpy(ip4, ptr);
                                int result = isValidIpAddress(ip4);
                                if(result==0){
                                printf("invalid ip address \n");
                                  exit(0);  
                                }
                                }
                                if(count==2){
                                serverPortNo=atoi(ptr); // extract the server port number from login user command
                                //add code for port number validation
                                }
                              }
                              }
                              if(count!=2){
                                printf("unsupported number of arguments \n");
                                exit(0);
                              }
                              else{
                                //everything worked fine so we landed here  
                                sockfd=socket(AF_INET,SOCK_STREAM,0);
                                if(sockfd < 0){
                              printf("Error Opening socket \n");
                              }
                              //bind the communicating socket to the listening port of the client
                              //fill up a struct my_addr to bind it with socket
                              //fill up serv_addr socket with server information from command line
                              memset(my_addr.sin_zero, '\0', sizeof my_addr.sin_zero);
                              my_addr.sin_family=AF_INET;
                              my_addr.sin_port = htons(portNo); //portNo is the listening port number
                              my_addr.sin_addr.s_addr= inet_addr(externalIP);
                              if(bind(sockfd, (struct sockaddr *) &my_addr,sizeof(my_addr))<0){
                                printf("Error on binding client socket with client IP \n");
                              }
                              //adding server addr fields for connecting to the server
                              memset(serv_addr.sin_zero, '\0', sizeof serv_addr.sin_zero);
                              serv_addr.sin_family=AF_INET;
                              serv_addr.sin_port = htons(serverPortNo);//this should be the server port we will get this via login command second argument
                              serv_addr.sin_addr.s_addr= inet_addr(ip4);
                              //end
                              if(connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
                                printf("Error connecting \n");  
                                }
                              //update fdmax 
                              FD_SET(sockfd, &master); // add to master set
                              fdmax=sockfd;
                              //printf("printing message buffer %s \n",msgBuf);
                              if (sendData(inputCommand,sockfd) == -1) 
                              {
                                printf("We only sent %d bytes because of the error! \n", len);
                              }
                              }
                          }
                          //SEND SHELL COMMAND CASE
                                  else if(strcmp(ptr,psend) == 0){
                                    //check if the user is logged in or not. a valid value of sockfd will confirm that user is signed in
                                      int count=0;
                                      int sendTrue=0;
                                      char *ip4=malloc(sizeof(char) * 800);
                                      while(ptr!=NULL){
                                          ptr=strtok(NULL," ");
                                          if(ptr!=NULL){
                                          count=count+1;
                                          if(count==1){
                                          //here we should get the client ip and give error if invalid IP
                                          strcpy(ip4, ptr);
                                          //here we need to add whether the client is in the logged in list or not
                                          int result = isValidIpAddress(ip4);
                                          if(result==0){
                                          exit(0);    
                                          }
                                          else{//if the ip is valid iterate the list of clients to match the ip
                                            for(int i=0;i<=3;i++){
                                              if((strlen(listForClients[i].ipAddress)==0)){//means the ip address is not filled at ith position
                                                break;
                                              }
                                              else if(strcmp(listForClients[i].ipAddress,ip4)==0){//ip matches : send data to the ip address and break
                                            //send the entire user input to the server for taking further action
                                              int result=sendData(inputCommand,sockfd);
                                              if(result==-1){
                                                  printf("error in transfer \n");
                                              }
                                              else if (result==0){
                                                  sendTrue=1; //means data was transferred fully
                                               }
                                               break;
                                              }
                                              else{
                                                continue;
                                              }
                                            }
                                          }
                                          }
                                          if(count==2){
                                          break;
                                          //add code for port number validation
                                          }
                                      }
                                      }
                                          
                                          free(ip4);
                                  }
                        }
                      }
                        }
      else {
        //received data from server side
        memset(buf, '\0', sizeof buf);
        if ((numbytes = receiveall(i, buf)) == 0) { //data received fully
          //check for list or message
          if(buf[0]=='L'){
            memmove(buf, buf+1, strlen(buf));
            storeClientsList(buf);
          }
          else if(buf[0]=='M'){
            //display the message
            memmove(buf, buf+1, strlen(buf));
            displayReceivedMessage(buf);
          }

        }
        else if((numbytes = receiveall(i, buf)) == -1){
        FD_CLR(i,&master);        
      }

      }
     }
    }
    
  }
}
  return 0;

}