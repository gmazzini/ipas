// Gianluca Mazzini @2015- Version 4.05
#include <libwebsockets.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT_RX 20
#define AUTOSAVE 900
#define LBUF 100000
#define V4_BASE 8
#define V4_MAX 24
#define V6_BASE 16
#define V6_MAX 48
#define V4_INIT 65536U
#define V6_INIT 32768U

struct v4disk {
  uint32_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
};

struct v6disk {
  uint64_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
};

struct root {
  uint32_t child[2];
  uint32_t asn;
  uint32_t ts;
};

// Prefix length is stored in unused low prefix bits.
struct node4 {
  uint32_t key;
  uint32_t child[2];
  uint32_t asn;
  uint32_t ts;
};

struct node6 {
  uint64_t key;
  uint32_t child[2];
  uint32_t asn;
  uint32_t ts;
};

struct match {
  uint32_t asn;
  uint32_t ts;
  uint8_t cidr;
};

struct snapshot {
  struct v4disk *v4;
  struct v6disk *v6;
  uint32_t n4;
  uint32_t n6;
};

static struct root root4[1U<<V4_BASE];
static struct root root6[1U<<V6_BASE];
static struct node4 *node4;
static struct node6 *node6;
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static int server_fd=-1;
static volatile sig_atomic_t interrupted=0;
static volatile sig_atomic_t save_requested=0;
static volatile sig_atomic_t reconnect_requested=0;
static uint32_t follow=0,rxv4=0,rxv6=0,newv4=0,newv6=0;
static uint32_t tstart,trx,tnew,tsave=0,restart=0,query=0;
static uint32_t nsave=0,save_error=0;
static uint32_t nnode4=0,nnode6=0,cap4=0,cap6=0,nroute4=0,nroute6=0;
static const char *bgpfile;
static char *bgptmp;
static char *subscribe_message="{\"type\": \"ris_subscribe\", \"data\": {\"type\": \"UPDATE\", \"host\": \"rrc00\"}}";
static char *lbuf;

static int hexval(unsigned char c){
  if(c>='0'&&c<='9')return c-'0';
  if(c>='A'&&c<='F')return c-'A'+10;
  if(c>='a'&&c<='f')return c-'a'+10;
  return -1;
}


static uint32_t mask4(uint32_t ip,uint8_t cidr){
  return ip&(~0U<<(32-cidr));
}

static uint64_t mask6(uint64_t ip,uint8_t cidr){
  return ip&(~0ULL<<(64-cidr));
}

static uint8_t cidr4(const struct node4 *n){
  return (uint8_t)(n->key&31U);
}

static uint8_t cidr6(const struct node6 *n){
  return (uint8_t)(n->key&63ULL);
}

static uint32_t prefix4(const struct node4 *n){
  return n->key&~31U;
}

static uint64_t prefix6(const struct node6 *n){
  return n->key&~63ULL;
}

static uint8_t bit4(uint32_t ip,uint8_t bit){
  return (uint8_t)((ip>>(31-bit))&1U);
}

static uint8_t bit6(uint64_t ip,uint8_t bit){
  return (uint8_t)((ip>>(63-bit))&1ULL);
}

static uint8_t common4(uint32_t a,uint32_t b,uint8_t limit){
  uint32_t x;
  uint8_t n;

  x=a^b;
  if(x==0)return limit;
  n=(uint8_t)__builtin_clz(x);
  return n<limit?n:limit;
}

static uint8_t common6(uint64_t a,uint64_t b,uint8_t limit){
  uint64_t x;
  uint8_t n;

  x=a^b;
  if(x==0)return limit;
  n=(uint8_t)__builtin_clzll(x);
  return n<limit?n:limit;
}

static int reserve4(uint32_t extra){
  struct node4 *p;
  uint32_t need,ncap;

  need=nnode4+extra+1;
  if(need<=cap4)return 1;
  ncap=cap4?cap4:V4_INIT;
  while(ncap<need){
    if(ncap>0xaaaaaaaau)return 0;
    ncap+=ncap>>1;
  }
  p=(struct node4 *)realloc(node4,(size_t)ncap*sizeof(struct node4));
  if(p==NULL)return 0;
  node4=p;
  cap4=ncap;
  return 1;
}

static int reserve6(uint32_t extra){
  struct node6 *p;
  uint32_t need,ncap;

  need=nnode6+extra+1;
  if(need<=cap6)return 1;
  ncap=cap6?cap6:V6_INIT;
  while(ncap<need){
    if(ncap>0xaaaaaaaau)return 0;
    ncap+=ncap>>1;
  }
  p=(struct node6 *)realloc(node6,(size_t)ncap*sizeof(struct node6));
  if(p==NULL)return 0;
  node6=p;
  cap6=ncap;
  return 1;
}

static uint32_t addnode4(uint32_t ip,uint8_t cidr,uint32_t asn,uint32_t ts){
  struct node4 *n;

  nnode4++;
  n=node4+nnode4;
  n->key=mask4(ip,cidr)|cidr;
  n->child[0]=0;
  n->child[1]=0;
  n->asn=asn;
  n->ts=ts;
  return nnode4;
}

static uint32_t addnode6(uint64_t ip,uint8_t cidr,uint32_t asn,uint32_t ts){
  struct node6 *n;

  nnode6++;
  n=node6+nnode6;
  n->key=mask6(ip,cidr)|cidr;
  n->child[0]=0;
  n->child[1]=0;
  n->asn=asn;
  n->ts=ts;
  return nnode6;
}

static int insert4(uint32_t ip,uint8_t cidr,uint32_t asn,uint32_t ts,int count_new){
  struct root *r;
  struct node4 *n,*p;
  uint32_t *link,idx,newidx,branchidx,np;
  uint8_t nc,lim,common,dir;

  if(cidr<V4_BASE||cidr>V4_MAX||asn==0)return 0;
  ip=mask4(ip,cidr);
  r=root4+(ip>>24);
  if(cidr==V4_BASE){
    if(r->asn==0){
      nroute4++;
      if(count_new){newv4++; tnew=ts;}
    }
    r->asn=asn;
    r->ts=ts;
    return 1;
  }
  if(!reserve4(2))return 0;
  link=&r->child[bit4(ip,V4_BASE)];
  for(;;){
    idx=*link;
    if(idx==0){
      *link=addnode4(ip,cidr,asn,ts);
      nroute4++;
      if(count_new){newv4++; tnew=ts;}
      return 1;
    }
    n=node4+idx;
    nc=cidr4(n);
    np=prefix4(n);
    lim=nc<cidr?nc:cidr;
    common=common4(np,ip,lim);
    if(common<nc){
      if(common==cidr){
        newidx=addnode4(ip,cidr,asn,ts);
        p=node4+newidx;
        dir=bit4(np,common);
        p->child[dir]=idx;
        *link=newidx;
      }
      else {
        branchidx=addnode4(ip,common,0,0);
        p=node4+branchidx;
        p->child[bit4(np,common)]=idx;
        newidx=addnode4(ip,cidr,asn,ts);
        p=node4+branchidx;
        p->child[bit4(ip,common)]=newidx;
        *link=branchidx;
      }
      nroute4++;
      if(count_new){newv4++; tnew=ts;}
      return 1;
    }
    if(cidr==nc){
      if(n->asn==0){
        nroute4++;
        if(count_new){newv4++; tnew=ts;}
      }
      n->asn=asn;
      n->ts=ts;
      return 1;
    }
    dir=bit4(ip,nc);
    link=&n->child[dir];
  }
}

static int insert6(uint64_t ip,uint8_t cidr,uint32_t asn,uint32_t ts,int count_new){
  struct root *r;
  struct node6 *n,*p;
  uint32_t *link,idx,newidx,branchidx;
  uint64_t np;
  uint8_t nc,lim,common,dir;

  if(cidr<V6_BASE||cidr>V6_MAX||asn==0)return 0;
  ip=mask6(ip,cidr);
  r=root6+(uint32_t)(ip>>48);
  if(cidr==V6_BASE){
    if(r->asn==0){
      nroute6++;
      if(count_new){newv6++; tnew=ts;}
    }
    r->asn=asn;
    r->ts=ts;
    return 1;
  }
  if(!reserve6(2))return 0;
  link=&r->child[bit6(ip,V6_BASE)];
  for(;;){
    idx=*link;
    if(idx==0){
      *link=addnode6(ip,cidr,asn,ts);
      nroute6++;
      if(count_new){newv6++; tnew=ts;}
      return 1;
    }
    n=node6+idx;
    nc=cidr6(n);
    np=prefix6(n);
    lim=nc<cidr?nc:cidr;
    common=common6(np,ip,lim);
    if(common<nc){
      if(common==cidr){
        newidx=addnode6(ip,cidr,asn,ts);
        p=node6+newidx;
        dir=bit6(np,common);
        p->child[dir]=idx;
        *link=newidx;
      }
      else {
        branchidx=addnode6(ip,common,0,0);
        p=node6+branchidx;
        p->child[bit6(np,common)]=idx;
        newidx=addnode6(ip,cidr,asn,ts);
        p=node6+branchidx;
        p->child[bit6(ip,common)]=newidx;
        *link=branchidx;
      }
      nroute6++;
      if(count_new){newv6++; tnew=ts;}
      return 1;
    }
    if(cidr==nc){
      if(n->asn==0){
        nroute6++;
        if(count_new){newv6++; tnew=ts;}
      }
      n->asn=asn;
      n->ts=ts;
      return 1;
    }
    dir=bit6(ip,nc);
    link=&n->child[dir];
  }
}

static uint8_t lookup4(uint32_t ip,struct match *m){
  struct root *r;
  struct node4 *n;
  uint32_t idx,np;
  uint8_t nmatch,nc;

  nmatch=0;
  r=root4+(ip>>24);
  if(r->asn!=0){
    m[nmatch].asn=r->asn;
    m[nmatch].ts=r->ts;
    m[nmatch].cidr=V4_BASE;
    nmatch++;
  }
  idx=r->child[bit4(ip,V4_BASE)];
  while(idx!=0){
    n=node4+idx;
    nc=cidr4(n);
    np=prefix4(n);
    if(mask4(ip,nc)!=np)break;
    if(n->asn!=0){
      m[nmatch].asn=n->asn;
      m[nmatch].ts=n->ts;
      m[nmatch].cidr=nc;
      nmatch++;
    }
    if(nc>=V4_MAX)break;
    idx=n->child[bit4(ip,nc)];
  }
  return nmatch;
}

static uint8_t lookup6(uint64_t ip,struct match *m){
  struct root *r;
  struct node6 *n;
  uint32_t idx;
  uint64_t np;
  uint8_t nmatch,nc;

  nmatch=0;
  r=root6+(uint32_t)(ip>>48);
  if(r->asn!=0){
    m[nmatch].asn=r->asn;
    m[nmatch].ts=r->ts;
    m[nmatch].cidr=V6_BASE;
    nmatch++;
  }
  idx=r->child[bit6(ip,V6_BASE)];
  while(idx!=0){
    n=node6+idx;
    nc=cidr6(n);
    np=prefix6(n);
    if(mask6(ip,nc)!=np)break;
    if(n->asn!=0){
      m[nmatch].asn=n->asn;
      m[nmatch].ts=n->ts;
      m[nmatch].cidr=nc;
      nmatch++;
    }
    if(nc>=V6_MAX)break;
    idx=n->child[bit6(ip,nc)];
  }
  return nmatch;
}

static char *mydata(uint32_t x){
  time_t tt;
  struct tm *tm_info;
  static char buft[30];

  tt=(time_t)x;
  tm_info=localtime(&tt);
  strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
  return buft;
}

static int parse4(const char *ptr,int len,uint32_t *ip,uint8_t *cidr){
  uint32_t out;
  uint16_t v;
  int i,j;

  out=0;
  i=0;
  for(j=0;j<4;j++){
    v=0;
    if(i>=len)return 0;
    while(i<len&&ptr[i]>='0'&&ptr[i]<='9'){
      v=(uint16_t)(v*10+(ptr[i]-'0'));
      if(v>255)return 0;
      i++;
    }
    out=(out<<8)|v;
    if(j<3){
      if(i>=len||ptr[i]!='.')return 0;
      i++;
    }
  }
  if(i>=len||ptr[i]!='/')return 0;
  i++;
  v=0;
  while(i<len&&ptr[i]>='0'&&ptr[i]<='9'){
    v=(uint16_t)(v*10+(ptr[i]-'0'));
    i++;
  }
  if(v<V4_BASE||v>V4_MAX)return 0;
  *ip=out;
  *cidr=(uint8_t)v;
  return 1;
}

static int parse6prefix(const char *ptr,int len,uint64_t *ip,uint8_t *cidr){
  uint16_t part[4],v;
  uint64_t out;
  int i,j,digits;

  for(j=0;j<4;j++)part[j]=0;
  i=0;
  j=0;
  while(i<len&&ptr[i]!='/'&&j<4){
    if(ptr[i]==':'){
      if(i+1<len&&ptr[i+1]==':'){
        while(i<len&&ptr[i]!='/')i++;
        break;
      }
      i++;
      continue;
    }
    v=0;
    digits=0;
    while(i<len&&ptr[i]!=':'&&ptr[i]!='/'){
      if(hexval((unsigned char)ptr[i])<0||digits>=4)return 0;
      v=(uint16_t)((v<<4)+hexval((unsigned char)ptr[i]));
      digits++;
      i++;
    }
    if(digits==0)return 0;
    part[j++]=v;
  }
  while(i<len&&ptr[i]!='/')i++;
  if(i>=len||ptr[i]!='/')return 0;
  i++;
  v=0;
  while(i<len&&ptr[i]>='0'&&ptr[i]<='9'){
    v=(uint16_t)(v*10+(ptr[i]-'0'));
    i++;
  }
  if(v<V6_BASE||v>V6_MAX)return 0;
  out=0;
  for(j=0;j<4;j++)out=(out<<16)|part[j];
  *ip=out;
  *cidr=(uint8_t)v;
  return 1;
}

static int parse4query(const char *s,uint32_t *ip){
  uint32_t out;
  uint16_t v;
  int i,j;

  out=0;
  i=0;
  for(j=0;j<4;j++){
    v=0;
    if(s[i]<'0'||s[i]>'9')return 0;
    while(s[i]>='0'&&s[i]<='9'){
      v=(uint16_t)(v*10+(s[i]-'0'));
      if(v>255)return 0;
      i++;
    }
    out=(out<<8)|v;
    if(j<3){
      if(s[i]!='.')return 0;
      i++;
    }
  }
  *ip=out;
  return 1;
}

static int parse6query(const char *s,uint64_t *ip){
  unsigned char raw[16];
  uint64_t out;
  int i;

  if(inet_pton(AF_INET6,s,raw)!=1)return 0;
  out=0;
  for(i=0;i<8;i++)out=(out<<8)|raw[i];
  *ip=out;
  return 1;
}

static void myproc(char *ptr,int len,uint32_t asn,uint32_t ts){
  uint32_t ip4;
  uint64_t ip6;
  uint8_t cidr;
  int i;

  for(i=0;i<len;i++)if(ptr[i]==':'){
    rxv6++;
    if(parse6prefix(ptr,len,&ip6,&cidr))insert6(ip6,cidr,asn,ts,1);
    return;
  }
  rxv4++;
  if(parse4(ptr,len,&ip4,&cidr))insert4(ip4,cidr,asn,ts,1);
}

static void free_snapshot(struct snapshot *snap){
  free(snap->v4);
  free(snap->v6);
  snap->v4=NULL;
  snap->v6=NULL;
  snap->n4=0;
  snap->n6=0;
}

static int make_snapshot(struct snapshot *snap){
  struct v4disk *d4;
  struct v6disk *d6;
  uint32_t i,n4,n6;

  snap->v4=NULL;
  snap->v6=NULL;
  snap->n4=0;
  snap->n6=0;
  pthread_mutex_lock(&lock);
  n4=nroute4;
  n6=nroute6;
  d4=n4?(struct v4disk *)malloc((size_t)n4*sizeof(struct v4disk)):NULL;
  d6=n6?(struct v6disk *)malloc((size_t)n6*sizeof(struct v6disk)):NULL;
  if((n4&&d4==NULL)||(n6&&d6==NULL)){
    pthread_mutex_unlock(&lock);
    free(d4);
    free(d6);
    return 0;
  }
  n4=0;
  for(i=0;i<(1U<<V4_BASE);i++)if(root4[i].asn!=0){
    memset(d4+n4,0,sizeof(struct v4disk));
    d4[n4].ip=i<<24;
    d4[n4].cidr=V4_BASE;
    d4[n4].asn=root4[i].asn;
    d4[n4].ts=root4[i].ts;
    n4++;
  }
  for(i=1;i<=nnode4;i++)if(node4[i].asn!=0){
    memset(d4+n4,0,sizeof(struct v4disk));
    d4[n4].ip=prefix4(node4+i);
    d4[n4].cidr=cidr4(node4+i);
    d4[n4].asn=node4[i].asn;
    d4[n4].ts=node4[i].ts;
    n4++;
  }
  n6=0;
  for(i=0;i<(1U<<V6_BASE);i++)if(root6[i].asn!=0){
    memset(d6+n6,0,sizeof(struct v6disk));
    d6[n6].ip=(uint64_t)i<<48;
    d6[n6].cidr=V6_BASE;
    d6[n6].asn=root6[i].asn;
    d6[n6].ts=root6[i].ts;
    n6++;
  }
  for(i=1;i<=nnode6;i++)if(node6[i].asn!=0){
    memset(d6+n6,0,sizeof(struct v6disk));
    d6[n6].ip=prefix6(node6+i);
    d6[n6].cidr=cidr6(node6+i);
    d6[n6].asn=node6[i].asn;
    d6[n6].ts=node6[i].ts;
    n6++;
  }
  pthread_mutex_unlock(&lock);
  snap->v4=d4;
  snap->v6=d6;
  snap->n4=n4;
  snap->n6=n6;
  return 1;
}

static int write_snapshot(struct snapshot *snap){
  FILE *fp;
  int fd,ok;

  fp=fopen(bgptmp,"wb");
  if(fp==NULL)return 0;
  ok=1;
  if(fwrite(&snap->n4,4,1,fp)!=1||fwrite(&snap->n6,4,1,fp)!=1)ok=0;
  if(ok&&snap->n4&&fwrite(snap->v4,sizeof(struct v4disk),snap->n4,fp)!=snap->n4)ok=0;
  if(ok&&snap->n6&&fwrite(snap->v6,sizeof(struct v6disk),snap->n6,fp)!=snap->n6)ok=0;
  if(ok&&fflush(fp)!=0)ok=0;
  fd=fileno(fp);
  if(ok&&fsync(fd)!=0)ok=0;
  if(fclose(fp)!=0)ok=0;
  if(!ok){unlink(bgptmp); return 0;}
  if(rename(bgptmp,bgpfile)!=0){unlink(bgptmp); return 0;}
  return 1;
}

static int save_db(void){
  struct snapshot snap;
  int ok;

  if(!make_snapshot(&snap))return 0;
  ok=write_snapshot(&snap);
  free_snapshot(&snap);
  pthread_mutex_lock(&lock);
  if(ok){
    tsave=(uint32_t)time(NULL);
    nsave++;
  }
  else save_error++;
  pthread_mutex_unlock(&lock);
  return ok;
}

static void *save_thread(void *arg){
  time_t now,next;
  int i,request;

  (void)arg;
  now=time(NULL);
  next=now+AUTOSAVE;
  for(;;){
    request=0;
    if(save_requested){save_requested=0; request=1;}
    now=time(NULL);
    if(now>=next)request=1;
    if(request){
      save_db();
      next=time(NULL)+AUTOSAVE;
    }
    if(interrupted&&!save_requested)break;
    for(i=0;i<1;i++){
      if(save_requested||interrupted)break;
      sleep(1);
    }
  }
  return NULL;
}

static int load_db(void){
  FILE *fp;
  struct v4disk d4;
  struct v6disk d6;
  uint32_t i,n4,n6;

  fp=fopen(bgpfile,"rb");
  if(fp==NULL)return 1;
  if(fread(&n4,4,1,fp)!=1||fread(&n6,4,1,fp)!=1){fclose(fp); return 0;}
  if(n4>0&&!reserve4(n4*2U)){
    fclose(fp);
    return 0;
  }
  if(n6>0&&!reserve6(n6*2U)){
    fclose(fp);
    return 0;
  }
  for(i=0;i<n4;i++){
    if(fread(&d4,sizeof(d4),1,fp)!=1){fclose(fp); return 0;}
    if(!insert4(d4.ip,d4.cidr,d4.asn,d4.ts,0)){fclose(fp); return 0;}
  }
  for(i=0;i<n6;i++){
    if(fread(&d6,sizeof(d6),1,fp)!=1){fclose(fp); return 0;}
    if(!insert6(d6.ip,d6.cidr,d6.asn,d6.ts,0)){fclose(fp); return 0;}
  }
  fclose(fp);
  return 1;
}

static int callback_ris(struct lws *wsi,enum lws_callback_reasons reason,void *user,void *in,size_t len){
  unsigned char aux[LWS_PRE+512];
  unsigned char dummy_ping[LWS_PRE];
  uint32_t j,asn,ts;
  size_t msg_len;
  char *ptr,*buf1,*buf2,*buf3;

  (void)user;
  switch(reason){
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      lws_callback_on_writable(wsi);
      lws_set_timer_usecs(wsi,10*LWS_USEC_PER_SEC);
      break;
    case LWS_CALLBACK_CLIENT_WRITEABLE:
      msg_len=strlen(subscribe_message);
      memcpy(&aux[LWS_PRE],subscribe_message,msg_len);
      lws_write(wsi,&aux[LWS_PRE],msg_len,LWS_WRITE_TEXT);
      break;
    case LWS_CALLBACK_CLIENT_RECEIVE:
      ts=(uint32_t)time(NULL);
      pthread_mutex_lock(&lock);
      trx=ts;
      pthread_mutex_unlock(&lock);
      if(follow+len>=LBUF-1){follow=0; break;}
      memcpy(lbuf+follow,in,len);
      follow+=(uint32_t)len;
      if(!lws_is_final_fragment(wsi))break;
      lbuf[follow]='\0';
      ptr=lbuf;
      len=follow;
      follow=0;
      buf1=strstr(ptr,"\"path\":["); if(buf1==NULL)break;
      buf1+=8;
      buf2=strstr(buf1,"]"); if(buf2==NULL)break;
      *buf2='\0';
      for(;;){
        buf3=strstr(buf1,",");
        if(buf3!=NULL)buf1=buf3+1;
        else {
          asn=0;
          for(j=0;j<(uint32_t)(buf2-buf1);j++)if(buf1[j]>='0'&&buf1[j]<='9')asn=asn*10+(buf1[j]-'0');
          break;
        }
      }
      buf1=strstr(buf2+1,"\"prefixes\":["); if(buf1==NULL)break;
      buf1+=12;
      buf2=strstr(buf1,"]"); if(buf2==NULL)break;
      *buf2='\0';
      pthread_mutex_lock(&lock);
      for(;;){
        buf3=strstr(buf1,",");
        if(buf3!=NULL){
          myproc(buf1+1,(int)(buf3-buf1-2),asn,ts);
          buf1=buf3+1;
        }
        else {
          myproc(buf1+1,(int)(buf2-buf1-2),asn,ts);
          break;
        }
      }
      pthread_mutex_unlock(&lock);
      break;
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
      fprintf(stderr,"No Connection\n");
      reconnect_requested=1;
      break;
    case LWS_CALLBACK_CLOSED:
      fprintf(stderr,"Closed Connection\n");
      reconnect_requested=1;
      break;
    case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
      pthread_mutex_lock(&lock);
      trx=(uint32_t)time(NULL);
      pthread_mutex_unlock(&lock);
      break;
    case LWS_CALLBACK_TIMER:
      lws_write(wsi,dummy_ping+LWS_PRE,0,LWS_WRITE_PING);
      lws_set_timer_usecs(wsi,10*LWS_USEC_PER_SEC);
      break;
    default:
      break;
  }
  return 0;
}

static struct lws_protocols protocols[]={
  {.name="ris-protocol",.callback=callback_ris,.per_session_data_size=0,.rx_buffer_size=131072},
  {.name=NULL}
};

static void sig_handler(int sig){
  if(sig==36)save_requested=1;
  else if(sig==37){
    save_requested=1;
    interrupted=1;
    if(server_fd>=0)shutdown(server_fd,SHUT_RDWR);
  }
}

static void *whois_server_thread(void *arg){
  struct sockaddr_in addr;
  struct match m[34];
  char buf[200],addrbuf[200];
  ssize_t n;
  uint32_t ip4,i;
  uint64_t ip6;
  int client_fd,opt,len;
  uint8_t nfound;

  (void)arg;
  server_fd=socket(AF_INET,SOCK_STREAM,0);
  if(server_fd<0)return NULL;
  opt=1;
  setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
  memset(&addr,0,sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=INADDR_ANY;
  addr.sin_port=htons(43);
  if(bind(server_fd,(struct sockaddr *)&addr,sizeof(addr))<0)return NULL;
  if(listen(server_fd,32)<0)return NULL;
  while(!interrupted){
    client_fd=accept(server_fd,NULL,NULL);
    if(client_fd<0)continue;
    n=read(client_fd,addrbuf,sizeof(addrbuf)-1);
    if(n>0){
      addrbuf[n]='\0';
      for(len=0;len<n;len++)if(addrbuf[len]=='\r'||addrbuf[len]=='\n'||addrbuf[len]==' '||addrbuf[len]=='\t'){addrbuf[len]='\0'; break;}
      pthread_mutex_lock(&lock);
      if(strncmp(addrbuf,"stat",4)==0){
        sprintf(buf,"%s Tstart\n",mydata(tstart)); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%s Trx\n",mydata(trx)); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%s Tnew\n",mydata(tnew)); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%10u Nrestart\n",restart); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%s Tsave\n",tsave?mydata(tsave):"00000000000000"); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%10u Nsave\n%10u Nsave_error\n",nsave,save_error); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%10u Nelm v4\n%10u Nnode v4\n%10u Nrx v4\n%10u Nnew v4\n",nroute4,nnode4,rxv4,newv4); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%10u Nelm v6\n%10u Nnode v6\n%10u Nrx v6\n%10u Nnew v6\n",nroute6,nnode6,rxv6,newv6); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%10lu KiB trie used\n%10lu KiB trie capacity\n",(unsigned long)((sizeof(root4)+sizeof(root6)+(size_t)nnode4*sizeof(struct node4)+(size_t)nnode6*sizeof(struct node6))/1024),(unsigned long)((sizeof(root4)+sizeof(root6)+(size_t)cap4*sizeof(struct node4)+(size_t)cap6*sizeof(struct node6))/1024)); write(client_fd,buf,strlen(buf));
      }
      else {
        query++;
        nfound=0;
        if(strchr(addrbuf,'.')!=NULL&&parse4query(addrbuf,&ip4))nfound=lookup4(ip4,m);
        else if(strchr(addrbuf,':')!=NULL&&parse6query(addrbuf,&ip6))nfound=lookup6(ip6,m);
        for(i=nfound;i>0;i--){
          sprintf(buf,"%u %u %s\n",m[i-1].cidr,m[i-1].asn,mydata(m[i-1].ts));
          write(client_fd,buf,strlen(buf));
        }
        sprintf(buf,"--\n%u match found\n%u v4 elm\n%u v6 elm\n%u query\n",nfound,nroute4,nroute6,query);
        write(client_fd,buf,strlen(buf));
      }
      pthread_mutex_unlock(&lock);
    }
    close(client_fd);
  }
  if(server_fd>=0)close(server_fd);
  server_fd=-1;
  return NULL;
}

int main(int argc,char **argv){
  struct lws_context_creation_info info;
  struct lws_client_connect_info ccinfo;
  struct lws_context *context;
  pthread_t whois_thread,saver_thread;
  uint32_t now;

  if(argc!=2||argv[1][0]!='/'){
    fprintf(stderr,"Usage: %s /absolute/path/bgp.raw\n",argv[0]);
    return 1;
  }
  bgpfile=argv[1];
  bgptmp=(char *)malloc(strlen(bgpfile)+5);
  if(bgptmp==NULL)return 1;
  sprintf(bgptmp,"%s.tmp",bgpfile);
  now=(uint32_t)time(NULL);
  tnew=now;
  tstart=now;
  trx=now;
  lbuf=(char *)malloc(LBUF);
  if(lbuf==NULL)return 1;
  if(!load_db()){
    fprintf(stderr,"Cannot load %s\n",bgpfile);
    return 1;
  }
  signal(36,sig_handler);
  signal(37,sig_handler);
  if(pthread_create(&saver_thread,NULL,save_thread,NULL)!=0)return 1;
  if(pthread_create(&whois_thread,NULL,whois_server_thread,NULL)!=0){
    interrupted=1;
    pthread_join(saver_thread,NULL);
    return 1;
  }

reconnect:
  reconnect_requested=0;
  memset(&info,0,sizeof(info));
  info.port=CONTEXT_PORT_NO_LISTEN;
  info.protocols=protocols;
  info.options=LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  context=lws_create_context(&info);
  if(context==NULL){
    restart++;
    sleep(2);
    goto reconnect;
  }
  memset(&ccinfo,0,sizeof(ccinfo));
  ccinfo.context=context;
  ccinfo.address="ris-live.ripe.net";
  ccinfo.port=443;
  ccinfo.path="/v1/ws/";
  ccinfo.host=ccinfo.address;
  ccinfo.origin=ccinfo.address;
  ccinfo.protocol=protocols[0].name;
  ccinfo.ssl_connection=LCCSCF_USE_SSL;
  if(lws_client_connect_via_info(&ccinfo)==NULL)reconnect_requested=1;
  trx=(uint32_t)time(NULL);
  while(!interrupted&&!reconnect_requested){
    lws_service(context,100);
    if((uint32_t)time(NULL)-trx>TIMEOUT_RX)reconnect_requested=1;
  }
  lws_context_destroy(context);
  if(!interrupted){
    restart++;
    sleep(2);
    goto reconnect;
  }

  save_requested=1;
  interrupted=1;
  pthread_join(whois_thread,NULL);
  pthread_join(saver_thread,NULL);
  free(node4);
  free(node6);
  free(bgptmp);
  free(lbuf);
  return 0;
}
