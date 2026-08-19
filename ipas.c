// Gianluca Mazzini @2015- Version 4.0
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define DEFAULT_RAW "/home/www/fulltable/bgp.raw"
#define MAX_QUERY 2048
#define MAX_MATCH 64

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

struct match {
  uint64_t ip;
  uint32_t asn;
  uint32_t ts;
  uint8_t cidr;
  uint8_t family;
};

struct range {
  uint64_t start;
  uint64_t end;
};

struct ranges {
  struct range *v;
  uint32_t n;
  uint32_t cap;
};

struct summary {
  uint32_t n4;
  uint32_t n6;
  uint32_t c4[33];
  uint32_t c6[65];
  uint32_t oldest4;
  uint32_t newest4;
  uint32_t oldest6;
  uint32_t newest6;
  uint64_t age[5];
  struct stat st;
};

static const char *rawfile;

static void format_time(uint32_t ts,char *buf,size_t len){
  time_t t;
  struct tm *tmv;

  if(ts==0){
    strcpy(buf,"-");
    return;
  }
  t=(time_t)ts;
  tmv=localtime(&t);
  if(tmv==NULL){
    strcpy(buf,"-");
    return;
  }
  strftime(buf,len,"%Y-%m-%d %H:%M:%S",tmv);
}

static int open_raw(FILE **f,uint32_t *n4,uint32_t *n6,struct stat *st){
  uint64_t expected;

  if(sizeof(struct v4disk)!=16||sizeof(struct v6disk)!=24)return 0;
  if(stat(rawfile,st)!=0)return 0;
  *f=fopen(rawfile,"rb");
  if(*f==NULL)return 0;
  if(fread(n4,4,1,*f)!=1||fread(n6,4,1,*f)!=1){
    fclose(*f);
    *f=NULL;
    return 0;
  }
  expected=8ULL+(uint64_t)(*n4)*sizeof(struct v4disk)+(uint64_t)(*n6)*sizeof(struct v6disk);
  if((uint64_t)st->st_size!=expected){
    fclose(*f);
    *f=NULL;
    return 0;
  }
  return 1;
}

static int hex_digit(int c){
  if(c>='0'&&c<='9')return c-'0';
  if(c>='A'&&c<='F')return c-'A'+10;
  if(c>='a'&&c<='f')return c-'a'+10;
  return -1;
}

static void url_decode(char *s){
  char *d;
  int a,b;

  d=s;
  while(*s){
    if(*s=='+'){
      *d++=' ';
      s++;
    }
    else if(*s=='%'&&s[1]&&s[2]){
      a=hex_digit((unsigned char)s[1]);
      b=hex_digit((unsigned char)s[2]);
      if(a>=0&&b>=0){
        *d++=(char)((a<<4)|b);
        s+=3;
      }
      else *d++=*s++;
    }
    else *d++=*s++;
  }
  *d='\0';
}

static void query_params(char *action,size_t alen,char *ip,size_t ilen,char *asn,size_t nlen){
  const char *q;
  char buf[MAX_QUERY],*p,*eq,*next;

  action[0]='\0';
  ip[0]='\0';
  asn[0]='\0';
  q=getenv("QUERY_STRING");
  if(q==NULL||*q=='\0')return;
  strncpy(buf,q,sizeof(buf)-1);
  buf[sizeof(buf)-1]='\0';
  p=buf;
  while(p&&*p){
    next=strchr(p,'&');
    if(next)*next++='\0';
    eq=strchr(p,'=');
    if(eq){
      *eq++='\0';
      url_decode(p);
      url_decode(eq);
      if(strcmp(p,"action")==0){strncpy(action,eq,alen-1); action[alen-1]='\0';}
      else if(strcmp(p,"ip")==0){strncpy(ip,eq,ilen-1); ip[ilen-1]='\0';}
      else if(strcmp(p,"asn")==0){strncpy(asn,eq,nlen-1); asn[nlen-1]='\0';}
    }
    p=next;
  }
}

static void html_head(const char *title){
  printf("Content-Type: text/html; charset=utf-8\r\n\r\n");
  printf("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
  printf("<title>%s - IPAS</title><style>",title);
  printf("body{font-family:system-ui,sans-serif;max-width:1100px;margin:0 auto;padding:24px;background:#f5f6f8;color:#202124}");
  printf("a{color:#175cd3;text-decoration:none}nav{display:flex;gap:18px;margin:0 0 24px;padding:12px 0;border-bottom:1px solid #ccd0d5}");
  printf("h1{margin:0 0 8px}h2{margin-top:28px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}");
  printf(".card{background:white;border:1px solid #dfe2e6;border-radius:10px;padding:16px}.big{font-size:1.8rem;font-weight:700}");
  printf("table{width:100%%;border-collapse:collapse;background:white}th,td{text-align:left;padding:8px;border-bottom:1px solid #e5e7eb}");
  printf(".barrow{display:grid;grid-template-columns:56px 1fr 100px;gap:8px;align-items:center;margin:5px 0}.bar{height:14px;background:#dbe7ff;border-radius:3px;overflow:hidden}.fill{height:100%%;background:#4f7fdc}");
  printf("form{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}input{padding:8px;border:1px solid #b8bdc5;border-radius:6px;min-width:220px}button{padding:8px 14px;border:0;border-radius:6px;background:#175cd3;color:white}");
  printf(".muted{color:#667085}.error{background:#fff1f0;border:1px solid #f1b7b2;padding:12px;border-radius:8px}</style></head><body>");
  printf("<h1>IPAS</h1><div class=\"muted\">IP prefix and autonomous system archive</div>");
  printf("<nav><a href=\"?\">Summary</a><a href=\"?action=export4\">IPv4 export</a><a href=\"?action=export6\">IPv6 export</a></nav>");
}

static void html_foot(void){
  printf("</body></html>\n");
}

static void html_error(const char *msg){
  html_head("Error");
  printf("<div class=\"error\">%s</div>",msg);
  html_foot();
}

static void age_add(struct summary *s,uint32_t ts,uint32_t now){
  uint32_t age;

  age=ts>now?0:now-ts;
  if(age<3600)s->age[0]++;
  else if(age<86400)s->age[1]++;
  else if(age<604800)s->age[2]++;
  else if(age<2592000)s->age[3]++;
  else s->age[4]++;
}

static int scan_summary(struct summary *s){
  FILE *f;
  struct v4disk d4;
  struct v6disk d6;
  uint32_t i,now;

  memset(s,0,sizeof(*s));
  if(!open_raw(&f,&s->n4,&s->n6,&s->st))return 0;
  now=(uint32_t)time(NULL);
  for(i=0;i<s->n4;i++){
    if(fread(&d4,sizeof(d4),1,f)!=1){fclose(f); return 0;}
    if(d4.cidr<=32)s->c4[d4.cidr]++;
    if(s->oldest4==0||d4.ts<s->oldest4)s->oldest4=d4.ts;
    if(d4.ts>s->newest4)s->newest4=d4.ts;
    age_add(s,d4.ts,now);
  }
  for(i=0;i<s->n6;i++){
    if(fread(&d6,sizeof(d6),1,f)!=1){fclose(f); return 0;}
    if(d6.cidr<=64)s->c6[d6.cidr]++;
    if(s->oldest6==0||d6.ts<s->oldest6)s->oldest6=d6.ts;
    if(d6.ts>s->newest6)s->newest6=d6.ts;
    age_add(s,d6.ts,now);
  }
  fclose(f);
  return 1;
}

static void cidr_bars(uint32_t *c,int first,int last){
  uint32_t max,width;
  int i;

  max=1;
  for(i=first;i<=last;i++)if(c[i]>max)max=c[i];
  for(i=first;i<=last;i++)if(c[i]){
    width=(uint32_t)(((uint64_t)c[i]*100)/max);
    if(width==0)width=1;
    printf("<div class=\"barrow\"><div>/%d</div><div class=\"bar\"><div class=\"fill\" style=\"width:%u%%\"></div></div><div>%u</div></div>",i,width,c[i]);
  }
}

static void summary_page(void){
  struct summary s;
  char mt[32],o4[32],n4[32],o6[32],n6[32];
  struct tm *tmv;
  time_t mtm;

  if(!scan_summary(&s)){html_error("Cannot read or validate the RAW snapshot."); return;}
  mtm=s.st.st_mtime;
  tmv=localtime(&mtm);
  if(tmv)strftime(mt,sizeof(mt),"%Y-%m-%d %H:%M:%S",tmv); else strcpy(mt,"-");
  format_time(s.oldest4,o4,sizeof(o4));
  format_time(s.newest4,n4,sizeof(n4));
  format_time(s.oldest6,o6,sizeof(o6));
  format_time(s.newest6,n6,sizeof(n6));
  html_head("Summary");
  printf("<div class=\"grid\"><div class=\"card\"><div class=\"muted\">IPv4 prefixes</div><div class=\"big\">%u</div></div>",s.n4);
  printf("<div class=\"card\"><div class=\"muted\">IPv6 prefixes</div><div class=\"big\">%u</div></div>",s.n6);
  printf("<div class=\"card\"><div class=\"muted\">RAW size</div><div class=\"big\">%.1f MiB</div></div>",(double)s.st.st_size/(1024.0*1024.0));
  printf("<div class=\"card\"><div class=\"muted\">Snapshot</div><div>%s</div><div class=\"muted\">%s</div></div></div>",mt,rawfile);
  printf("<h2>Lookup</h2><div class=\"grid\"><div class=\"card\"><form method=\"get\"><input type=\"hidden\" name=\"action\" value=\"query\"><input name=\"ip\" placeholder=\"IPv4 or IPv6 address\"><button>Search IP</button></form></div>");
  printf("<div class=\"card\"><form method=\"get\"><input type=\"hidden\" name=\"action\" value=\"asn\"><input name=\"asn\" placeholder=\"ASN, e.g. 13335\"><button>Analyze ASN</button></form></div></div>");
  printf("<h2>IPv4 CIDR distribution</h2><div class=\"card\">"); cidr_bars(s.c4,8,24); printf("<div class=\"muted\">Oldest update %s &middot; newest %s</div></div>",o4,n4);
  printf("<h2>IPv6 CIDR distribution</h2><div class=\"card\">"); cidr_bars(s.c6,16,48); printf("<div class=\"muted\">Oldest update %s &middot; newest %s</div></div>",o6,n6);
  printf("<h2>Route freshness</h2><div class=\"card\"><table><tr><th>Age</th><th>Prefixes</th></tr>");
  printf("<tr><td>&lt; 1 hour</td><td>%llu</td></tr><tr><td>1-24 hours</td><td>%llu</td></tr><tr><td>1-7 days</td><td>%llu</td></tr><tr><td>7-30 days</td><td>%llu</td></tr><tr><td>&gt; 30 days</td><td>%llu</td></tr>",
    (unsigned long long)s.age[0],(unsigned long long)s.age[1],(unsigned long long)s.age[2],(unsigned long long)s.age[3],(unsigned long long)s.age[4]);
  printf("</table></div>");
  html_foot();
}

static uint32_t mask4(uint8_t cidr){
  return ~0U<<(32-cidr);
}

static uint64_t mask6(uint8_t cidr){
  return ~0ULL<<(64-cidr);
}

static int cmp_match(const void *a,const void *b){
  const struct match *x,*y;

  x=(const struct match *)a;
  y=(const struct match *)b;
  if(x->cidr<y->cidr)return 1;
  if(x->cidr>y->cidr)return -1;
  return 0;
}

static void ip4_text(uint32_t ip,char *buf){
  sprintf(buf,"%u.%u.%u.%u",(ip>>24)&255,(ip>>16)&255,(ip>>8)&255,ip&255);
}

static void ip6_text(uint64_t ip,char *buf,size_t len){
  unsigned char raw[16];
  int i;

  memset(raw,0,sizeof(raw));
  for(i=7;i>=0;i--){raw[i]=(unsigned char)(ip&255); ip>>=8;}
  if(inet_ntop(AF_INET6,raw,buf,len)==NULL)strcpy(buf,"?");
}

static int parse_ip4(const char *s,uint32_t *ip){
  unsigned char raw[4];

  if(inet_pton(AF_INET,s,raw)!=1)return 0;
  *ip=((uint32_t)raw[0]<<24)|((uint32_t)raw[1]<<16)|((uint32_t)raw[2]<<8)|raw[3];
  return 1;
}

static int parse_ip6(const char *s,uint64_t *ip){
  unsigned char raw[16];
  int i;

  if(inet_pton(AF_INET6,s,raw)!=1)return 0;
  *ip=0;
  for(i=0;i<8;i++)*ip=(*ip<<8)|raw[i];
  return 1;
}

static void query_page(const char *text){
  FILE *f;
  struct stat st;
  struct v4disk d4;
  struct v6disk d6;
  struct match m[MAX_MATCH];
  uint32_t n4,n6,i,ip4,nm;
  uint64_t ip6;
  int family;
  char pbuf[80],tbuf[32];

  family=0;
  if(parse_ip4(text,&ip4))family=4;
  else if(parse_ip6(text,&ip6))family=6;
  if(!family){html_error("Invalid IPv4 or IPv6 address."); return;}
  if(!open_raw(&f,&n4,&n6,&st)){html_error("Cannot read or validate the RAW snapshot."); return;}
  nm=0;
  if(family==4){
    for(i=0;i<n4;i++){
      if(fread(&d4,sizeof(d4),1,f)!=1){fclose(f); html_error("RAW read error."); return;}
      if(d4.cidr>=8&&d4.cidr<=24&&(ip4&mask4(d4.cidr))==d4.ip&&nm<MAX_MATCH){
        m[nm].ip=d4.ip; m[nm].cidr=d4.cidr; m[nm].asn=d4.asn; m[nm].ts=d4.ts; m[nm].family=4; nm++;
      }
    }
  }
  else {
    if(fseek(f,(long)((uint64_t)n4*sizeof(struct v4disk)),SEEK_CUR)!=0){fclose(f); html_error("RAW seek error."); return;}
    for(i=0;i<n6;i++){
      if(fread(&d6,sizeof(d6),1,f)!=1){fclose(f); html_error("RAW read error."); return;}
      if(d6.cidr>=16&&d6.cidr<=48&&(ip6&mask6(d6.cidr))==d6.ip&&nm<MAX_MATCH){
        m[nm].ip=d6.ip; m[nm].cidr=d6.cidr; m[nm].asn=d6.asn; m[nm].ts=d6.ts; m[nm].family=6; nm++;
      }
    }
  }
  fclose(f);
  qsort(m,nm,sizeof(*m),cmp_match);
  html_head("IP lookup");
  printf("<h2>%s</h2><div class=\"card\"><table><tr><th>Prefix</th><th>ASN</th><th>Last update</th></tr>",text);
  for(i=0;i<nm;i++){
    if(m[i].family==4)ip4_text((uint32_t)m[i].ip,pbuf); else ip6_text(m[i].ip,pbuf,sizeof(pbuf));
    format_time(m[i].ts,tbuf,sizeof(tbuf));
    printf("<tr><td>%s/%u</td><td>AS%u</td><td>%s</td></tr>",pbuf,m[i].cidr,m[i].asn,tbuf);
  }
  if(nm==0)printf("<tr><td colspan=\"3\">No match in this snapshot.</td></tr>");
  printf("</table></div>");
  html_foot();
}

static int range_push(struct ranges *r,uint64_t start,uint64_t end){
  struct range *p;
  uint32_t cap;

  if(r->n>=r->cap){
    cap=r->cap?r->cap*2:64;
    p=(struct range *)realloc(r->v,(size_t)cap*sizeof(*p));
    if(p==NULL)return 0;
    r->v=p;
    r->cap=cap;
  }
  r->v[r->n].start=start;
  r->v[r->n].end=end;
  r->n++;
  return 1;
}

static int cmp_range(const void *a,const void *b){
  const struct range *x,*y;

  x=(const struct range *)a;
  y=(const struct range *)b;
  if(x->start<y->start)return -1;
  if(x->start>y->start)return 1;
  if(x->end<y->end)return -1;
  if(x->end>y->end)return 1;
  return 0;
}

static uint64_t range_union(struct ranges *r){
  uint64_t total,start,end;
  uint32_t i;

  if(r->n==0)return 0;
  qsort(r->v,r->n,sizeof(*r->v),cmp_range);
  total=0;
  start=r->v[0].start;
  end=r->v[0].end;
  for(i=1;i<r->n;i++){
    if(r->v[i].start<=end){
      if(r->v[i].end>end)end=r->v[i].end;
    }
    else {
      total+=end-start;
      start=r->v[i].start;
      end=r->v[i].end;
    }
  }
  return total+end-start;
}

static void asn_page(const char *text){
  FILE *f;
  struct stat st;
  struct v4disk d4;
  struct v6disk d6;
  struct ranges r4,r6;
  uint32_t n4,n6,i,asn,c4[33],c6[65],oldest,newest,count4,count6;
  uint64_t space4,space6;
  unsigned long v;
  char *end,t1[32],t2[32];

  v=strtoul(text,&end,10);
  if(*text=='\0'||*end!='\0'||v==0||v>0xffffffffUL){html_error("Invalid ASN."); return;}
  asn=(uint32_t)v;
  if(!open_raw(&f,&n4,&n6,&st)){html_error("Cannot read or validate the RAW snapshot."); return;}
  memset(c4,0,sizeof(c4));
  memset(c6,0,sizeof(c6));
  memset(&r4,0,sizeof(r4));
  memset(&r6,0,sizeof(r6));
  oldest=0; newest=0; count4=0; count6=0;
  for(i=0;i<n4;i++){
    if(fread(&d4,sizeof(d4),1,f)!=1)break;
    if(d4.asn==asn&&d4.cidr>=8&&d4.cidr<=24){
      count4++; c4[d4.cidr]++;
      if(oldest==0||d4.ts<oldest)oldest=d4.ts;
      if(d4.ts>newest)newest=d4.ts;
      if(!range_push(&r4,d4.ip,(uint64_t)d4.ip+(1ULL<<(32-d4.cidr)))){fclose(f); free(r4.v); free(r6.v); html_error("Out of memory."); return;}
    }
  }
  for(i=0;i<n6;i++){
    if(fread(&d6,sizeof(d6),1,f)!=1)break;
    if(d6.asn==asn&&d6.cidr>=16&&d6.cidr<=48){
      count6++; c6[d6.cidr]++;
      if(oldest==0||d6.ts<oldest)oldest=d6.ts;
      if(d6.ts>newest)newest=d6.ts;
      if(!range_push(&r6,d6.ip>>16,(d6.ip>>16)+(1ULL<<(48-d6.cidr)))){fclose(f); free(r4.v); free(r6.v); html_error("Out of memory."); return;}
    }
  }
  fclose(f);
  space4=range_union(&r4);
  space6=range_union(&r6);
  free(r4.v);
  free(r6.v);
  format_time(oldest,t1,sizeof(t1));
  format_time(newest,t2,sizeof(t2));
  html_head("ASN analysis");
  printf("<h2>AS%u</h2><div class=\"grid\"><div class=\"card\"><div class=\"muted\">IPv4 prefixes</div><div class=\"big\">%u</div></div>",asn,count4);
  printf("<div class=\"card\"><div class=\"muted\">Unique IPv4 addresses</div><div class=\"big\">%llu</div></div>",(unsigned long long)space4);
  printf("<div class=\"card\"><div class=\"muted\">IPv6 prefixes</div><div class=\"big\">%u</div></div>",count6);
  printf("<div class=\"card\"><div class=\"muted\">Unique IPv6 /48 equivalents</div><div class=\"big\">%llu</div></div></div>",(unsigned long long)space6);
  if(count4){printf("<h2>IPv4 CIDR distribution</h2><div class=\"card\">"); cidr_bars(c4,8,24); printf("</div>");}
  if(count6){printf("<h2>IPv6 CIDR distribution</h2><div class=\"card\">"); cidr_bars(c6,16,48); printf("</div>");}
  printf("<p class=\"muted\">Unique space removes overlap between prefixes announced by the same ASN. Update range: %s to %s.</p>",t1,t2);
  html_foot();
}

static int cmp_v4(const void *a,const void *b){
  const struct v4disk *x,*y;

  x=(const struct v4disk *)a;
  y=(const struct v4disk *)b;
  if(x->ip<y->ip)return -1;
  if(x->ip>y->ip)return 1;
  if(x->cidr<y->cidr)return -1;
  if(x->cidr>y->cidr)return 1;
  return 0;
}

static int cmp_v6(const void *a,const void *b){
  const struct v6disk *x,*y;

  x=(const struct v6disk *)a;
  y=(const struct v6disk *)b;
  if(x->ip<y->ip)return -1;
  if(x->ip>y->ip)return 1;
  if(x->cidr<y->cidr)return -1;
  if(x->cidr>y->cidr)return 1;
  return 0;
}

static void export4(void){
  FILE *f;
  struct stat st;
  struct v4disk *v;
  uint32_t n4,n6,i;
  char buf[32];

  if(!open_raw(&f,&n4,&n6,&st)){printf("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nRAW read error\n"); return;}
  v=(struct v4disk *)malloc((size_t)n4*sizeof(*v));
  if(v==NULL){fclose(f); printf("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nOut of memory\n"); return;}
  if(fread(v,sizeof(*v),n4,f)!=n4){free(v); fclose(f); printf("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nRAW read error\n"); return;}
  fclose(f);
  qsort(v,n4,sizeof(*v),cmp_v4);
  printf("Content-Type: text/plain; charset=utf-8\r\nContent-Disposition: attachment; filename=\"ipas-ipv4.txt\"\r\n\r\n");
  for(i=0;i<n4;i++){ip4_text(v[i].ip,buf); printf("%s/%u,%u\n",buf,v[i].cidr,v[i].asn);}
  free(v);
}

static void export6(void){
  FILE *f;
  struct stat st;
  struct v6disk *v;
  uint32_t n4,n6,i;
  char buf[80];

  if(!open_raw(&f,&n4,&n6,&st)){printf("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nRAW read error\n"); return;}
  if(fseek(f,(long)((uint64_t)n4*sizeof(struct v4disk)),SEEK_CUR)!=0){fclose(f); printf("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nRAW seek error\n"); return;}
  v=(struct v6disk *)malloc((size_t)n6*sizeof(*v));
  if(v==NULL){fclose(f); printf("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nOut of memory\n"); return;}
  if(fread(v,sizeof(*v),n6,f)!=n6){free(v); fclose(f); printf("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nRAW read error\n"); return;}
  fclose(f);
  qsort(v,n6,sizeof(*v),cmp_v6);
  printf("Content-Type: text/plain; charset=utf-8\r\nContent-Disposition: attachment; filename=\"ipas-ipv6.txt\"\r\n\r\n");
  for(i=0;i<n6;i++){ip6_text(v[i].ip,buf,sizeof(buf)); printf("%s/%u,%u\n",buf,v[i].cidr,v[i].asn);}
  free(v);
}

int main(int argc,char **argv){
  char action[32],ip[128],asn[32];
  const char *env;

  env=getenv("IPAS_RAW");
  rawfile=(argc>1)?argv[1]:(env&&*env?env:DEFAULT_RAW);
  query_params(action,sizeof(action),ip,sizeof(ip),asn,sizeof(asn));
  if(strcmp(action,"query")==0)query_page(ip);
  else if(strcmp(action,"asn")==0)asn_page(asn);
  else if(strcmp(action,"export4")==0)export4();
  else if(strcmp(action,"export6")==0)export6();
  else summary_page();
  return 0;
}
